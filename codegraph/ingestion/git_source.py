"""Shallow-clone a public Git repository into a staging workspace.

The service analyses whatever it ingests and may later run javac, Maven or
Gradle against it, so a URL handed to this module is treated as untrusted
input: the scheme, host and credential shape are all checked before git runs.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from codegraph.config import settings
from codegraph.ingestion.utils import UploadValidationError

_BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}


def _is_private_address(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )


def validate_repo_url(raw_url: str) -> str:
    """Return the normalised clone URL, or raise ``UploadValidationError``."""
    url = (raw_url or "").strip()
    if not url:
        raise UploadValidationError("Repository URL is required.")
    if len(url) > 2048:
        raise UploadValidationError("Repository URL is too long.")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UploadValidationError(
            f"Only https:// repository URLs are accepted, got {parsed.scheme or 'no'} scheme."
        )
    if parsed.username or parsed.password or "@" in (parsed.netloc.split(":")[0] or ""):
        raise UploadValidationError("Credentials in the repository URL are not accepted.")

    host = (parsed.hostname or "").lower()
    if not host:
        raise UploadValidationError("Repository URL has no host.")
    if host in _BLOCKED_HOSTNAMES or _is_private_address(host):
        raise UploadValidationError(f"Refusing to clone from {host}.")

    allowed = [h.strip().lower() for h in settings.upload_git_allowed_hosts if h.strip()]
    if host not in allowed:
        raise UploadValidationError(
            f"Host {host} is not allowed. Permitted hosts: {', '.join(allowed)}."
        )
    if not parsed.path.strip("/"):
        raise UploadValidationError("Repository URL has no path.")
    return url


def validate_ref(raw_ref: str | None) -> str | None:
    """Reject ref names git would treat as options or shell-significant."""
    if raw_ref is None:
        return None
    ref = raw_ref.strip()
    if not ref:
        return None
    if len(ref) > 255 or ref.startswith("-") or any(c in ref for c in " \t\n\\'\"$;&|`"):
        raise UploadValidationError(f"Invalid ref: {ref!r}")
    return ref


def _directory_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def clone_repository(repo_url: str, destination: str, *, ref: str | None = None) -> str:
    """Clone ``repo_url`` into ``destination`` and return the validated URL."""
    if shutil.which("git") is None:
        raise UploadValidationError("git is not installed on the server.")

    url = validate_repo_url(repo_url)
    checked_ref = validate_ref(ref)

    command = [
        "git",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        "--recurse-submodules=no",
    ]
    if checked_ref:
        command += ["--branch", checked_ref]
    command += ["--", url, destination]

    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "never"}
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.upload_git_timeout_seconds,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UploadValidationError(
            f"Cloning timed out after {settings.upload_git_timeout_seconds:.0f}s."
        ) from exc

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"git exited {proc.returncode}"
        raise UploadValidationError(f"Clone failed: {reason}")

    size = _directory_size(Path(destination))
    if size > settings.upload_max_extracted_size_bytes:
        raise UploadValidationError(
            f"Cloned repository is {size} bytes, over the {settings.upload_max_extracted_size_bytes} limit."
        )

    git_dir = Path(destination) / ".git"
    if git_dir.is_dir():
        shutil.rmtree(git_dir, ignore_errors=True)
    return url
