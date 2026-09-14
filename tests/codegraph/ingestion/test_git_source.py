"""URL and ref validation for repository ingestion.

Ingested code is later compiled and, under remediation, built. A URL reaching
this layer is untrusted input, so the checks below are a security boundary
rather than input tidying.
"""

from __future__ import annotations

import pytest

from codegraph.ingestion.git_source import validate_ref, validate_repo_url
from codegraph.ingestion.utils import UploadValidationError


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://GitHub.com/owner/repo",
        "  https://github.com/owner/repo  ",
    ],
)
def test_accepts_public_https_github_urls(url: str) -> None:
    assert validate_repo_url(url).strip() == url.strip()


@pytest.mark.parametrize(
    ("url", "because"),
    [
        ("http://github.com/owner/repo", "plaintext scheme"),
        ("git://github.com/owner/repo", "git protocol"),
        ("ssh://git@github.com/owner/repo", "ssh"),
        ("file:///etc/passwd", "local filesystem"),
        ("https://user:token@github.com/owner/repo", "embedded credentials"),
        ("https://github.com", "no repository path"),
        ("https://gitlab.com/owner/repo", "host not on the allowlist"),
        ("https://localhost/owner/repo", "loopback by name"),
        ("https://127.0.0.1/owner/repo", "loopback by address"),
        ("https://169.254.169.254/latest/meta-data", "cloud metadata endpoint"),
        ("https://10.0.0.5/internal/repo", "private network"),
        ("https://[::1]/owner/repo", "IPv6 loopback"),
        ("", "empty"),
    ],
)
def test_rejects_unsafe_urls(url: str, because: str) -> None:
    with pytest.raises(UploadValidationError):
        validate_repo_url(url)


def test_allowlist_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    from codegraph import config

    monkeypatch.setattr(
        config.get_settings(), "upload_git_allowed_hosts", ["gitlab.com"], raising=False
    )
    assert validate_repo_url("https://gitlab.com/owner/repo")
    with pytest.raises(UploadValidationError):
        validate_repo_url("https://github.com/owner/repo")


@pytest.mark.parametrize("ref", ["main", "v1.2.3", "feature/branch-name", None, "", "   "])
def test_accepts_ordinary_refs(ref: str | None) -> None:
    validate_ref(ref)


@pytest.mark.parametrize(
    "ref",
    ["--upload-pack=touch /tmp/pwned", "-x", "main; rm -rf /", "main`id`", "main$(id)", "a b"],
)
def test_rejects_option_like_and_shell_significant_refs(ref: str) -> None:
    with pytest.raises(UploadValidationError):
        validate_ref(ref)
