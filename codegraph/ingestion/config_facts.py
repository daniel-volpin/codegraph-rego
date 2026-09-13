"""Configuration facts discovered from an analysed workspace.

Security-relevant values frequently live in configuration rather than code: a
cipher algorithm, a TLS toggle, a session timeout. Policies that can only read
source text cannot decide those controls at all. This module records what the
workspace's configuration files actually declare, with the file and line that
declared it, so a rule's decision carries provenance.

A value here is what the repository declares, not necessarily what a deployed
process sees: environment variables, system properties, and profile overlays
can all override it at runtime.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)

PROPERTY_FILE_GLOB = "*.properties"

# Build output mirrors source resources; ingesting both invents conflicts.
_EXCLUDED_DIR_NAMES = frozenset({"target", "build", "out", "bin", "node_modules", ".git", ".venv"})

_COMMENT_PREFIXES = ("#", "!")
_SEPARATORS = ("=", ":")

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "f": "\f", "\\": "\\", '"': '"', "'": "'", " ": " "}


@dataclass(frozen=True)
class ConfigProperty:
    """One declaration of a configuration key."""

    key: str
    value: str
    source_file: str
    line: int


@dataclass(frozen=True)
class ResolvedProperty:
    """A key's resolution across the workspace.

    ``conflicting_values`` is non-empty when declarations disagree. Callers must
    not silently choose one: a rule that fires on a value has to say which
    declaration it used, and an ambiguous key is a finding about the workspace.
    """

    key: str
    value: str
    sources: tuple[ConfigProperty, ...]
    conflicting_values: tuple[str, ...] = ()

    @property
    def is_ambiguous(self) -> bool:
        return bool(self.conflicting_values)


def _unescape(raw: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\" or index + 1 >= len(raw):
            out.append(char)
            index += 1
            continue
        nxt = raw[index + 1]
        if nxt == "u" and index + 5 < len(raw) + 1:
            hexdigits = raw[index + 2 : index + 6]
            try:
                out.append(chr(int(hexdigits, 16)))
                index += 6
                continue
            except ValueError:
                pass
        out.append(_ESCAPES.get(nxt, nxt))
        index += 2
    return "".join(out)


def _split_declaration(logical_line: str) -> tuple[str, str] | None:
    """Split on the first unescaped separator, per java.util.Properties."""
    index = 0
    while index < len(logical_line):
        char = logical_line[index]
        if char == "\\":
            index += 2
            continue
        if char in _SEPARATORS:
            return logical_line[:index], logical_line[index + 1 :]
        if char.isspace():
            remainder = logical_line[index:].lstrip()
            if remainder[:1] in _SEPARATORS:
                return logical_line[:index], remainder[1:]
            return logical_line[:index], remainder
        index += 1
    return None


def parse_properties(text: str, *, source_file: str) -> list[ConfigProperty]:
    """Parse java.util.Properties text, keeping the declaring line number."""
    declarations: list[ConfigProperty] = []
    pending = ""
    pending_line = 0

    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not pending:
            if not stripped or stripped.startswith(_COMMENT_PREFIXES):
                continue
            pending_line = number

        # An odd number of trailing backslashes continues the logical line.
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2:
            pending += stripped[:-1]
            continue

        logical = pending + stripped
        pending = ""
        split = _split_declaration(logical)
        if split is None:
            continue
        key, value = split
        key = _unescape(key.strip())
        if not key:
            continue
        declarations.append(
            ConfigProperty(
                key=key,
                value=_unescape(value.strip()),
                source_file=source_file,
                line=pending_line or number,
            )
        )

    if pending:
        LOGGER.warning("Unterminated line continuation in %s", source_file)
    return declarations


def discover_property_files(workspace_root: str | Path) -> list[Path]:
    """Property files under the workspace, excluding build output."""
    root = Path(workspace_root)
    if not root.is_dir():
        return []
    found = [
        path
        for path in root.rglob(PROPERTY_FILE_GLOB)
        if path.is_file() and not _EXCLUDED_DIR_NAMES.intersection(path.relative_to(root).parts[:-1])
    ]
    return sorted(found)


_PROJECT_MARKERS = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)

_PROJECT_ROOT_MAX_DEPTH = 6


def find_project_root(start: str | Path) -> Path | None:
    """Nearest ancestor holding a build manifest.

    Java source roots sit under ``src/main/java`` while configuration sits under
    ``src/main/resources``, so config discovery cannot start from the source
    root. The build manifest bounds the search: without it, scanning upwards in
    a monorepo would pull in unrelated modules' configuration.
    """
    current = Path(start).resolve()
    if current.is_file():
        current = current.parent
    for _ in range(_PROJECT_ROOT_MAX_DEPTH):
        if any((current / marker).is_file() for marker in _PROJECT_MARKERS):
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def collect_config_properties(workspace_root: str | Path) -> list[ConfigProperty]:
    """Every configuration declaration in the workspace, in stable order."""
    root = Path(workspace_root)
    declarations: list[ConfigProperty] = []
    for path in discover_property_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            LOGGER.warning("Could not read configuration file %s: %s", path, exc)
            continue
        relative = path.relative_to(root).as_posix()
        declarations.extend(parse_properties(text, source_file=relative))
    LOGGER.info(
        "Collected %d configuration declarations from %d files",
        len(declarations),
        len(discover_property_files(root)),
    )
    return declarations


def resolve_properties(declarations: list[ConfigProperty]) -> dict[str, ResolvedProperty]:
    """Index declarations by key, recording disagreement rather than hiding it."""
    grouped: dict[str, list[ConfigProperty]] = {}
    for declaration in declarations:
        grouped.setdefault(declaration.key, []).append(declaration)

    resolved: dict[str, ResolvedProperty] = {}
    for key, entries in grouped.items():
        distinct = sorted({entry.value for entry in entries})
        resolved[key] = ResolvedProperty(
            key=key,
            value=entries[0].value,
            sources=tuple(entries),
            conflicting_values=tuple(distinct) if len(distinct) > 1 else (),
        )
    return resolved
