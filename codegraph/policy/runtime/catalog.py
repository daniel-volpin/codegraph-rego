from __future__ import annotations

from typing import Any, Dict, List, Optional

from codegraph.benchmark_registry import (
    iso_rules_payload_from_registry,
    policy_catalog_entries_from_registry,
    policy_catalog_payload_from_registry,
)

_CATALOG_CACHE: Dict[str, Dict[str, Any]] | None = None
_CATALOG_ENTRIES_CACHE: List[Dict[str, Any]] | None = None
_ISO_RULES_CACHE: Dict[str, Any] | None = None


def load_policy_catalog() -> Dict[str, Dict[str, Any]]:
    global _CATALOG_CACHE, _CATALOG_ENTRIES_CACHE
    if _CATALOG_CACHE is None or _CATALOG_ENTRIES_CACHE is None:
        entries = policy_catalog_entries_from_registry()
        catalog_lookup: Dict[str, Dict[str, Any]] = {}
        catalog_entries: List[Dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id.strip():
                continue
            catalog_entries.append(entry)
            catalog_lookup[entry_id] = entry
            aliases = entry.get("alias_ids") or []
            if isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.strip():
                        catalog_lookup[alias] = entry
        _CATALOG_CACHE = catalog_lookup
        _CATALOG_ENTRIES_CACHE = catalog_entries
    return _CATALOG_CACHE or {}


def get_policy_catalog_entries() -> List[Dict[str, Any]]:
    load_policy_catalog()
    return list(_CATALOG_ENTRIES_CACHE or [])


def violation_id_variants(violation_id: str) -> List[str]:
    text = str(violation_id).strip()
    if not text:
        return []
    variants = [text]
    if text.startswith("ISO-27001-"):
        base = text[len("ISO-27001-") :]
    elif text.startswith("ISO-"):
        base = text[len("ISO-") :]
    else:
        base = text
    for candidate in (base, f"ISO-{base}", f"ISO-27001-{base}"):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def resolve_catalog_entry(
    violation_id: Any,
    catalog: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not violation_id:
        return None
    for candidate in violation_id_variants(str(violation_id)):
        entry = catalog.get(candidate)
        if entry is not None:
            return entry
    return None


def load_iso_rules() -> Dict[str, Any]:
    global _ISO_RULES_CACHE
    if _ISO_RULES_CACHE is None:
        _ISO_RULES_CACHE = iso_rules_payload_from_registry()
    return _ISO_RULES_CACHE or {}


def get_policy_catalog_payload() -> Dict[str, Any]:
    payload = policy_catalog_payload_from_registry()
    payload["controls"] = get_policy_catalog_entries()
    payload["rules"] = load_iso_rules().get("rules", [])
    return payload
