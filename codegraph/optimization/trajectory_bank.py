"""Persistent trajectory bank for storing and retrieving verified 3-gate repair exemplars."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

DEFAULT_TRAJECTORY_BANK_PATH = Path("outputs/trajectory_bank/bank.json")


@dataclass(frozen=True)
class TrajectoryBankEntry:
    """A verified 3-gate repair trajectory stored as a reference exemplar."""

    case_id: str
    rule_id: str
    target_method: str
    initial_code: str
    diff: str
    turns_count: int
    tool_sequence: list[str]
    verification_summary: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrajectoryBankEntry:
        return cls(
            case_id=str(data.get("case_id") or ""),
            rule_id=str(data.get("rule_id") or ""),
            target_method=str(data.get("target_method") or ""),
            initial_code=str(data.get("initial_code") or ""),
            diff=str(data.get("diff") or ""),
            turns_count=int(data.get("turns_count") or 1),
            tool_sequence=list(data.get("tool_sequence") or []),
            verification_summary=str(data.get("verification_summary") or ""),
            timestamp=str(data.get("timestamp") or ""),
        )


class TrajectoryBank:
    """Manages storage and dynamic retrieval of verified few-shot exemplars."""

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        storage_path: Path | str | None = None,
    ) -> None:
        target = storage_path or path or DEFAULT_TRAJECTORY_BANK_PATH
        self.path = Path(target).resolve()
        self.entries: list[TrajectoryBankEntry] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                self.entries = [TrajectoryBankEntry.from_dict(item) for item in raw if isinstance(item, dict)]
                LOGGER.info("Loaded %d verified exemplars from %s", len(self.entries), self.path)
        except Exception as exc:
            LOGGER.warning("Failed to load trajectory bank from %s: %s", self.path, exc)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [e.to_dict() for e in self.entries]
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        LOGGER.info("Saved %d verified exemplars to %s", len(self.entries), self.path)

    def deposit(self, entry: TrajectoryBankEntry) -> None:
        """Add a verified trajectory to the bank, deduplicating by case_id."""
        self.entries = [e for e in self.entries if e.case_id != entry.case_id]
        self.entries.append(entry)

    def get_exemplars_for_rule(self, rule_id: str, max_count: int = 2) -> list[TrajectoryBankEntry]:
        """Query top verified exemplars matching rule_id, ordered by turn efficiency."""
        matching = [e for e in self.entries if e.rule_id == rule_id]
        matching.sort(key=lambda e: (e.turns_count, len(e.diff)))
        return matching[:max_count]

    def query_exemplars(self, rule_id: str, limit: int = 2) -> list[TrajectoryBankEntry]:
        """Alias for get_exemplars_for_rule."""
        return self.get_exemplars_for_rule(rule_id, max_count=limit)

    def format_few_shot_prompt_section(self, rule_id: str, max_count: int = 1) -> str:
        """Format matching verified exemplars as a prompt section."""
        exemplars = self.get_exemplars_for_rule(rule_id, max_count=max_count)
        if not exemplars:
            return ""

        lines = ["\nVerified Reference Demonstrations (Few-Shot):"]
        for idx, ex in enumerate(exemplars, 1):
            lines.append(f"\nExample {idx} ({ex.rule_id}):")
            lines.append(f"Target Method: {ex.target_method}")
            lines.append(f"Verified Patch:\n```diff\n{ex.diff}\n```")
            lines.append(f"Verification: {ex.verification_summary}")
        return "\n".join(lines)
