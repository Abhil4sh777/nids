"""Load and validate the project knowledge packet."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from features.contract import ALL_FEATURES, CLASSIFIER_LABELS

logger = logging.getLogger(__name__)


class KnowledgeBaseError(RuntimeError):
    """Raised when the knowledge packet is incomplete or malformed."""


@dataclass(frozen=True)
class AttackInfo:
    name: str
    description: str
    mitigation: tuple[str, ...]


@dataclass(frozen=True)
class KnowledgeBase:
    feature_info: dict[str, str]
    attacks: dict[str, AttackInfo]

    def feature_meaning(self, feature: str) -> str:
        try:
            return self.feature_info[feature]
        except KeyError as exc:
            raise KnowledgeBaseError(
                f"No feature_info entry for feature {feature!r}"
            ) from exc

    def attack(self, label: str) -> AttackInfo:
        try:
            return self.attacks[label]
        except KeyError as exc:
            raise KnowledgeBaseError(
                f"No attack entry for class {label!r}"
            ) from exc


def _read_json(path: Path) -> Any:
    if not path.exists():
        raise KnowledgeBaseError(
            f"Knowledge packet file not found: {path}. Run from the project root "
            "or set NIDS_KNOWLEDGE_DIR."
        )
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise KnowledgeBaseError(f"Invalid JSON in {path}: {exc}") from exc


def load_knowledge_base(directory: Path) -> KnowledgeBase:
    feature_raw = _read_json(directory / "feature_info.json")
    attacks_raw = _read_json(directory / "attacks.json")

    if not isinstance(feature_raw, dict):
        raise KnowledgeBaseError("feature_info.json must contain an object")
    if not isinstance(attacks_raw, dict):
        raise KnowledgeBaseError("attacks.json must contain an object")

    missing_features = [name for name in ALL_FEATURES if name not in feature_raw]
    if missing_features:
        raise KnowledgeBaseError(
            "feature_info.json is missing entries for: "
            + ", ".join(missing_features[:15])
        )

    attacks: dict[str, AttackInfo] = {}
    for label in CLASSIFIER_LABELS.values():
        raw = attacks_raw.get(label)
        if raw is None:
            raise KnowledgeBaseError(f"attacks.json is missing class {label!r}")
        if not isinstance(raw, dict):
            raise KnowledgeBaseError(f"attacks.json entry {label!r} must be an object")
        description = raw.get("description")
        mitigation = raw.get("mitigation")
        if not isinstance(description, str) or not description.strip():
            raise KnowledgeBaseError(
                f"attacks.json entry {label!r} needs a non-empty description"
            )
        if (
            not isinstance(mitigation, list)
            or len(mitigation) != 3
            or not all(isinstance(item, str) and item.strip() for item in mitigation)
        ):
            raise KnowledgeBaseError(
                f"attacks.json entry {label!r} needs exactly three mitigation strings"
            )
        attacks[label] = AttackInfo(
            name=label,
            description=description.strip(),
            mitigation=tuple(item.strip() for item in mitigation),
        )

    unknown_attacks = sorted(set(attacks_raw) - set(CLASSIFIER_LABELS.values()))
    if unknown_attacks:
        raise KnowledgeBaseError(
            "attacks.json contains labels outside the classifier contract: "
            + ", ".join(unknown_attacks)
        )

    feature_info = {
        name: str(feature_raw[name]).strip() for name in ALL_FEATURES
    }
    logger.info(
        "Loaded knowledge packet: %d feature meanings, %d attack classes",
        len(feature_info),
        len(attacks),
    )
    return KnowledgeBase(feature_info=feature_info, attacks=attacks)
