from __future__ import annotations

import json
from pathlib import Path

import pytest

from explain.knowledge_base import KnowledgeBase, KnowledgeBaseError, load_knowledge_base
from features.contract import ALL_FEATURES, CLASSIFIER_LABELS


def test_real_knowledge_packet_covers_contract(knowledge: KnowledgeBase) -> None:
    assert set(knowledge.feature_info) == set(ALL_FEATURES)
    assert set(knowledge.attacks) == set(CLASSIFIER_LABELS.values())
    for name in ALL_FEATURES:
        assert knowledge.feature_meaning(name).strip()
    for label in CLASSIFIER_LABELS.values():
        attack = knowledge.attack(label)
        assert attack.description.strip()
        assert len(attack.mitigation) == 3
        assert all(item.strip() for item in attack.mitigation)


def test_unknown_feature_has_clear_error(knowledge: KnowledgeBase) -> None:
    with pytest.raises(KnowledgeBaseError, match="not_a_feature"):
        knowledge.feature_meaning("not_a_feature")


def test_unknown_attack_has_clear_error(knowledge: KnowledgeBase) -> None:
    with pytest.raises(KnowledgeBaseError, match="Not_A_Class"):
        knowledge.attack("Not_A_Class")


def _write_packet(directory: Path, feature_info: dict, attacks: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "feature_info.json").write_text(
        json.dumps(feature_info), encoding="utf-8"
    )
    (directory / "attacks.json").write_text(json.dumps(attacks), encoding="utf-8")


def test_missing_feature_entry_is_rejected(tmp_path: Path) -> None:
    source = load_knowledge_base(
        Path(__file__).resolve().parents[1] / "explain" / "knowledge"
    )
    feature_info = dict(source.feature_info)
    feature_info.pop("duration")
    attacks = {
        label: {
            "description": attack.description,
            "mitigation": list(attack.mitigation),
        }
        for label, attack in source.attacks.items()
    }
    _write_packet(tmp_path, feature_info, attacks)
    with pytest.raises(KnowledgeBaseError, match="duration"):
        load_knowledge_base(tmp_path)


def test_missing_attack_entry_is_rejected(tmp_path: Path) -> None:
    source = load_knowledge_base(
        Path(__file__).resolve().parents[1] / "explain" / "knowledge"
    )
    feature_info = dict(source.feature_info)
    attacks = {
        label: {
            "description": attack.description,
            "mitigation": list(attack.mitigation),
        }
        for label, attack in source.attacks.items()
    }
    attacks.pop("Heartbleed")
    _write_packet(tmp_path, feature_info, attacks)
    with pytest.raises(KnowledgeBaseError, match="Heartbleed"):
        load_knowledge_base(tmp_path)


def test_bad_mitigation_shape_is_rejected(tmp_path: Path) -> None:
    source = load_knowledge_base(
        Path(__file__).resolve().parents[1] / "explain" / "knowledge"
    )
    feature_info = dict(source.feature_info)
    attacks = {
        label: {
            "description": attack.description,
            "mitigation": list(attack.mitigation),
        }
        for label, attack in source.attacks.items()
    }
    attacks["DoS_Hulk"]["mitigation"] = ["only one"]
    _write_packet(tmp_path, feature_info, attacks)
    with pytest.raises(KnowledgeBaseError, match="three mitigation"):
        load_knowledge_base(tmp_path)
