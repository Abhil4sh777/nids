from __future__ import annotations

import pandas as pd
import pytest

from explain.knowledge_base import KnowledgeBase
from models.loader import LoadedModels
from pipeline import Pipeline


def _pipeline(models: LoadedModels, knowledge: KnowledgeBase, llm) -> Pipeline:
    return Pipeline(models, knowledge, llm)


def test_analyze_frame_does_not_call_llm(
    models, knowledge, mixed_frame, stub_llm
) -> None:
    pipeline = _pipeline(models, knowledge, stub_llm)
    results = pipeline.analyze_frame(mixed_frame, batch_id="batch")
    assert len(results) == 2
    assert stub_llm.packets == []
    attack = next(result for result in results if result.is_attack)
    benign = next(result for result in results if not result.is_attack)
    assert attack.evidence is not None
    assert attack.explanation is None
    assert benign.evidence is None
    assert benign.explanation is None
    assert attack.row_key.startswith("batch:")


def test_run_frame_explains_only_attacks(
    models, knowledge, mixed_frame, stub_llm
) -> None:
    pipeline = _pipeline(models, knowledge, stub_llm)
    results = pipeline.run_frame(mixed_frame, batch_id="batch")
    attack = next(result for result in results if result.is_attack)
    benign = next(result for result in results if not result.is_attack)
    assert attack.explanation is not None
    assert attack.explanation.text == "Stub explanation"
    assert benign.explanation is None
    assert len(stub_llm.packets) == 1


def test_benign_row_never_reaches_llm(
    models, knowledge, mixed_frame, stub_llm
) -> None:
    pipeline = _pipeline(models, knowledge, stub_llm)
    benign = pipeline.analyze_frame(mixed_frame)[1]
    assert pipeline.explain_result(benign) is None
    assert stub_llm.packets == []


def test_pipeline_rejects_incomplete_rows(
    models, knowledge, mixed_frame, stub_llm
) -> None:
    pipeline = _pipeline(models, knowledge, stub_llm)
    with pytest.raises(Exception, match="missing"):
        pipeline.analyze_frame(mixed_frame.drop(columns=["duration"]))
