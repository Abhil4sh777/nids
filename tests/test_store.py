from __future__ import annotations

from explain.llm import Explanation
from pipeline import FlowResult
from ui.store import UiStore
from ui.table import TABLE_COLUMNS, rows_to_dataframe


def _result(
    flow_id: str,
    *,
    attack: bool,
    explanation: Explanation | None = None,
) -> FlowResult:
    return FlowResult(
        row_key=f"batch:{flow_id}",
        flow_id=flow_id,
        timestamp="2026-01-01 00:00:00",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        is_attack=attack,
        attack_probability=0.9 if attack else 0.1,
        predicted_class="DoS_Hulk" if attack else None,
        class_probability=0.8 if attack else None,
        explanation=explanation,
    )


def test_store_newest_first_and_pending() -> None:
    store = UiStore(history_limit=10)
    store.add_results([_result("first", attack=False), _result("second", attack=True)])
    rows = store.snapshot()
    assert [row.flow_id for row in rows] == ["second", "first"]
    assert rows[0].pending is True
    assert rows[0].result_text == "explaining..."
    assert rows[1].pending is False
    assert rows[1].result_text == "Benign"
    status = store.status()
    assert status.processed == 2
    assert status.attacks == 1


def test_store_explanation_update() -> None:
    store = UiStore()
    store.add_results([_result("attack", attack=True)])
    store.update_explanation(
        "batch:attack", Explanation(text="explained", source="llm")
    )
    row = store.snapshot()[0]
    assert row.pending is False
    assert row.explanation == "explained"
    assert row.result_text == "explained"


def test_store_shared_group_update() -> None:
    store = UiStore()
    store.add_results([_result("a", attack=True), _result("b", attack=True)])
    store.update_explanations(
        ["batch:a", "batch:b"], Explanation(text="group text", source="llm")
    )
    rows = store.snapshot()
    assert [row.explanation for row in rows] == ["group text", "group text"]
    assert all(row.pending is False for row in rows)


def test_store_accepts_prefilled_explanation() -> None:
    store = UiStore()
    store.add_results(
        [
            _result(
                "attack",
                attack=True,
                explanation=Explanation(text="already explained", source="llm"),
            )
        ]
    )
    row = store.snapshot()[0]
    assert row.pending is False
    assert row.explanation == "already explained"
    assert row.explanation_source == "llm"


def test_store_bounded_history() -> None:
    store = UiStore(history_limit=2)
    store.add_results(
        [
            _result("one", attack=False),
            _result("two", attack=False),
            _result("three", attack=False),
        ]
    )
    assert [row.flow_id for row in store.snapshot()] == ["three", "two"]


def test_rows_to_dataframe_columns_and_values() -> None:
    store = UiStore()
    store.add_results([_result("benign", attack=False), _result("attack", attack=True)])
    frame = rows_to_dataframe(store.snapshot())
    assert list(frame.columns) == TABLE_COLUMNS
    assert frame.iloc[0]["flow_id"] == "attack"
    assert frame.iloc[0]["result"] == "explaining..."
    assert frame.iloc[1]["result"] == "Benign"
    assert frame.iloc[0]["attack_probability"] == 0.9
    assert frame.iloc[1]["predicted_class"] == ""
