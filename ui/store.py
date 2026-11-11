"""Thread-safe UI store shared by the pipeline worker and Streamlit."""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from explain.evidence import EvidencePacket
from explain.llm import Explanation
from pipeline import FlowResult


@dataclass(frozen=True)
class UiRow:
    row_key: str
    flow_id: str
    timestamp: str
    src_ip: str
    src_port: Any
    dst_ip: str
    dst_port: Any
    verdict: str
    attack_probability: float
    predicted_class: str | None
    class_probability: float | None
    explanation: str | None
    explanation_source: str | None
    explanation_error: str | None
    pending: bool
    evidence: EvidencePacket | None
    updated_at: datetime

    @property
    def result_text(self) -> str:
        if self.verdict == "Benign":
            return "Benign"
        if self.pending:
            return "pending explanation"
        return self.explanation or "Attack (explanation unavailable)"


def row_from_result(result: FlowResult) -> UiRow:
    explanation = result.explanation
    return UiRow(
        row_key=result.row_key,
        flow_id=result.flow_id,
        timestamp=result.timestamp,
        src_ip=result.src_ip,
        src_port=result.src_port,
        dst_ip=result.dst_ip,
        dst_port=result.dst_port,
        verdict=result.verdict,
        attack_probability=result.attack_probability,
        predicted_class=result.predicted_class,
        class_probability=result.class_probability,
        explanation=explanation.text if explanation else None,
        explanation_source=explanation.source if explanation else None,
        explanation_error=explanation.error if explanation else None,
        pending=result.is_attack and explanation is None,
        evidence=result.evidence,
        updated_at=datetime.now(timezone.utc),
    )


@dataclass(frozen=True)
class StoreStatus:
    state: str
    source_label: str
    processed: int
    attacks: int
    error: str | None


class UiStore:
    def __init__(self, history_limit: int = 500) -> None:
        self.history_limit = max(1, history_limit)
        self._rows: OrderedDict[str, UiRow] = OrderedDict()
        self._lock = threading.Lock()
        self._state = "idle"
        self._source_label = ""
        self._processed = 0
        self._attacks = 0
        self._error: str | None = None

    def reset(self, source_label: str = "") -> None:
        with self._lock:
            self._rows.clear()
            self._state = "idle"
            self._source_label = source_label
            self._processed = 0
            self._attacks = 0
            self._error = None

    def set_status(self, state: str, *, error: str | None = None) -> None:
        with self._lock:
            self._state = state
            self._error = error

    def set_error(self, error: str) -> None:
        with self._lock:
            self._state = "error"
            self._error = error

    def add_results(self, results: list[FlowResult]) -> None:
        with self._lock:
            for result in results:
                row = row_from_result(result)
                self._rows[row.row_key] = row
                self._rows.move_to_end(row.row_key)
                self._processed += 1
                if result.is_attack:
                    self._attacks += 1
            while len(self._rows) > self.history_limit:
                self._rows.popitem(last=False)

    def update_explanation(self, row_key: str, explanation: Explanation) -> None:
        with self._lock:
            row = self._rows.get(row_key)
            if row is None:
                return
            self._rows[row_key] = replace(
                row,
                explanation=explanation.text,
                explanation_source=explanation.source,
                explanation_error=explanation.error,
                pending=False,
                updated_at=datetime.now(timezone.utc),
            )

    def snapshot(self, limit: int | None = None) -> list[UiRow]:
        with self._lock:
            rows = list(reversed(self._rows.values()))
        if limit is not None:
            rows = rows[:limit]
        return rows

    def status(self) -> StoreStatus:
        with self._lock:
            return StoreStatus(
                state=self._state,
                source_label=self._source_label,
                processed=self._processed,
                attacks=self._attacks,
                error=self._error,
            )
