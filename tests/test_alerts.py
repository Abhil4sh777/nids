from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from explain.alerts import AlertExplainer
from explain.evidence import EvidencePacket
from explain.llm import Explanation


@dataclass
class FakeResult:
    row_key: str
    predicted_class: str | None = "DoS_Hulk"
    src_ip: str = "10.0.0.1"
    is_attack: bool = True
    evidence: EvidencePacket | None = None
    explanation: Explanation | None = None


@dataclass
class Collector:
    updates: dict[str, Explanation]

    def __init__(self) -> None:
        self.updates = {}
        self.lock = threading.Lock()

    def __call__(self, row_keys, explanation: Explanation) -> None:
        with self.lock:
            for key in row_keys:
                self.updates[key] = explanation

    def text(self, key: str) -> str:
        with self.lock:
            return self.updates[key].text


def _packet(flow_id: str) -> EvidencePacket:
    return EvidencePacket(
        flow_id=flow_id,
        attack_probability=0.9,
        predicted_class="DoS_Hulk",
        class_probability=0.8,
        description="description",
        mitigation=("m1", "m2", "m3"),
        detector_top5=(),
        classifier_top5=(),
    )


def _result(key: str, **kwargs) -> FakeResult:
    return FakeResult(row_key=key, evidence=_packet(key), **kwargs)


def _wait_for(collector: Collector, key: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with collector.lock:
            if key in collector.updates:
                return
        time.sleep(0.01)
    raise AssertionError(f"{key} was never explained")


def test_same_group_is_explained_once_and_shared() -> None:
    calls: list[str] = []
    collector = Collector()

    def explain(result: FakeResult) -> Explanation:
        calls.append(result.row_key)
        return Explanation(text=f"explained {result.row_key}", source="llm")

    alerts = AlertExplainer(
        explain=explain,
        on_explanations=collector,
        queue_size=8,
        window_seconds=60,
        clock=lambda: 0.0,
    )
    alerts.start()
    results = [_result("a"), _result("b"), _result("c")]
    alerts.submit(results)
    alerts.close()

    assert len(calls) == 1, calls
    for key in ("a", "b", "c"):
        assert collector.text(key) == "explained a"
        assert collector.updates[key].source == "llm"


def test_different_class_or_source_is_a_different_group() -> None:
    calls: list[str] = []
    collector = Collector()

    def explain(result: FakeResult) -> Explanation:
        calls.append(result.row_key)
        return Explanation(text=f"explained {result.row_key}", source="llm")

    alerts = AlertExplainer(
        explain=explain,
        on_explanations=collector,
        queue_size=8,
        window_seconds=60,
        clock=lambda: 0.0,
    )
    alerts.start()
    alerts.submit(
        [
            _result("a"),
            _result("b", predicted_class="Port_Scan"),
            _result("c", src_ip="10.0.0.9"),
        ]
    )
    alerts.close()

    assert sorted(calls) == ["a", "b", "c"]


def test_benign_rows_never_reach_the_llm() -> None:
    calls: list[str] = []
    collector = Collector()

    alerts = AlertExplainer(
        explain=lambda result: calls.append(result.row_key),
        on_explanations=collector,
        queue_size=4,
        window_seconds=60,
        clock=lambda: 0.0,
    )
    alerts.start()
    alerts.submit([_result("benign", is_attack=False, predicted_class=None)])
    alerts.close()

    assert calls == []
    assert collector.updates == {}


def test_full_queue_falls_back_without_blocking() -> None:
    collector = Collector()
    started = threading.Event()
    release = threading.Event()

    def explain(result: FakeResult) -> Explanation:
        started.set()
        release.wait(timeout=5)
        return Explanation(text=f"explained {result.row_key}", source="llm")

    alerts = AlertExplainer(
        explain=explain,
        on_explanations=collector,
        queue_size=1,
        window_seconds=60,
        clock=lambda: 0.0,
    )
    alerts.start()
    try:
        alerts.submit([_result("first")])
        assert started.wait(timeout=5), "worker never started the first job"
        alerts.submit([_result("second", src_ip="10.0.0.2")])
        # The worker is busy and the single queue slot is taken.
        alerts.submit([_result("third", src_ip="10.0.0.3")])
        assert collector.updates["third"].source == "fallback"
        assert "queue full" in (collector.updates["third"].error or "").lower()
        release.set()
    finally:
        release.set()
        alerts.close()

    assert collector.updates["first"].source == "llm"
    assert collector.updates["second"].source == "llm"


def test_rows_joining_a_finished_group_share_its_explanation() -> None:
    calls: list[str] = []
    collector = Collector()

    def explain(result: FakeResult) -> Explanation:
        calls.append(result.row_key)
        return Explanation(text="shared text", source="llm")

    alerts = AlertExplainer(
        explain=explain,
        on_explanations=collector,
        queue_size=4,
        window_seconds=60,
        clock=lambda: 1.0,
    )
    alerts.start()
    try:
        alerts.submit([_result("first")])
        _wait_for(collector, "first")
        alerts.submit([_result("late")])
        assert collector.text("late") == "shared text"
    finally:
        alerts.close()

    assert calls == ["first"]


def test_explain_failure_uses_the_fallback() -> None:
    collector = Collector()

    def explain(result: FakeResult) -> Explanation:
        raise RuntimeError("backend exploded")

    alerts = AlertExplainer(
        explain=explain,
        on_explanations=collector,
        queue_size=4,
        window_seconds=60,
        clock=lambda: 0.0,
    )
    alerts.start()
    alerts.submit([_result("a")])
    alerts.close()

    assert collector.updates["a"].source == "fallback"
    assert "backend exploded" in (collector.updates["a"].error or "")
