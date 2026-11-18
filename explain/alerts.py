"""Alert grouping and throttling, independent of the UI.

A DoS flood can produce hundreds of alerts; a 1B model on a Pi cannot explain
them all.  Alerts are grouped by ``(predicted_class, src_ip, window)`` and a
single worker process explains one representative per group.  Rows that join a
group share its explanation.  The queue is bounded: when it is full the group
immediately gets the evidence-based fallback text, and that is logged.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from explain.evidence import EvidencePacket
from explain.llm import Explanation, fallback_text

logger = logging.getLogger(__name__)


class AlertResult(Protocol):
    """The small slice of a flow result the alert explainer needs."""

    row_key: str
    is_attack: bool
    predicted_class: str | None
    src_ip: str
    evidence: EvidencePacket | None


@dataclass(frozen=True)
class AlertGroup:
    """Group identity: class + source + arrival-time bucket."""

    predicted_class: str
    src_ip: str
    window_index: int


def group_for(
    result: AlertResult, now: float, window_seconds: float
) -> AlertGroup:
    window = max(1.0, float(window_seconds))
    return AlertGroup(
        predicted_class=result.predicted_class or "Unknown",
        src_ip=result.src_ip,
        window_index=int(now // window),
    )


@dataclass
class _GroupState:
    row_keys: list[str] = field(default_factory=list)
    done: Explanation | None = None
    queued: bool = False


@dataclass(frozen=True)
class _Job:
    group: AlertGroup
    result: AlertResult


ExplainFn = Callable[[AlertResult], Explanation | None]
UpdateFn = Callable[[Sequence[str], Explanation], None]
FallbackFn = Callable[..., Explanation]


class AlertExplainer:
    """Bounded single-worker queue that explains one flow per alert group."""

    def __init__(
        self,
        *,
        explain: ExplainFn,
        on_explanations: UpdateFn,
        queue_size: int = 64,
        window_seconds: float = 60.0,
        fallback: FallbackFn | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._explain = explain
        self._on_explanations = on_explanations
        self._queue_size = max(1, int(queue_size))
        self._window_seconds = max(1.0, float(window_seconds))
        self._fallback = fallback or (
            lambda evidence, error=None: Explanation(
                text=fallback_text(evidence), source="fallback", error=error
            )
        )
        self._clock = clock
        self._queue: queue.Queue[_Job | None] = queue.Queue(
            maxsize=self._queue_size
        )
        self._lock = threading.Lock()
        self._states: dict[AlertGroup, _GroupState] = {}
        self._thread: threading.Thread | None = None
        self._closed = False

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._closed = False
        self._thread = threading.Thread(
            target=self._run, name="nids-alert-llm", daemon=True
        )
        self._thread.start()

    def close(self, timeout: float = 60.0) -> None:
        thread = self._thread
        self._closed = True
        if thread is None:
            return
        try:
            self._queue.put(None, timeout=max(0.1, timeout))
        except queue.Full:
            logger.warning(
                "Alert queue still full at shutdown; remaining alerts use the "
                "evidence fallback"
            )
        thread.join(timeout=max(0.1, timeout))
        if thread.is_alive():
            logger.warning(
                "Alert worker did not finish within %.1fs; pending alerts use "
                "the evidence fallback",
                timeout,
            )
        self._drain_leftovers("Alert queue closed before the LLM finished")
        self._thread = None

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    # -- submission -----------------------------------------------------
    def submit(self, results: Sequence[AlertResult]) -> None:
        """Group attacks in ``results`` and queue at most one job per group."""

        now = self._clock()
        updates: list[tuple[list[str], Explanation]] = []
        with self._lock:
            window_index = int(now // self._window_seconds)
            self._prune_stale(window_index)
            for result in results:
                if not result.is_attack or result.evidence is None:
                    continue
                group = group_for(result, now, self._window_seconds)
                state = self._states.setdefault(group, _GroupState())
                state.row_keys.append(result.row_key)
                if state.done is not None:
                    updates.append(([result.row_key], state.done))
                    continue
                if state.queued:
                    continue  # the running job will cover this row key too
                job = _Job(group=group, result=result)
                try:
                    self._queue.put_nowait(job)
                except queue.Full:
                    state.done = self._fallback(
                        result.evidence,
                        error=(
                            "Alert queue full; used the evidence-based fallback"
                        ),
                    )
                    state.queued = False
                    updates.append((list(state.row_keys), state.done))
                    logger.warning(
                        "Alert queue full (%d); flow %s in group %s/%s uses "
                        "the evidence fallback",
                        self._queue_size,
                        result.row_key,
                        group.predicted_class,
                        group.src_ip,
                    )
                else:
                    state.queued = True
        self._apply(updates)

    def _prune_stale(self, window_index: int) -> None:
        stale = [
            group
            for group, state in self._states.items()
            if state.done is not None and group.window_index < window_index - 1
        ]
        for group in stale:
            del self._states[group]

    # -- worker ---------------------------------------------------------
    def _run(self) -> None:
        while True:
            job = self._queue.get()
            try:
                if job is None:
                    return
                try:
                    explanation = self._explain_job(job)
                    with self._lock:
                        state = self._states.get(job.group)
                        if state is None:
                            continue
                        state.done = explanation
                        state.queued = False
                        row_keys = list(state.row_keys)
                    self._on_explanations(row_keys, explanation)
                except Exception:
                    # A broken callback must not kill the worker silently.
                    logger.exception(
                        "Alert worker failed for group %s/%s",
                        job.group.predicted_class,
                        job.group.src_ip,
                    )
            finally:
                self._queue.task_done()

    def _explain_job(self, job: _Job) -> Explanation:
        try:
            explanation = self._explain(job.result)
        except Exception as exc:
            logger.exception(
                "Group explanation failed for %s/%s",
                job.group.predicted_class,
                job.group.src_ip,
            )
            if job.result.evidence is None:
                raise
            return self._fallback(job.result.evidence, error=str(exc))
        if explanation is None:
            if job.result.evidence is None:
                raise ValueError("Attack result has no evidence packet")
            return self._fallback(
                job.result.evidence,
                error="The explanation client returned nothing",
            )
        return explanation

    def _drain_leftovers(self, error: str) -> None:
        leftovers: list[_Job] = []
        while True:
            try:
                job = self._queue.get_nowait()
            except queue.Empty:
                break
            if job is None:
                continue
            leftovers.append(job)
        updates: list[tuple[list[str], Explanation]] = []
        with self._lock:
            for job in leftovers:
                state = self._states.get(job.group)
                if state is None or state.done is not None:
                    continue
                state.done = self._fallback(job.result.evidence, error=error)
                state.queued = False
                updates.append((list(state.row_keys), state.done))
        self._apply(updates)

    def _apply(self, updates: list[tuple[list[str], Explanation]]) -> None:
        for row_keys, explanation in updates:
            if row_keys:
                self._on_explanations(row_keys, explanation)

    def __enter__(self) -> "AlertExplainer":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()
