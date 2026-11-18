"""Background worker: analyze batches, publish rows, explain alerts off-thread.

Inference and the live table never wait for the LLM.  Attack rows appear with
state "explaining..." immediately; the bounded alert queue fills in explanations
one group at a time.
"""

from __future__ import annotations

import logging
import threading

from config import Settings, get_settings
from explain.alerts import AlertExplainer
from explain.llm import ExplanationService
from features.sources import FeatureSource
from pipeline import Pipeline
from ui.store import UiStore

logger = logging.getLogger(__name__)


class PipelineWorker(threading.Thread):
    def __init__(
        self,
        source: FeatureSource,
        pipeline: Pipeline,
        store: UiStore,
        stop_event: threading.Event | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(name="nids-pipeline", daemon=True)
        self.source = source
        self.pipeline = pipeline
        self.store = store
        self.settings = settings or get_settings()
        self.stop_event = stop_event or threading.Event()
        self.alerts = AlertExplainer(
            explain=pipeline.explain_result,
            on_explanations=store.update_explanations,
            queue_size=self.settings.alert_queue_size,
            window_seconds=self.settings.alert_group_window_seconds,
            fallback=ExplanationService.fallback,
        )

    def _close_alerts(self) -> None:
        # Leave room for the in-flight alert plus one queued retry before the
        # worker thread is abandoned.
        timeout = max(60.0, 2.0 * self.pipeline.llm_timeout_seconds)
        self.alerts.close(timeout=timeout)

    def run(self) -> None:  # pragma: no cover - exercised through integration tests
        self.store.set_status("running")
        self.alerts.start()
        try:
            for batch in self.source.stream():
                if self.stop_event.is_set():
                    break
                results = self.pipeline.analyze_frame(
                    batch.frame, batch_id=batch.batch_id
                )
                # Publish model verdicts immediately, before any LLM call.
                self.store.add_results(results)
                self.alerts.submit(results)

            self.store.set_status("stopped" if self.stop_event.is_set() else "done")
        except Exception as exc:
            logger.exception("Pipeline worker failed")
            self.store.set_error(str(exc))
        finally:
            self._close_alerts()
            try:
                self.source.close()
            except Exception:
                logger.exception("Could not close feature source")
