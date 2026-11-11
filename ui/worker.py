"""Background worker: analyze batches, publish rows, fill explanations later."""

from __future__ import annotations

import logging
import threading

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
    ) -> None:
        super().__init__(name="nids-pipeline", daemon=True)
        self.source = source
        self.pipeline = pipeline
        self.store = store
        self.stop_event = stop_event or threading.Event()

    def run(self) -> None:  # pragma: no cover - exercised through integration tests
        self.store.set_status("running")
        try:
            for batch in self.source.stream():
                if self.stop_event.is_set():
                    break
                results = self.pipeline.analyze_frame(
                    batch.frame, batch_id=batch.batch_id
                )
                # Publish model verdicts immediately, before any LLM call.
                self.store.add_results(results)

                for result in results:
                    if self.stop_event.is_set():
                        break
                    if not result.is_attack:
                        continue
                    explanation = self.pipeline.explain_result(result)
                    if explanation is not None:
                        self.store.update_explanation(result.row_key, explanation)

            self.store.set_status("stopped" if self.stop_event.is_set() else "done")
        except Exception as exc:
            logger.exception("Pipeline worker failed")
            self.store.set_error(str(exc))
        finally:
            try:
                self.source.close()
            except Exception:
                logger.exception("Could not close feature source")
