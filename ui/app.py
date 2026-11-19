"""Streamlit UI.  All blocking work runs in a background thread."""

from __future__ import annotations

import io
import logging
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path

import pandas as pd
import streamlit as st

from capture.dumpcap import find_dumpcap
from config import Settings, get_settings
from explain.llm import BackendStatus, StatusProvider
from features.sources import (
    CsvFeatureSource,
    FeatureSource,
    LiveFeatureSource,
    PcapFeatureSource,
    StaticFeatureSource,
)
from pipeline import Pipeline, build_pipeline
from ui.store import UiStore
from ui.table import render_attack_details, render_table
from ui.worker import PipelineWorker

logger = logging.getLogger(__name__)


@dataclass
class Runtime:
    """Process-wide run state, shared by every browser session.

    It lives in ``st.cache_resource`` rather than ``st.session_state`` on
    purpose: a page reload (or a second tab) must attach to the capture that is
    already running instead of starting a second ``dumpcap`` on the same
    interface.  The Pi is CPU-bound and cannot afford duplicate pipelines.
    """

    store: UiStore
    worker: PipelineWorker | None = None
    stop_event: threading.Event | None = None
    source: FeatureSource | None = None
    autostarted: bool = field(default=False)


@st.cache_resource(show_spinner="Loading models, SHAP explainers, and knowledge packet...")
def _load_pipeline(settings: Settings) -> Pipeline:
    return build_pipeline(settings)


@st.cache_resource(show_spinner=False)
def _runtime(history_limit: int) -> Runtime:
    return Runtime(store=UiStore(history_limit))


def _get_runtime(settings: Settings) -> Runtime:
    return _runtime(settings.history_limit)


def _is_running(runtime: Runtime) -> bool:
    return runtime.worker is not None and runtime.worker.is_alive()


def _start(
    source: FeatureSource,
    pipeline: Pipeline,
    runtime: Runtime,
    source_label: str,
    settings: Settings,
) -> None:
    if _is_running(runtime):
        st.warning("A run is already active. Stop it before starting another.")
        return

    runtime.store.reset(source_label)
    stop_event = threading.Event()
    worker = PipelineWorker(source, pipeline, runtime.store, stop_event, settings)
    runtime.worker = worker
    runtime.stop_event = stop_event
    runtime.source = source
    worker.start()


def _stop(runtime: Runtime) -> None:
    if runtime.stop_event is not None:
        runtime.stop_event.set()
    if runtime.source is not None:
        try:
            runtime.source.close()
        except Exception:
            logger.exception("Could not close source on stop")
    runtime.store.set_status("stopped")


def _autostart(settings: Settings, pipeline: Pipeline, runtime: Runtime) -> None:
    """Start live capture on load when ``NIDS_AUTOSTART=1`` (Pi appliance mode).

    Runs at most once per process: a reload reuses the running worker instead
    of starting a second capture.
    """

    if runtime.autostarted or not settings.autostart:
        return
    runtime.autostarted = True

    if not settings.interface:
        st.sidebar.warning(
            "NIDS_AUTOSTART=1 but NIDS_INTERFACE is empty; pick an interface "
            "and press Start."
        )
        return
    if _is_running(runtime):
        return

    try:
        find_dumpcap(settings.dumpcap_path)
    except Exception as exc:
        st.sidebar.error(f"Autostart skipped: {exc}")
        return

    _start(
        LiveFeatureSource(settings),
        pipeline,
        runtime,
        f"Live: {settings.interface}",
        settings,
    )


def _sidebar(settings: Settings, pipeline: Pipeline, runtime: Runtime) -> None:
    st.sidebar.header("Run")

    mode = st.sidebar.radio(
        "Feature-row source",
        ["CSV (pre-extracted)", "PCAP replay", "Live capture"],
        index=2 if settings.autostart else 0,
        help="All modes share the same inference, SHAP, explanation, and table code.",
    )

    source: FeatureSource | None = None
    label = ""
    live_settings = settings

    if mode == "CSV (pre-extracted)":
        uploaded = st.sidebar.file_uploader("Feature CSV", type=["csv"])
        csv_text = st.sidebar.text_input(
            "or a CSV path on this machine",
            value="",
            help="Use a path for exports larger than the upload limit.",
        )
        st.sidebar.caption("Rows must satisfy the 121-column contract.")
        if uploaded is not None:
            try:
                frame = pd.read_csv(io.BytesIO(uploaded.getvalue()), low_memory=False)
            except Exception as exc:
                st.sidebar.error(f"Could not read CSV: {exc}")
            else:
                source = StaticFeatureSource(frame, batch_id=uploaded.name)
                label = f"CSV: {uploaded.name}"
                st.sidebar.caption(f"{len(frame)} row(s) loaded")
        elif csv_text:
            csv_path = Path(csv_text).expanduser()
            if csv_path.exists():
                source = CsvFeatureSource(csv_path, batch_id=csv_path.stem)
                label = f"CSV: {csv_path.name}"
                st.sidebar.caption(f"Reading {csv_path}")
            else:
                st.sidebar.error(f"CSV not found: {csv_path}")
    elif mode == "PCAP replay":
        pcap_text = st.sidebar.text_input(
            "PCAP / PCAPNG path",
            value="",
            placeholder="/home/pi/captures/capture.pcap",
        )
        pcap_path = Path(pcap_text).expanduser()
        st.sidebar.caption("Replays the file through NTLFlowLyzer, then inference.")
        if pcap_text and pcap_path.exists():
            source = PcapFeatureSource(pcap_path, settings)
            label = f"PCAP: {pcap_path.name}"
        elif pcap_text:
            st.sidebar.caption("File does not exist yet.")
    else:
        interface = st.sidebar.text_input(
            "Interface",
            value=settings.interface or "",
            help="Examples: eth0, wlan0, enp3s0, end0 (see `ip link`).",
        )
        live_settings = replace(settings, interface=interface or None)
        try:
            find_dumpcap(live_settings.dumpcap_path)
            st.sidebar.caption(
                f"Rolling {live_settings.pcap_rotation_seconds}s files, "
                f"ring of {live_settings.pcap_ring_files}."
            )
        except Exception as exc:
            st.sidebar.error(str(exc))
        if interface:
            source = LiveFeatureSource(live_settings)
            label = f"Live: {interface}"

    start_col, stop_col = st.sidebar.columns(2)
    if start_col.button("Start", type="primary", width="stretch"):
        if source is None:
            st.sidebar.error("Choose a valid source first.")
        else:
            _start(source, pipeline, runtime, label, settings)
            st.rerun()
    if stop_col.button("Stop", width="stretch"):
        _stop(runtime)
        st.rerun()

    st.sidebar.divider()
    st.sidebar.subheader("LLM")
    backend = pipeline.backend
    if backend is None:
        st.sidebar.info("The pipeline is using a custom explanation client.")
    else:
        st.sidebar.caption(f"Backend: `{backend.name}`")
        status: BackendStatus | None = None
        if isinstance(backend, StatusProvider):
            try:
                status = backend.status()
            except Exception as exc:  # status checks must never break the UI
                st.sidebar.error(f"LLM status check failed: {exc}")
        if status is None:
            st.sidebar.info("No status check is available for this backend.")
        elif status.ready:
            st.sidebar.success(status.detail)
        else:
            st.sidebar.warning(status.detail)
    st.sidebar.caption(
        f"Groups: `{settings.alert_group_window_seconds:.0f}s`, "
        f"queue: `{settings.alert_queue_size}`"
    )


def _render_live(store: UiStore, settings: Settings) -> None:
    @st.fragment(run_every=settings.ui_refresh_seconds)
    def _panel() -> None:
        status = store.status()
        left, middle, right, far = st.columns(4)
        left.metric("Source", status.source_label or "—")
        middle.metric("Flows", status.processed)
        right.metric("Attacks", status.attacks)
        far.metric("State", status.state)

        if status.error:
            st.error(status.error)

        rows = store.snapshot()
        render_table(rows)
        st.divider()
        render_attack_details(rows)

    _panel()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    st.set_page_config(
        page_title="NIDS live flow explanations",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    settings = get_settings()
    settings.ensure_directories()
    pipeline = _load_pipeline(settings)
    runtime = _get_runtime(settings)

    st.title("Network intrusion detection")
    st.caption(
        "Detector → classifier → SHAP evidence → local LLM explanation. "
        "Benign flows never call the LLM."
    )

    _sidebar(settings, pipeline, runtime)
    _autostart(settings, pipeline, runtime)
    _render_live(runtime.store, settings)


if __name__ == "__main__":
    main()
