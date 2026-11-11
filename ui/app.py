"""Streamlit UI.  All blocking work runs in a background thread."""

from __future__ import annotations

import io
import logging
import threading
from dataclasses import replace
from pathlib import Path

import pandas as pd
import streamlit as st

from capture.dumpcap import find_dumpcap
from config import Settings, get_settings
from explain.knowledge_base import load_knowledge_base
from explain.llm import OllamaClient
from features.sources import (
    FeatureSource,
    LiveFeatureSource,
    PcapFeatureSource,
    StaticFeatureSource,
)
from models.loader import load_models
from pipeline import Pipeline
from ui.store import UiStore
from ui.table import render_attack_details, render_table
from ui.worker import PipelineWorker

logger = logging.getLogger(__name__)


@st.cache_resource(show_spinner="Loading models, SHAP explainers, and knowledge packet...")
def _load_pipeline(settings: Settings) -> Pipeline:
    models = load_models(settings)
    knowledge = load_knowledge_base(settings.knowledge_dir)
    return Pipeline(models, knowledge, OllamaClient(settings))


def _get_store(settings: Settings) -> UiStore:
    store = st.session_state.get("nids_store")
    if store is None:
        store = UiStore(settings.history_limit)
        st.session_state["nids_store"] = store
    return store


def _start(
    source: FeatureSource,
    pipeline: Pipeline,
    store: UiStore,
    source_label: str,
) -> None:
    existing = st.session_state.get("nids_worker")
    if existing is not None and existing.is_alive():
        st.warning("A run is already active. Stop it before starting another.")
        return

    store.reset(source_label)
    stop_event = threading.Event()
    worker = PipelineWorker(source, pipeline, store, stop_event)
    st.session_state["nids_worker"] = worker
    st.session_state["nids_source"] = source
    st.session_state["nids_stop_event"] = stop_event
    worker.start()


def _stop(store: UiStore) -> None:
    stop_event = st.session_state.get("nids_stop_event")
    source = st.session_state.get("nids_source")
    if stop_event is not None:
        stop_event.set()
    if source is not None:
        try:
            source.close()
        except Exception:
            logger.exception("Could not close source on stop")
    store.set_status("stopped")


def _sidebar(settings: Settings, pipeline: Pipeline, store: UiStore) -> None:
    st.sidebar.header("Run")

    mode = st.sidebar.radio(
        "Feature-row source",
        ["CSV (pre-extracted)", "PCAP replay", "Live capture"],
        help="All modes share the same inference, SHAP, explanation, and table code.",
    )

    source: FeatureSource | None = None
    label = ""
    live_settings = settings

    if mode == "CSV (pre-extracted)":
        uploaded = st.sidebar.file_uploader("Feature CSV", type=["csv"])
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
    elif mode == "PCAP replay":
        pcap_text = st.sidebar.text_input(
            "PCAP / PCAPNG path",
            value=str(settings.project_root / "capture" / "sample.pcap"),
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
            help=r"Examples: \Device\NPF_{GUID}, Wi-Fi, or Ethernet.",
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
            _start(source, pipeline, store, label)
            st.rerun()
    if stop_col.button("Stop", width="stretch"):
        _stop(store)
        st.rerun()

    st.sidebar.divider()
    st.sidebar.subheader("LLM")
    ollama = OllamaClient(settings)
    try:
        status = ollama.status()
    except Exception as exc:  # status() is defensive, but never break the UI
        st.sidebar.error(f"LLM status check failed: {exc}")
    else:
        if not status.reachable:
            st.sidebar.error(status.detail)
        elif not status.model_available:
            st.sidebar.warning(status.detail)
        elif status.gpu is True:
            st.sidebar.success(status.detail)
        elif status.gpu is False:
            st.sidebar.warning(status.detail + " (GPU was requested)")
        else:
            st.sidebar.info(status.detail)
    st.sidebar.caption(f"Model: `{settings.ollama_model}`")
    st.sidebar.caption(f"num_gpu: `{settings.ollama_num_gpu}`")


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
    store = _get_store(settings)

    st.title("Network intrusion detection")
    st.caption(
        "Detector → classifier → SHAP evidence → local LLM explanation. "
        "Benign flows never call the LLM."
    )

    _sidebar(settings, pipeline, store)
    _render_live(store, settings)


if __name__ == "__main__":
    main()
