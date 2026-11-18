"""Streamlit table rendering helpers."""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from ui.store import UiRow

TABLE_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "timestamp",
    "src_port",
    "dst_port",
    "result",
    "attack_probability",
    "predicted_class",
    "class_probability",
]


def _round(value: float | None) -> float | None:
    return None if value is None else round(float(value), 4)


def rows_to_dataframe(rows: list[UiRow]) -> pd.DataFrame:
    records: list[dict[str, Any]] = []
    for row in rows:
        text = row.result_text
        if row.verdict == "Attack" and row.explanation:
            # Keep the table readable; the full text is in the detail panel.
            text = row.explanation if len(row.explanation) <= 500 else row.explanation[:497] + "..."
        records.append(
            {
                "flow_id": row.flow_id,
                "src_ip": row.src_ip,
                "dst_ip": row.dst_ip,
                "timestamp": row.timestamp,
                "src_port": row.src_port,
                "dst_port": row.dst_port,
                "result": text,
                "attack_probability": _round(row.attack_probability),
                "predicted_class": row.predicted_class or "",
                "class_probability": _round(row.class_probability),
            }
        )
    if not records:
        return pd.DataFrame(columns=TABLE_COLUMNS)
    return pd.DataFrame.from_records(records, columns=TABLE_COLUMNS)


def render_table(rows: list[UiRow]) -> None:
    frame = rows_to_dataframe(rows)
    st.dataframe(
        frame,
        hide_index=True,
        width="stretch",
        column_config={
            "flow_id": st.column_config.TextColumn("flow_id", width="large"),
            "result": st.column_config.TextColumn("result", width="large"),
            "attack_probability": st.column_config.NumberColumn(
                "P(Attack)", format="%.4f"
            ),
            "class_probability": st.column_config.NumberColumn(
                "P(Class)", format="%.4f"
            ),
        },
    )


def render_attack_details(rows: list[UiRow]) -> None:
    attacks = [row for row in rows if row.verdict == "Attack"]
    if not attacks:
        st.caption("No attack rows yet.")
        return

    labels = {
        f"{row.flow_id}  |  {row.predicted_class}  |  {row.row_key}": row
        for row in attacks
    }
    selected = st.selectbox("Attack detail", list(labels), key="attack_detail")
    row = labels[selected]

    left, middle, right = st.columns(3)
    left.metric("P(Attack)", f"{row.attack_probability:.4f}")
    middle.metric("Predicted class", row.predicted_class or "")
    right.metric(
        "P(Class)",
        "" if row.class_probability is None else f"{row.class_probability:.4f}",
    )

    st.markdown("**Explanation**")
    if row.pending:
        st.info("explaining...")
    elif row.explanation:
        st.write(row.explanation)
        if row.explanation_source == "fallback":
            st.warning(
                "LLM unavailable; this is the evidence-based fallback. "
                + (row.explanation_error or "")
            )
    else:
        st.warning("No explanation available.")

    if row.evidence is None:
        return
    st.markdown("**Detector top-5 (toward Attack)**")
    st.dataframe(
        pd.DataFrame(row.evidence.detector_top5),
        hide_index=True,
        width="stretch",
    )
    st.markdown("**Classifier top-5 (predicted class)**")
    st.dataframe(
        pd.DataFrame(row.evidence.classifier_top5),
        hide_index=True,
        width="stretch",
    )
