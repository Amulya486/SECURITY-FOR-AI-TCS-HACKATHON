"""
stats.py — Session statistics tracker.

Stores all metrics in Streamlit's session_state (no database).
Provides computed properties for the statistics panel.
"""

import streamlit as st
from typing import Dict, List, Optional, Union
from detector import AnalysisResult, CombinedAnalysisResult


# ── Session state keys ──────────────────────────────────────────────
_KEY_PREFIX = "psg_stats_"
_TOTAL        = f"{_KEY_PREFIX}total"
_ALLOWED      = f"{_KEY_PREFIX}allowed"
_WARNED       = f"{_KEY_PREFIX}warned"
_BLOCKED      = f"{_KEY_PREFIX}blocked"
_HARM_SCORES  = f"{_KEY_PREFIX}harm_scores"
_CAT_COUNTS   = f"{_KEY_PREFIX}category_counts"
_ITEMS_CAUGHT = f"{_KEY_PREFIX}items_caught"
_HISTORY      = f"{_KEY_PREFIX}history"
_DOC_SCANS    = f"{_KEY_PREFIX}doc_scans"


def _init():
    """Initialize stats keys if they don't exist."""
    defaults = {
        _TOTAL: 0,
        _ALLOWED: 0,
        _WARNED: 0,
        _BLOCKED: 0,
        _HARM_SCORES: [],
        _CAT_COUNTS: {},
        _ITEMS_CAUGHT: 0,
        _HISTORY: [],
        _DOC_SCANS: 0,
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


def record(result: Union[AnalysisResult, CombinedAnalysisResult], decision: str):
    """
    Record one analysis result (either single AnalysisResult or CombinedAnalysisResult).

    Args:
        result: The AnalysisResult or CombinedAnalysisResult
        decision: "allowed" | "warned" | "blocked"
    """
    _init()

    if hasattr(result, "combined_harm_score") or isinstance(result, CombinedAnalysisResult):
        harm_score = getattr(result, "combined_harm_score", 0)
        level = getattr(result, "combined_level", "safe")
        findings_count = getattr(result, "total_findings_count", 0)
        exposure_pct = getattr(result, "combined_exposure_pct", 0.0)
        findings = getattr(result, "all_findings", [])

        preview_parts = []
        if getattr(result, "has_prompt", False) and getattr(result, "original_prompt", ""):
            preview_parts.append(f"Prompt: {result.original_prompt[:50]}")
        if getattr(result, "has_doc", False) and getattr(result, "doc_info", None):
            preview_parts.append(f"Doc: {result.doc_info.get('filename', 'file')}")
            st.session_state[_DOC_SCANS] += 1
        preview = " | ".join(preview_parts) if preview_parts else "Input"

    else:
        harm_score = getattr(result, "harm_score", 0)
        level = getattr(result, "level", "safe")
        findings = getattr(result, "findings", [])
        findings_count = len(findings)
        exposure_pct = getattr(result, "exposure_pct", 0.0)
        orig_p = getattr(result, "original_prompt", "")
        preview = orig_p[:80] + ("…" if len(orig_p) > 80 else "")

    st.session_state[_TOTAL] += 1
    st.session_state[_HARM_SCORES].append(harm_score)
    st.session_state[_ITEMS_CAUGHT] += findings_count

    if decision == "allowed":
        st.session_state[_ALLOWED] += 1
    elif decision == "warned":
        st.session_state[_WARNED] += 1
    elif decision == "blocked":
        st.session_state[_BLOCKED] += 1

    # Merge category counts
    for f in findings:
        current = st.session_state[_CAT_COUNTS]
        current[f.category] = current.get(f.category, 0) + 1

    # Append to history
    st.session_state[_HISTORY].append({
        "prompt_preview": preview,
        "harm_score": harm_score,
        "level": level,
        "decision": decision,
        "findings_count": findings_count,
        "exposure_pct": exposure_pct,
    })


# ── Computed properties ─────────────────────────────────────────────
def get_total() -> int:
    _init()
    return st.session_state[_TOTAL]


def get_counts() -> Dict[str, int]:
    _init()
    return {
        "allowed": st.session_state[_ALLOWED],
        "warned":  st.session_state[_WARNED],
        "blocked": st.session_state[_BLOCKED],
    }


def get_percentages() -> Dict[str, float]:
    _init()
    total = st.session_state[_TOTAL]
    if total == 0:
        return {"allowed": 0.0, "warned": 0.0, "blocked": 0.0}
    return {
        "allowed": round(100 * st.session_state[_ALLOWED] / total, 1),
        "warned":  round(100 * st.session_state[_WARNED]  / total, 1),
        "blocked": round(100 * st.session_state[_BLOCKED] / total, 1),
    }


def get_avg_harm_score() -> float:
    _init()
    scores = st.session_state[_HARM_SCORES]
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 1)


def get_total_items_caught() -> int:
    _init()
    return st.session_state[_ITEMS_CAUGHT]


def get_doc_scans_count() -> int:
    _init()
    return st.session_state[_DOC_SCANS]


def get_category_counts() -> Dict[str, int]:
    _init()
    return dict(st.session_state[_CAT_COUNTS])


def get_history() -> List[Dict]:
    _init()
    return list(st.session_state[_HISTORY])


def reset():
    """Reset all session statistics."""
    st.session_state[_TOTAL] = 0
    st.session_state[_ALLOWED] = 0
    st.session_state[_WARNED] = 0
    st.session_state[_BLOCKED] = 0
    st.session_state[_HARM_SCORES] = []
    st.session_state[_CAT_COUNTS] = {}
    st.session_state[_ITEMS_CAUGHT] = 0
    st.session_state[_HISTORY] = []
    st.session_state[_DOC_SCANS] = 0
