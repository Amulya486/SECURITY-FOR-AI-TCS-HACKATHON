"""
app.py — Prompt & Document Safety Gateway

A Streamlit security gateway that intercepts user prompts and attached documents
(PDF, Word, Excel, Code, TXT, CSV, etc.), scans them for sensitive data, PII,
API keys, credentials, and hidden indirect prompt injections / data exfiltration,
calculates exposure and harm scores, and decides whether to forward, warn, or block.

Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
from typing import Optional, Dict

from detector import (
    analyze_combined,
    check_response,
    LABELS,
    SAMPLE_PROMPTS,
    CombinedAnalysisResult,
    AnalysisResult,
)
from doc_parser import extract_text_from_file, ExtractedDocument
from mock_llm import get_response, get_model_names, get_model_info
import stats

# ── Page config ─────────────────────────────────────────────────────
st.set_page_config(
    page_title="Prompt & Document Safety Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ──────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* Hero header */
    .hero {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(255,255,255,0.06);
    }
    .hero h1 {
        background: linear-gradient(90deg, #00d2ff, #7b2ff7, #ff6a88);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.3rem;
        font-weight: 800;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .hero p {
        color: #a0a0b8;
        font-size: 1.05rem;
        margin: 0.5rem 0 0 0;
    }

    /* Score cards */
    .score-card {
        padding: 1.2rem 1.5rem;
        border-radius: 14px;
        text-align: center;
        border: 1px solid rgba(255,255,255,0.08);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .score-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    }
    .score-card .value {
        font-size: 2.2rem;
        font-weight: 800;
        line-height: 1.1;
    }
    .score-card .label {
        font-size: 0.85rem;
        opacity: 0.7;
        margin-top: 0.3rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Level badges */
    .level-safe, .level-low {
        background: linear-gradient(135deg, #0d3320, #064e2b);
        border-color: #10b981 !important;
    }
    .level-safe .value, .level-low .value { color: #34d399; }

    .level-medium {
        background: linear-gradient(135deg, #3d2e08, #4a3510);
        border-color: #f59e0b !important;
    }
    .level-medium .value { color: #fbbf24; }

    .level-high {
        background: linear-gradient(135deg, #3b0d0d, #4c1111);
        border-color: #ef4444 !important;
    }
    .level-high .value { color: #f87171; }

    /* Source breakdown mini card */
    .breakdown-box {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 0.9rem 1.1rem;
        margin-top: 0.5rem;
        margin-bottom: 0.5rem;
    }
    .breakdown-box .title {
        font-size: 0.95rem;
        font-weight: 700;
        color: #e2e8f0;
        margin-bottom: 0.3rem;
    }

    /* Finding cards */
    .finding-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.7rem;
        transition: border-color 0.2s;
    }
    .finding-card:hover {
        border-color: rgba(123,47,247,0.4);
    }
    .finding-source-tag {
        display: inline-block;
        background: rgba(123,47,247,0.25);
        color: #c4b5fd;
        font-size: 0.75rem;
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        margin-right: 0.5rem;
    }
    .finding-title {
        font-weight: 700;
        font-size: 0.95rem;
        margin-bottom: 0.3rem;
    }
    .finding-match {
        font-family: 'Courier New', monospace;
        background: rgba(239,68,68,0.15);
        color: #fca5a5;
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.85rem;
        word-break: break-all;
    }
    .finding-risk {
        color: #a0a0b8;
        font-size: 0.82rem;
        margin-top: 0.4rem;
        line-height: 1.5;
    }
    .finding-tip {
        color: #34d399;
        font-size: 0.82rem;
        margin-top: 0.3rem;
    }

    /* Stats grid */
    .stat-box {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
    }
    .stat-box .stat-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #c4b5fd;
    }
    .stat-box .stat-label {
        font-size: 0.78rem;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 0.2rem;
    }

    /* Flow diagram */
    .flow-step {
        display: inline-block;
        background: rgba(123,47,247,0.12);
        border: 1px solid rgba(123,47,247,0.3);
        border-radius: 8px;
        padding: 0.4rem 0.8rem;
        margin: 0.2rem;
        font-size: 0.82rem;
        color: #c4b5fd;
    }
    .flow-arrow {
        display: inline-block;
        color: #6b7280;
        margin: 0 0.2rem;
        font-size: 0.9rem;
    }

    /* Attached doc banner */
    .doc-banner {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(147, 51, 234, 0.15));
        border: 1px solid rgba(147, 51, 234, 0.3);
        border-radius: 10px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Masked prompt box */
    .masked-box {
        background: rgba(251,191,36,0.08);
        border: 1px solid rgba(251,191,36,0.3);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        font-family: 'Courier New', monospace;
        font-size: 0.9rem;
        line-height: 1.6;
        color: #fde68a;
        word-break: break-word;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)


# ── Session state init ──────────────────────────────────────────────
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pending_result" not in st.session_state:
    st.session_state.pending_result = None
if "pending_safe" not in st.session_state:
    st.session_state.pending_safe = None
if "pending_high_redact" not in st.session_state:
    st.session_state.pending_high_redact = None
if "uploaded_doc" not in st.session_state:
    st.session_state.uploaded_doc = None
if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0


# ── Sidebar ─────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    st.divider()

    # Model selector
    model_names = get_model_names()
    selected_model = st.selectbox(
        "🤖 Default LLM Model",
        model_names,
        help="Choose an LLM model for simulated responses.",
    )
    model_info = get_model_info(selected_model)
    st.caption(f"{model_info['icon']} {model_info['description']}")

    st.divider()

    # Sample prompts
    st.markdown("### 🧪 Sample Prompts")
    st.caption("Click to load a test prompt into the chat input.")
    for label, prompt_text in SAMPLE_PROMPTS.items():
        if st.button(label, key=f"sample_{label}", use_container_width=True):
            st.session_state["_loaded_sample"] = prompt_text

    st.divider()

    # Reset
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.session_state.pending_result = None
            st.session_state.pending_safe = None
            st.session_state.pending_high_redact = None
            st.session_state.uploaded_doc = None
            st.session_state.uploader_key += 1
            st.rerun()
    with col2:
        if st.button("📊 Reset Stats", use_container_width=True):
            stats.reset()
            st.rerun()

    st.divider()

    # Limitations disclaimer
    st.markdown("### ⚠️ Honest Limitations")
    st.caption(
        "• Harm score is an estimate based on severity weights, not measured real-world loss.\n"
        "• Documents (PDF, DOCX, XLSX, TXT) are parsed and scanned for PII, secrets, and indirect prompt injection.\n"
        "• Steganography check detects invisible zero-width unicode characters.\n"
        "• Mock LLM responses are simulated — connect real API keys in production."
    )

    st.divider()

    st.markdown("### 📏 Decision Thresholds")
    st.markdown(
        "| Score | Decision |\n"
        "|---|---|\n"
        "| **0** | 🟢 Safe — Choose LLM to route to |\n"
        "| **1–34** | 🟡 Ask user permission (Original/Masked) |\n"
        "| **35+** | 🔴 Blocked — cannot send to any LLM |"
    )


# ── Hero header ─────────────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <h1>🛡️ Prompt & Document Safety Gateway</h1>
    <p>Intercepts <b>Prompts & Attached Files (PDF, Word, Excel, Code)</b> before reaching the LLM. Scans for sensitive data, PII, API keys, credentials, and <b>indirect document prompt injections</b>.</p>
</div>
""", unsafe_allow_html=True)

# Flow diagram
st.markdown("""
<div style="text-align:center; margin-bottom:1.5rem;">
    <span class="flow-step">📝 Prompt / 📄 Document</span>
    <span class="flow-arrow">→</span>
    <span class="flow-step">🔍 Extract & Normalize</span>
    <span class="flow-arrow">→</span>
    <span class="flow-step">🎯 Detect Secrets & Injections</span>
    <span class="flow-arrow">→</span>
    <span class="flow-step">📊 Multi-Source Scoring</span>
    <span class="flow-arrow">→</span>
    <span class="flow-step">⚖️ Decide & Route</span>
</div>
""", unsafe_allow_html=True)


# Helper: build a markdown summary for chat history
def _build_report_md(res: CombinedAnalysisResult) -> str:
    if not res.all_findings:
        return "🛡️ **Security Scan:** 🟢 SAFE (0 items detected • 0/100)"
    
    counts = {}
    for f in res.all_findings:
        counts[f.label] = counts.get(f.label, 0) + 1
    summary = ", ".join(f"{c}x {lbl}" for lbl, c in counts.items())
    
    level_emoji = {"safe": "🟢", "low": "🟢", "medium": "🟡", "high": "🔴"}.get(res.combined_level, "🟢")
    return f"🛡️ **Security Scan:** {level_emoji} **{res.combined_harm_score}/100 ({res.combined_level.upper()})** — **{res.total_findings_count} item(s) detected** ({summary})"


# ── Tabs ────────────────────────────────────────────────────────────
tab_chat, tab_stats = st.tabs(["💬 Chat & Document Analysis", "📊 Session Statistics"])


# ═══════════════════════════════════════════════════════════════════
#   TAB 1: Chat & Document Analysis
# ═══════════════════════════════════════════════════════════════════
with tab_chat:

    # Render existing chat history
    for entry in st.session_state.chat_history:
        role = entry["role"]
        content = entry["content"]
        if role == "user":
            with st.chat_message("user", avatar="👤"):
                st.markdown(content)
        elif role == "assistant":
            avatar_icon = entry.get("avatar", "🤖")
            with st.chat_message("assistant", avatar=avatar_icon):
                st.markdown(content)
        elif role == "gateway":
            with st.chat_message("assistant", avatar="🛡️"):
                st.markdown(content)

    # ── Handle pending SAFE (Score 0) LLM redirection ──────────────
    if st.session_state.pending_safe is not None:
        safe_data = st.session_state.pending_safe
        res: CombinedAnalysisResult = safe_data["result"]

        st.success(
            "✅ **Prompt & Attached Files are 100% Safe (Harm Score: 0/100)** — No sensitive data or malicious injections detected.\n\n"
            "🎯 **Select which LLM you want to direct this request to:**"
        )

        all_models = get_model_names()
        mcols = st.columns(len(all_models))
        for idx, m_name in enumerate(all_models):
            m_info = get_model_info(m_name)
            short_name = m_name.replace(" (Mock)", "")
            with mcols[idx]:
                if st.button(f"{m_info['icon']} {short_name}", key=f"route_safe_{m_name}", use_container_width=True, type="primary" if idx == 0 else "secondary"):
                    stats.record(res, "allowed")

                    # Formulate full input prompt for the LLM
                    full_llm_input = res.original_prompt
                    if res.has_doc:
                        full_llm_input = f"{res.original_prompt}\n\n[Attached Document Context ({res.doc_info.get('filename', '')})]:\n{res.original_doc_text}"

                    with st.spinner(f"Getting response from {m_name}…"):
                        llm_response = get_response(full_llm_input, m_name)

                    resp_check = check_response(llm_response)
                    if resp_check.findings:
                        llm_response += "\n\n⚠️ **Gateway Warning:** The LLM response contains sensitive patterns. Review carefully."

                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "avatar": m_info["icon"],
                        "content": f"**[{m_name}]**\n\n{llm_response}"
                    })
                    st.session_state.pending_safe = None
                    st.session_state.uploaded_doc = None
                    st.session_state.uploader_key += 1
                    st.rerun()

        if st.button("❌ Cancel", key="cancel_safe_btn", use_container_width=True):
            st.session_state.pending_safe = None
            st.session_state.uploaded_doc = None
            st.session_state.uploader_key += 1
            st.rerun()

    # ── Handle pending Medium-risk confirmation ─────────────────────
    if st.session_state.pending_result is not None:
        res: CombinedAnalysisResult = st.session_state.pending_result

        counts = {}
        for f in res.all_findings:
            counts[f.label] = counts.get(f.label, 0) + 1
        summary_txt = ", ".join(f"{c} {lbl}" for lbl, c in counts.items())

        st.warning(
            f"⚠️ **Sensitive data detected:** **{res.total_findings_count} item(s)** ({summary_txt}) — "
            f"Harm Score: **{res.combined_harm_score}/100**.\n\n"
            "Do you want to send the original or the sanitized (masked) version to the LLM?"
        )

        # Show details only if user opens expander
        with st.expander("🔎 View Masked Preview & Details (Optional)", expanded=False):
            if res.has_prompt:
                st.markdown("**Masked Prompt:**")
                st.markdown(f'<div class="masked-box">{res.masked_prompt}</div>', unsafe_allow_html=True)
            if res.has_doc:
                st.markdown(f"**Masked Document ({res.doc_info.get('filename', 'document')}):**")
                preview_doc = res.masked_doc_text if len(res.masked_doc_text) <= 800 else res.masked_doc_text[:800] + "\n… [truncated]"
                st.markdown(f'<div class="masked-box">{preview_doc}</div>', unsafe_allow_html=True)

            st.markdown("---")
            for f in res.all_findings:
                display_match = f.matched_text if len(f.matched_text) <= 60 else f.matched_text[:57] + "…"
                st.markdown(f"- *[{f.source}]* **{f.label}**: `{display_match}`")

        pcol1, pcol2, pcol3 = st.columns(3)
        with pcol1:
            if st.button("✅ Yes, Send Original", use_container_width=True, type="primary"):
                stats.record(res, "warned")
                full_input = res.original_prompt
                if res.has_doc:
                    full_input = f"{res.original_prompt}\n\n[Document: {res.doc_info.get('filename')}]:\n{res.original_doc_text}"

                st.session_state.chat_history.append({
                    "role": "gateway",
                    "content": "⚠️ **User Approved Original:** Forwarding unmasked prompt & attached document to LLM."
                })
                with st.spinner(f"Sending to {selected_model}…"):
                    llm_response = get_response(full_input, selected_model)

                resp_check = check_response(llm_response)
                if resp_check.findings:
                    llm_response += "\n\n⚠️ **Gateway Warning:** The LLM response contains sensitive patterns. Review carefully."

                st.session_state.chat_history.append({"role": "assistant", "avatar": get_model_info(selected_model)["icon"], "content": llm_response})
                st.session_state.pending_result = None
                st.session_state.uploaded_doc = None
                st.session_state.uploader_key += 1
                st.rerun()

        with pcol2:
            if st.button("📝 Send Masked Version", use_container_width=True):
                stats.record(res, "warned")
                full_masked = res.masked_prompt
                if res.has_doc:
                    full_masked = f"{res.masked_prompt}\n\n[Document (Masked): {res.doc_info.get('filename')}]:\n{res.masked_doc_text}"

                st.session_state.chat_history.append({
                    "role": "gateway",
                    "content": "🔒 **Masked Version Accepted:** Sensitive fields have been redacted. Forwarding sanitized prompt & document to LLM."
                })
                with st.spinner(f"Sending masked payload to {selected_model}…"):
                    llm_response = get_response(full_masked, selected_model)

                resp_check = check_response(llm_response)
                if resp_check.findings:
                    llm_response += "\n\n⚠️ **Gateway Warning:** The LLM response contains sensitive patterns. Review carefully."

                st.session_state.chat_history.append({"role": "assistant", "avatar": get_model_info(selected_model)["icon"], "content": llm_response})
                st.session_state.pending_result = None
                st.session_state.uploaded_doc = None
                st.session_state.uploader_key += 1
                st.rerun()

        with pcol3:
            if st.button("❌ Cancel", use_container_width=True):
                stats.record(res, "warned")
                st.session_state.chat_history.append({
                    "role": "gateway",
                    "content": "🚫 Prompt/document processing cancelled by user after review."
                })
                st.session_state.pending_result = None
                st.session_state.uploaded_doc = None
                st.session_state.uploader_key += 1
                st.rerun()

    # ── Handle pending High-risk Sensitive Data (Sanitization Flow) ─
    if st.session_state.pending_high_redact is not None:
        res: CombinedAnalysisResult = st.session_state.pending_high_redact

        counts = {}
        for f in res.all_findings:
            counts[f.label] = counts.get(f.label, 0) + 1
        summary_txt = ", ".join(f"{c} {lbl}" for lbl, c in counts.items())

        st.error(
            f"🚫 **Direct Transmission Blocked** — **{res.total_findings_count} sensitive item(s) detected** ({summary_txt}) • Harm Score: **{res.combined_harm_score}/100**\n\n"
            "Raw unmasked personal data cannot be sent directly. Click an LLM below to **send the Sanitized (Masked) Version** safely."
        )

        with st.expander("🔎 View Sanitized / Masked Payload & Redacted Fields", expanded=False):
            if res.has_prompt:
                st.markdown("**Masked Prompt:**")
                st.markdown(f'<div class="masked-box">{res.masked_prompt}</div>', unsafe_allow_html=True)
            if res.has_doc:
                st.markdown(f"**Masked Document ({res.doc_info.get('filename', 'document')}):**")
                preview_doc = res.masked_doc_text if len(res.masked_doc_text) <= 800 else res.masked_doc_text[:800] + "\n… [truncated]"
                st.markdown(f'<div class="masked-box">{preview_doc}</div>', unsafe_allow_html=True)

            st.markdown("---")
            for f in res.all_findings:
                display_match = f.matched_text if len(f.matched_text) <= 60 else f.matched_text[:57] + "…"
                st.markdown(f"- *[{f.source}]* **{f.label}**: `{display_match}`")

        st.markdown("##### 🎯 Select LLM to Process Sanitized (Masked) Document:")
        all_models = get_model_names()
        mcols = st.columns(len(all_models))
        for idx, m_name in enumerate(all_models):
            m_info = get_model_info(m_name)
            short_name = m_name.replace(" (Mock)", "")
            with mcols[idx]:
                if st.button(f"{m_info['icon']} {short_name}", key=f"route_high_masked_{m_name}", use_container_width=True, type="primary" if idx == 0 else "secondary"):
                    stats.record(res, "warned")
                    full_masked = res.masked_prompt
                    if res.has_doc:
                        full_masked = f"{res.masked_prompt}\n\n[Document (Masked): {res.doc_info.get('filename')}]:\n{res.masked_doc_text}"

                    st.session_state.chat_history.append({
                        "role": "gateway",
                        "content": f"🔒 **Masked Version Forwarded to {m_name}:** Sensitive PII & credentials have been redacted. Processing query from sanitized document."
                    })
                    with st.spinner(f"Sending sanitized payload to {m_name}…"):
                        llm_response = get_response(full_masked, m_name)

                    resp_check = check_response(llm_response)
                    if resp_check.findings:
                        llm_response += "\n\n⚠️ **Gateway Warning:** The LLM response contains sensitive patterns. Review carefully."

                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "avatar": m_info["icon"],
                        "content": f"**[{m_name}]**\n\n{llm_response}"
                    })
                    st.session_state.pending_high_redact = None
                    st.session_state.uploaded_doc = None
                    st.session_state.uploader_key += 1
                    st.rerun()

        if st.button("❌ Cancel Request", key="cancel_high_redact_btn", use_container_width=True):
            stats.record(res, "blocked")
            st.session_state.chat_history.append({
                "role": "gateway",
                "content": f"🚫 **CANCELLED** — Score {res.combined_harm_score}/100. Request cancelled by user after review."
            })
            st.session_state.pending_high_redact = None
            st.session_state.uploaded_doc = None
            st.session_state.uploader_key += 1
            st.rerun()

    # ── File Attachment Section ─────────────────────────────────────
    st.markdown("#### 📎 Document & File Attachment Scanner")
    with st.expander("📂 Upload / Attach Document (PDF, Word, Excel, TXT, Code)", expanded=False):
        uploaded_file = st.file_uploader(
            "Attach a document to scan for sensitive data, credentials, and indirect prompt injection:",
            type=["pdf", "docx", "xlsx", "xls", "txt", "md", "csv", "json", "py", "js", "html", "yaml", "yml", "log", "sql", "env"],
            key=f"file_attachment_input_{st.session_state.uploader_key}"
        )
        if uploaded_file is not None:
            # Parse document
            parsed_doc = extract_text_from_file(uploaded_file.getvalue(), uploaded_file.name)
            st.session_state.uploaded_doc = parsed_doc

            if not parsed_doc.is_supported:
                st.error(f"❌ {parsed_doc.error_msg or 'Could not extract text from document.'}")
            else:
                kb_size = round(parsed_doc.file_size_bytes / 1024, 1)
                st.success(f"📄 **{parsed_doc.filename}** loaded ({parsed_doc.file_type}, {kb_size} KB, {parsed_doc.char_count:,} characters)")

                if parsed_doc.hidden_char_count > 0:
                    st.warning(f"⚠️ **Steganography Alert:** Found {parsed_doc.hidden_char_count} hidden zero-width unicode characters in this file.")

                with st.expander("👁️ View extracted document text preview", expanded=False):
                    st.text(parsed_doc.text[:1500] + ("\n… [truncated]" if len(parsed_doc.text) > 1500 else ""))

    # Display indicator if document is currently attached
    if st.session_state.uploaded_doc and st.session_state.uploaded_doc.is_supported:
        doc = st.session_state.uploaded_doc
        doc_col1, doc_col2 = st.columns([4, 1])
        with doc_col1:
            st.info(f"📎 **Attached File Active:** `{doc.filename}` ({round(doc.file_size_bytes/1024, 1)} KB). Type a prompt below or click 'Analyze Document Only'.")
        with doc_col2:
            if st.button("🔍 Analyze Doc Only", key="analyze_doc_btn", use_container_width=True):
                st.session_state["_trigger_doc_only"] = True
                st.rerun()

    # ── Chat input ──────────────────────────────────────────────────
    loaded = st.session_state.pop("_loaded_sample", None)
    trigger_doc_only = st.session_state.pop("_trigger_doc_only", False)
    user_input = st.chat_input("Type your prompt here (with or without attached file)…", key="main_input")

    prompt_to_process = loaded or user_input
    doc_to_process: Optional[ExtractedDocument] = st.session_state.uploaded_doc if (st.session_state.uploaded_doc and st.session_state.uploaded_doc.is_supported) else None

    # Trigger analysis if user submitted a prompt, loaded a sample, or clicked analyze doc
    if (prompt_to_process or (trigger_doc_only and doc_to_process)) and st.session_state.pending_result is None and st.session_state.pending_safe is None and st.session_state.pending_high_redact is None:

        current_prompt = prompt_to_process or ("" if trigger_doc_only else "")

        # Display user message
        with st.chat_message("user", avatar="👤"):
            if current_prompt:
                st.markdown(current_prompt)
            if doc_to_process:
                st.caption(f"📄 *Attached file: `{doc_to_process.filename}` ({round(doc_to_process.file_size_bytes/1024, 1)} KB)*")

        # ── COMBINED MULTI-SOURCE ANALYSIS ───────────────────────────
        doc_text = doc_to_process.text if doc_to_process else None
        doc_info = {
            "filename": doc_to_process.filename,
            "file_type": doc_to_process.file_type,
            "file_size_bytes": doc_to_process.file_size_bytes,
            "hidden_char_count": doc_to_process.hidden_char_count,
            "hidden_char_types": doc_to_process.hidden_char_types,
        } if doc_to_process else None

        result: CombinedAnalysisResult = analyze_combined(
            prompt=current_prompt,
            doc_text=doc_text,
            doc_info=doc_info,
        )

        # Clear the uploaded doc immediately after analysis so it doesn't
        # carry over to the next prompt submission.
        st.session_state.uploaded_doc = None
        st.session_state.uploader_key += 1  # Reset file uploader widget

        # ── Security Report ──────────────────────────────────────────
        with st.chat_message("assistant", avatar="🛡️"):
            st.markdown("### 🔒 Security Analysis Report")

            # Score cards row
            c1, c2, c3, c4 = st.columns(4)
            level_key = "safe" if result.combined_level in ("safe", "low") else result.combined_level
            level_class = f"level-{level_key}"

            with c1:
                st.markdown(f"""
                <div class="score-card {level_class}">
                    <div class="value">{result.combined_harm_score}/100</div>
                    <div class="label">Overall Harm Score</div>
                </div>
                """, unsafe_allow_html=True)
            with c2:
                level_emoji = {"safe": "🟢", "low": "🟢", "medium": "🟡", "high": "🔴"}.get(result.combined_level, "🟢")
                level_display = "SAFE" if result.combined_level in ("safe", "low") else result.combined_level.upper()
                st.markdown(f"""
                <div class="score-card {level_class}">
                    <div class="value">{level_emoji} {level_display}</div>
                    <div class="label">Overall Risk Level</div>
                </div>
                """, unsafe_allow_html=True)
            with c3:
                st.markdown(f"""
                <div class="score-card {level_class}">
                    <div class="value">{result.total_findings_count}</div>
                    <div class="label">Items Found</div>
                </div>
                """, unsafe_allow_html=True)
            with c4:
                st.markdown(f"""
                <div class="score-card {level_class}">
                    <div class="value">{result.combined_exposure_pct}%</div>
                    <div class="label">Exposure</div>
                </div>
                """, unsafe_allow_html=True)

            # Multi-source Breakdown if BOTH Prompt and Document exist
            if result.has_prompt and result.has_doc and result.prompt_result and result.doc_result:
                st.markdown("#### 📊 Multi-Source Breakdown")
                bcol1, bcol2 = st.columns(2)
                with bcol1:
                    p_res = result.prompt_result
                    p_emoji = {"safe": "🟢", "medium": "🟡", "high": "🔴"}.get(p_res.level, "🟢")
                    st.markdown(f"""
                    <div class="breakdown-box">
                        <div class="title">📝 Text Prompt</div>
                        <div>Harm Score: <b>{p_res.harm_score}/100</b> ({p_emoji} {p_res.level.upper()})</div>
                        <div>Findings: <b>{len(p_res.findings)} item(s)</b> • Exposure: <b>{p_res.exposure_pct}%</b></div>
                    </div>
                    """, unsafe_allow_html=True)
                with bcol2:
                    d_res = result.doc_result
                    d_emoji = {"safe": "🟢", "medium": "🟡", "high": "🔴"}.get(d_res.level, "🟢")
                    st.markdown(f"""
                    <div class="breakdown-box">
                        <div class="title">📄 Document: {result.doc_info.get('filename')}</div>
                        <div>Harm Score: <b>{d_res.harm_score}/100</b> ({d_emoji} {d_res.level.upper()})</div>
                        <div>Findings: <b>{len(d_res.findings)} item(s)</b> • Steganography: <b>{result.doc_info.get('hidden_char_count', 0)} char(s)</b></div>
                    </div>
                    """, unsafe_allow_html=True)

            # Summary of detected items count
            if result.all_findings:
                counts = {}
                for f in result.all_findings:
                    counts[f.label] = counts.get(f.label, 0) + 1
                summary_items = ", ".join(f"**{c}x {lbl}**" for lbl, c in counts.items())
                st.markdown(f"🛡️ **Detected Items:** {summary_items}")

                with st.expander("🔎 View Technical Details (Optional)", expanded=False):
                    for f in result.all_findings:
                        display_match = f.matched_text if len(f.matched_text) <= 65 else f.matched_text[:62] + "…"
                        st.markdown(f"- *[{f.source}]* **{f.label}**: `{display_match}` (weight: {f.weight})")
            else:
                st.success("✅ No sensitive data or malicious injections detected (0 items found).")

        # Save user message & security report to history
        user_history_entry = current_prompt
        if doc_to_process:
            user_history_entry += f"\n*(Attached: {doc_to_process.filename})*"
        st.session_state.chat_history.append({"role": "user", "content": user_history_entry})

        report_md = _build_report_md(result)
        st.session_state.chat_history.append({"role": "gateway", "content": report_md})

        # ── Decision Branches ─────────────────────────────────────────

        # 🟢 SAFE (score = 0) -> Ask which LLM to direct to
        if result.combined_level in ("safe", "low"):
            st.session_state.pending_safe = {"result": result}
            st.rerun()

        # 🟡 MEDIUM (score 1–34) -> Ask user confirmation
        elif result.combined_level == "medium":
            st.session_state.pending_result = result
            st.rerun()

        # 🔴 HIGH (score 35+) -> Blocked / Sanitization
        elif result.combined_level == "high":
            # Check if high score is caused by active security attacks vs sensitive data/PII
            is_active_attack = any(
                f.category in {"injection", "indirect_injection", "exfiltration", "malicious_intent", "hidden_payload"}
                for f in result.all_findings
            ) or (result.doc_info and result.doc_info.get("hidden_char_count", 0) > 0)

            if is_active_attack:
                # Active malicious attack -> Hard Block
                stats.record(result, "blocked")

                with st.chat_message("assistant", avatar="🛡️"):
                    st.error(
                        f"🚫 **BLOCKED: Exploit Payload Detected** — Harm Score **{result.combined_harm_score}/100**\n\n"
                        f"**{result.total_findings_count} malicious trigger(s) detected.** This request violates security policy and cannot be sent to any LLM."
                    )

                st.session_state.chat_history.append({
                    "role": "gateway",
                    "content": f"🚫 **HARD BLOCKED (Security Attack)** — Score {result.combined_harm_score}/100. Request contained active exploit payloads."
                })
                st.session_state.uploaded_doc = None
                st.session_state.uploader_key += 1
            else:
                # High-risk sensitive data (PII / credentials) -> Provide safe masked forwarding option
                st.session_state.pending_high_redact = result
                st.rerun()


# ═══════════════════════════════════════════════════════════════════
#   TAB 2: Session Statistics
# ═══════════════════════════════════════════════════════════════════
with tab_stats:
    st.markdown("### 📊 Session Statistics")
    st.caption("Real-time metrics across all prompts and documents checked in this session.")

    total = stats.get_total()

    if total == 0:
        st.info("No prompts or documents analyzed yet. Start chatting or upload a file to see statistics here!")
    else:
        # Top-level KPIs
        k1, k2, k3, k4, k5 = st.columns(5)
        counts = stats.get_counts()
        pcts = stats.get_percentages()

        with k1:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            """, unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value" style="color:#34d399;">{counts['allowed']}</div>
                <div class="stat-label">Allowed ({pcts['allowed']}%)</div>
            </div>
            """, unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value" style="color:#fbbf24;">{counts['warned']}</div>
                <div class="stat-label">Warned ({pcts['warned']}%)</div>
            </div>
            """, unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value" style="color:#f87171;">{counts['blocked']}</div>
                <div class="stat-label">Blocked ({pcts['blocked']}%)</div>
            </div>
            """, unsafe_allow_html=True)
        with k5:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value">{stats.get_avg_harm_score()}</div>
                <div class="stat-label">Avg Harm Score</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("")

        # Second row
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value">{stats.get_total_items_caught()}</div>
                <div class="stat-label">Total Sensitive Items Caught</div>
            </div>
            """, unsafe_allow_html=True)
        with s2:
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value" style="color:#60a5fa;">{stats.get_doc_scans_count()}</div>
                <div class="stat-label">Documents Scanned</div>
            </div>
            """, unsafe_allow_html=True)
        with s3:
            cat_counts = stats.get_category_counts()
            top_cat = max(cat_counts, key=cat_counts.get) if cat_counts else "None"
            st.markdown(f"""
            <div class="stat-box">
                <div class="stat-value" style="font-size:1.1rem;">🏷️ {LABELS.get(top_cat, top_cat)}</div>
                <div class="stat-label">Top Threat Category</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("")
        st.divider()

        # Bar chart by category
        st.markdown("#### 📈 Findings by Threat Category")
        if cat_counts:
            chart_data = {LABELS.get(k, k): v for k, v in cat_counts.items()}
            df = pd.DataFrame({"Category": list(chart_data.keys()), "Count": list(chart_data.values())})
            df = df.set_index("Category").sort_values("Count", ascending=False)
            st.bar_chart(df, color="#7b2ff7")
        else:
            st.caption("No findings yet.")

        st.divider()

        # History table
        st.markdown("#### 📜 Scan & Routing History")
        history = stats.get_history()
        if history:
            hist_df = pd.DataFrame(history)
            hist_df.columns = ["Payload Preview", "Harm Score", "Level", "Decision", "Findings", "Exposure %"]
            st.dataframe(
                hist_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Harm Score": st.column_config.ProgressColumn(
                        "Harm Score",
                        min_value=0,
                        max_value=100,
                        format="%d",
                    ),
                    "Level": st.column_config.TextColumn("Level"),
                    "Decision": st.column_config.TextColumn("Decision"),
                },
            )
