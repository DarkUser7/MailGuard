"""Reusable UI components for MailGuard AI Streamlit interface."""

import streamlit as st


def render_risk_badge(risk_level: str, risk_score: int):
    """Render a color-coded risk badge."""
    css_class = f"risk-{risk_level.lower()}"
    st.markdown(
        f'<div class="{css_class}">⚠️ Overall Threat Level: {risk_level} (Score: {risk_score}/100)</div>',
        unsafe_allow_html=True
    )


def render_prediction_badge(prediction: str, spam_prob: float):
    """Render prediction result with clear visual cues."""
    if prediction == 'spam':
        st.error(f"🚨 Classification: **SPAM / PHISHING** (Model Confidence: {spam_prob:.2%})")
    else:
        st.success(f"✅ Classification: **HAM (Legitimate Email)** (Model Confidence: {1-spam_prob:.2%})")


def render_indicator_card(category: str, count: int, items: list, emoji: str):
    """Render a clean, modern self-contained indicator card without layout breaks."""
    has_issues = count > 0
    bg_badge = "rgba(239, 68, 68, 0.15)" if has_issues else "rgba(34, 197, 94, 0.12)"
    border_badge = "rgba(239, 68, 68, 0.4)" if has_issues else "rgba(34, 197, 94, 0.3)"
    text_badge = "#f87171" if has_issues else "#4ade80"
    badge_label = f"{count} detected" if has_issues else "None detected"
    status_icon = "⚠️" if has_issues else "✅"

    items_html = ""
    if items and has_issues:
        preview_list = []
        for it in items[:3]:
            if isinstance(it, dict):
                preview_list.append(it.get('url', str(it)))
            else:
                preview_list.append(str(it))
        preview_text = ", ".join(preview_list)
        if len(items) > 3:
            preview_text += "..."
        items_html = f'<div style="font-size: 0.76rem; color: #94a3b8; margin-top: 8px; line-height: 1.4; word-break: break-word;">Items: {preview_text}</div>'

    card_html = f"""
    <div style="background: #0d1527; border: 1px solid #1e2d48; border-radius: 12px; padding: 1.1rem; height: 100%; min-height: 90px; box-sizing: border-box;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
            <span style="font-size: 0.92rem; font-weight: 700; color: #f1f5f9;">{emoji} {category}</span>
            <span style="font-size: 0.72rem; font-weight: 700; color: {text_badge}; background: {bg_badge}; border: 1px solid {border_badge}; padding: 2px 8px; border-radius: 9999px;">{status_icon} {badge_label}</span>
        </div>
        {items_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_virustotal_card(vt_analysis: dict):
    """Render VirusTotal URL intelligence analysis section."""
    if not vt_analysis or vt_analysis.get('urls_detected', 0) == 0:
        st.info("ℹ️ No URLs detected in this email content.")
        return

    st.markdown("##### 🔗 VirusTotal URL Reputation Intelligence")
    
    # Summary Metrics Row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        st.metric("URLs Detected", vt_analysis.get('urls_detected', 0))
    with m_col2:
        st.metric("URLs Analyzed", vt_analysis.get('urls_analyzed', 0))
    with m_col3:
        m_cnt = vt_analysis.get('malicious_count', 0)
        st.metric("🔴 Malicious", m_cnt)
    with m_col4:
        s_cnt = vt_analysis.get('suspicious_count', 0)
        st.metric("🟠 Suspicious", s_cnt)
    with m_col5:
        c_cnt = vt_analysis.get('clean_count', 0)
        st.metric("🟢 Clean Detections", c_cnt)

    # Privacy / Disclaimer Notice
    st.caption("⚠️ **URL Privacy Notice**: Extracted URLs are queried against VirusTotal threat database. Do not submit sensitive/confidential links.")

    # Detailed URL Inspection Cards
    results = vt_analysis.get('results', [])
    for idx, item in enumerate(results, start=1):
        url = item.get('url', 'Unknown URL')
        classification = item.get('classification', item.get('status', 'Unknown'))
        mal = item.get('malicious', 0)
        susp = item.get('suspicious', 0)
        harm = item.get('harmless', 0)
        undet = item.get('undetected', 0)
        err = item.get('error_message')
        permalink = item.get('permalink')

        expander_title = f"{classification} — {url}"
        with st.expander(expander_title, expanded=(mal > 0 or susp > 0)):
            if err:
                st.warning(f"⚠️ {err}")
            else:
                col_e1, col_e2, col_e3, col_e4, col_e5 = st.columns(5)
                with col_e1:
                    st.metric("Malicious", mal)
                with col_e2:
                    st.metric("Suspicious", susp)
                with col_e3:
                    st.metric("Harmless", harm)
                with col_e4:
                    st.metric("Undetected", undet)
                with col_e5:
                    st.metric("Reputation", item.get('reputation', 0))

                if mal > 0:
                    st.error(f"🚨 **Threat Warning**: {mal} independent antivirus/security vendors flagged this link as malicious!")
                elif susp > 0:
                    st.warning(f"🟠 **Suspicious Reputation**: {susp} security vendors flagged suspicious behavior.")
                elif harm > 0:
                    st.success("🟢 **VirusTotal Verdict**: No malicious detections reported by security vendors.")
                else:
                    st.info("⚪ **VirusTotal Verdict**: Undetected / New unranked URL.")

                if permalink:
                    st.markdown(f"[🔗 View Detailed Analysis on VirusTotal GUI]({permalink})")


def render_header_security_card(header_analysis: dict):
    """Render email header authentication and spoofing analysis."""
    if not header_analysis or not header_analysis.get('has_headers', False):
        st.info("ℹ️ No email headers provided. Only body content was analyzed.")
        return

    auth = header_analysis.get('auth_results', {})
    sender = header_analysis.get('sender_info', {})
    spoofing = header_analysis.get('spoofing_detected', False)

    col1, col2, col3 = st.columns(3)
    with col1:
        spf = auth.get('spf', 'NONE')
        color = "🟢" if spf == "PASS" else ("🔴" if spf == "FAIL" else "🟡")
        st.metric("SPF Status", f"{color} {spf}")
    with col2:
        dkim = auth.get('dkim', 'NONE')
        color = "🟢" if "PASS" in dkim else ("🔴" if dkim == "FAIL" else "🟡")
        st.metric("DKIM Status", f"{color} {dkim}")
    with col3:
        dmarc = auth.get('dmarc', 'NONE')
        color = "🟢" if dmarc == "PASS" else ("🔴" if dmarc == "FAIL" else "🟡")
        st.metric("DMARC Status", f"{color} {dmarc}")

    if spoofing:
        st.error("🚨 **SPOOFING ALERT**: Sender domain is unauthenticated and fails cryptographic alignment!")
        st.caption(f"From: `{sender.get('from_email')}` ➡️ Return-Path: `{sender.get('return_path')}`")
    else:
        st.success("✅ **Domain & Sender Alignment**: Validated through cryptographic signatures and sender policy.")

    if header_analysis.get('anomalies'):
        with st.expander("🔍 View All Header Security Findings", expanded=False):
            for a in header_analysis['anomalies']:
                st.markdown(f"- ⚠️ {a}")
            if header_analysis.get('origin_ips'):
                st.markdown(f"- 🌐 **Originating IP(s)**: `{', '.join(header_analysis['origin_ips'])}`")
            if header_analysis.get('x_mailer') and header_analysis.get('x_mailer') != 'Not specified':
                st.markdown(f"- ✉️ **Mailer / Client**: `{header_analysis['x_mailer']}`")


def render_confidence_gauge(spam_prob: float, ham_prob: float):
    """Render confidence metrics and progress bar."""
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Spam Probability", f"{spam_prob:.2%}")
    with col2:
        st.metric("Ham Probability", f"{ham_prob:.2%}")
    
    st.progress(spam_prob, text=f"Spam likelihood: {spam_prob:.1%}")
