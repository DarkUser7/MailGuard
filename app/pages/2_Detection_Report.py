"""Detection Report — view latest scan & export PDF."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import streamlit as st
from app.styles import MODERN_DARK_CSS
from reports.pdf_generator import generate_pdf_report

st.set_page_config(page_title="Detection Report — MailGuard AI", page_icon="📄", layout="wide")
st.markdown(MODERN_DARK_CSS, unsafe_allow_html=True)

st.title("📄 Detection Report")
r = st.session_state.get("analysis_results")
if not r:
    st.info("No scans in this session. Run an analysis from Home or Analyze Email first.")
else:
    st.markdown(f"**Verdict:** `{r['ml_result']['prediction'].upper()}`  |  **Risk:** `{r['risk_result']['risk_score']}/100 ({r['risk_result']['risk_level']})`  |  **Source:** `{r['report_result'].get('source','')}`")
    st.text_area("AI Security Report", value=r.get("report_text",""), height=360)
    try:
        pdf = generate_pdf_report(r)
        st.download_button("📄 Download Security Audit Report (PDF)", data=pdf, file_name="MailGuard_Security_Audit.pdf", mime="application/pdf", type="primary")
    except Exception as e:
        st.warning(str(e))
