"""About — MailGuard AI architecture."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import streamlit as st
from app.styles import MODERN_DARK_CSS
st.set_page_config(page_title="About — MailGuard AI", page_icon="ℹ️", layout="wide")
st.markdown(MODERN_DARK_CSS, unsafe_allow_html=True)
st.title("ℹ️ About MailGuard AI")
st.markdown("""
**Tagline:** *Detect Spam. Stop Threats. Stay Safe.*

MailGuard AI combines an ML spam classifier (TF-IDF + Logistic Regression), rule-based threat analyzers, a weighted risk engine (0–100), and Gemini-powered explainability.

```text
EMAIL (+ Headers) → Streamlit → ML + Analyzers → Risk Engine → Gemini Report → PDF
```

- ML does **classification** only — never Gemini.
- Gemini provides **human-readable** remediation.
- Header forensics checks **SPF / DKIM / DMARC** and spoofing.
- Offline deterministic fallback when API key is absent.

**Secrets:** `GEMINI_API_KEY` via `st.secrets` or `.env` (never hard-coded).

Built for a college ML / Cybersecurity project — minimal, readable Python.
""")
