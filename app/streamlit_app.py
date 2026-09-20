# -*- coding: utf-8 -*-
"""MailGuard AI — Modern AI-Powered Email Spam & Security Dashboard."""

import os
import sys
import json
import email
from collections import Counter
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from app.styles import MODERN_DARK_CSS
from app.components import (
    render_prediction_badge,
    render_confidence_gauge,
    render_risk_badge,
    render_indicator_card,
    render_virustotal_card,
    render_header_security_card
)

from ml.src.predict import SpamDetector
from analyzer.url_analyzer import URLAnalyzer, extract_urls
from analyzer.keyword_analyzer import KeywordAnalyzer
from analyzer.pattern_analyzer import PatternAnalyzer
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.virustotal import analyze_urls_with_virustotal
from analyzer.risk_engine import RiskEngine
from gemini.report_generator import ReportGenerator
from reports.pdf_generator import generate_pdf_report

# Page Config
st.set_page_config(
    page_title="MailGuard AI - Email Security & Spam Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Custom CSS
st.markdown(MODERN_DARK_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_detector():
    """Load or initialize the ML Spam Detector."""
    try:
        return SpamDetector()
    except Exception:
        return None


detector = get_detector()


@st.cache_data(show_spinner=False, ttl=600)
def get_tfidf_top_features():
    """Cached load of TF-IDF top features to keep UI smooth."""
    try:
        import joblib as _jl2
        model_p = os.path.join(os.path.dirname(__file__), '..', 'models', 'spam_model.pkl')
        vec_p = os.path.join(os.path.dirname(__file__), '..', 'models', 'tfidf_vectorizer.pkl')
        if os.path.exists(model_p) and os.path.exists(vec_p):
            _model = _jl2.load(model_p); _vec2 = _jl2.load(vec_p)
            coef = _model.coef_[0]
            feats = _vec2.get_feature_names_out()
            pairs = list(zip(feats, coef))
            top_spam = sorted(pairs, key=lambda x: x[1], reverse=True)[:12]
            top_ham = sorted(pairs, key=lambda x: x[1])[:12]
            return top_spam, top_ham
    except Exception:
        pass
    return None, None


@st.cache_data(show_spinner=False, ttl=600)
def scan_available_datasets():
    """Scan data/processed + data/raw for all CSV datasets and return metadata sorted by size. Cached for speed."""
    import glob
    datasets = []
    search_dirs = [
        os.path.join(os.path.dirname(__file__), '..', 'data', 'processed'),
        os.path.join(os.path.dirname(__file__), '..', 'data', 'raw'),
    ]
    seen = set()
    for d_dir in search_dirs:
        if not os.path.exists(d_dir):
            continue
        for fp in glob.glob(os.path.join(d_dir, "*.csv")):
            if fp in seen:
                continue
            seen.add(fp)
            try:
                df_head = pd.read_csv(fp, nrows=5)
                if 'label' not in df_head.columns and 'text' not in df_head.columns:
                    continue
                # FAST row count: line count minus header (avoids full CSV parse)
                # For accurate ham/spam we sample label column efficiently with chunks
                size_mb = os.path.getsize(fp) / (1024*1024)
                # Quick n_rows via buffered binary count (C-level, much faster for 1M+ rows)
                try:
                    n_rows = 0
                    with open(fp, 'rb') as fh:
                        while True:
                            buf = fh.read(1024*1024)
                            if not buf:
                                break
                            n_rows += buf.count(b'\n')
                    n_rows = max(0, n_rows - 1)  # minus header
                except:
                    n_rows = 0
                # spam/ham: fast estimation — for huge files sample only to keep UI smooth
                spam_c = ham_c = 0
                try:
                    # For large datasets (>100k rows) sample 20k rows to estimate ratio (100x faster)
                    if n_rows > 100000:
                        sample_n = min(20000, n_rows)
                        df_sample = pd.read_csv(fp, usecols=['label'], nrows=sample_n)
                        s = df_sample['label'].astype(str).str.lower()
                        spam_s = int((s == 'spam').sum())
                        ham_s = int((s == 'ham').sum())
                        if spam_s == 0 and ham_s == 0:
                            spam_s = int((df_sample['label'] == 1).sum())
                            ham_s = int((df_sample['label'] == 0).sum())
                        # extrapolate
                        if sample_n > 0:
                            spam_c = int(spam_s / sample_n * n_rows)
                            ham_c = int(ham_s / sample_n * n_rows)
                    else:
                        chunk_iter = pd.read_csv(fp, usecols=['label'], chunksize=100000)
                        for chunk in chunk_iter:
                            s = chunk['label'].astype(str).str.lower()
                            spam_c += int((s == 'spam').sum())
                            ham_c += int((s == 'ham').sum())
                        if spam_c == 0 and ham_c == 0:
                            chunk_iter2 = pd.read_csv(fp, usecols=['label'], chunksize=100000)
                            spam_c = ham_c = 0
                            for chunk in chunk_iter2:
                                spam_c += int((chunk['label'] == 1).sum())
                                ham_c += int((chunk['label'] == 0).sum())
                except:
                    pass
                # fallback if line count failed
                if n_rows == 0:
                    n_rows = spam_c + ham_c
                datasets.append({
                    'path': fp,
                    'name': os.path.basename(fp),
                    'rows': n_rows,
                    'spam': spam_c,
                    'ham': ham_c,
                    'size_mb': round(size_mb, 1),
                    'folder': os.path.basename(os.path.dirname(fp)),
                })
            except Exception:
                continue
    # sort by rows descending (1M on top)
    datasets.sort(key=lambda x: x['rows'], reverse=True)
    return datasets


@st.cache_data(show_spinner=False, ttl=600)
def get_system_telemetry(selected_path=None):
    """Dynamically load metrics and dataset statistics from actual project files.

    If selected_path is given (from dataset selector), that CSV is prioritized.
    Otherwise prioritizes dataset_path from metrics.json, then largest available CSV.
    """
    stats = {
        'total_emails': 0,
        'spam_emails': 0,
        'ham_emails': 0,
        'model_accuracy': 0.0,
        'cv_mean': 0.0,
        'confusion_matrix': [[0, 0], [0, 0]],
        'classification_report': {},
        'df': pd.DataFrame(),
        'dataset_name': 'Default',
        'available_datasets': [],
        'metrics': {},
    }

    available = scan_available_datasets()
    stats['available_datasets'] = available

    # 1. Load actual model training metrics
    metrics_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'metrics.json')
    dataset_path_from_metrics = None
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r', encoding='utf-8') as f:
                m = json.load(f)
                stats['metrics'] = m
                stats['model_accuracy'] = float(m.get('accuracy', m.get('test_accuracy', 0.0)))
                stats['cv_mean'] = float(m.get('cv_mean', 0.0))
                stats['confusion_matrix'] = m.get('confusion_matrix', m.get('test_confusion_matrix', [[0, 0], [0, 0]]))
                stats['classification_report'] = m.get('classification_report', m.get('test_classification_report', {}))
                if 'total_samples' in m:
                    stats['total_emails'] = int(m['total_samples'])
                if 'spam_count' in m:
                    stats['spam_emails'] = int(m['spam_count'])
                if 'ham_count' in m:
                    stats['ham_emails'] = int(m['ham_count'])
                dataset_path_from_metrics = m.get('dataset_path') or m.get('dataset')
                # handle streaming path (no file)
                if dataset_path_from_metrics and dataset_path_from_metrics.startswith("streaming:"):
                    dataset_path_from_metrics = None
        except Exception:
            pass

    # 2. Resolve which dataset to show (selector overrides metrics)
    candidate_paths = []
    # selector priority 1
    if selected_path and os.path.exists(selected_path):
        candidate_paths.append(selected_path)
    # metrics path priority 2
    if dataset_path_from_metrics:
        if os.path.isabs(dataset_path_from_metrics):
            candidate_paths.append(dataset_path_from_metrics)
        else:
            candidate_paths.append(os.path.join(os.path.dirname(__file__), '..', dataset_path_from_metrics))
    # available sorted by rows (largest first) priority 3
    for d in available:
        if d['path'] not in candidate_paths:
            candidate_paths.append(d['path'])
    # legacy fallbacks
    for p in [
        os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'email_dataset_50k.csv'),
        os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'cleaned_dataset.csv'),
        os.path.join(os.path.dirname(__file__), '..', 'data', 'raw', 'email_dataset.csv'),
    ]:
        if p not in candidate_paths:
            candidate_paths.append(p)

    for p in candidate_paths:
        if os.path.exists(p):
            try:
                # PERFORMANCE: only read small sample for preview (5000 rows), not full 1M
                # counts are already derived from metrics or scan_available_datasets
                df_sample = pd.read_csv(p, nrows=5000)
                stats['df'] = df_sample
                # for accurate totals use scan info if available
                _match = next((d for d in available if d['path'] == p), None)
                if _match:
                    if stats['total_emails'] == 0:
                        stats['total_emails'] = _match['rows']
                    if stats['spam_emails'] == 0:
                        stats['spam_emails'] = _match['spam']
                    if stats['ham_emails'] == 0:
                        stats['ham_emails'] = _match['ham']
                else:
                    if stats['total_emails'] == 0:
                        stats['total_emails'] = len(df_sample)
                stats['dataset_name'] = os.path.basename(p)
                stats['dataset_path'] = p
                # also keep full count for display without loading full file
                stats['full_rows'] = _match['rows'] if _match else len(df_sample)
                break
            except Exception:
                pass

    return stats


# Resolve active dataset path without selector — auto-pick metrics path or largest
def _resolve_active_dataset_path():
    try:
        _m_tmp = json.load(open(os.path.join(os.path.dirname(__file__), '..', 'models', 'metrics.json'), encoding='utf-8'))
        _dp = _m_tmp.get('dataset_path')
        if _dp:
            _full = _dp if os.path.isabs(_dp) else os.path.join(os.path.dirname(__file__), '..', _dp)
            if os.path.exists(_full):
                return _full
    except:
        pass
    _avail = scan_available_datasets()
    if _avail:
        return _avail[0]['path']
    return None

_active_dataset_path = _resolve_active_dataset_path()

telemetry = get_system_telemetry(_active_dataset_path)

# Initialize Session State
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'email_body' not in st.session_state:
    st.session_state.email_body = ""
if 'email_header' not in st.session_state:
    st.session_state.email_header = ""
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None

# ==============================================================================
# SIDEBAR NAVIGATION
# ==============================================================================
with st.sidebar:
    # Logo & Brand
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 2rem; padding-left: 4px;">
        <div style="background: linear-gradient(135deg, #3b82f6, #6366f1); width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);">
            <span style="font-size: 1.5rem;">🛡️</span>
        </div>
        <div>
            <div style="font-size: 1.25rem; font-weight: 800; color: #ffffff; letter-spacing: -0.01em;">MailGuard AI</div>
            <div style="font-size: 0.72rem; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">Detect • Analyze • Stay Safe</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Nav Menu — Analyze Email only on Home; dedicated ML training graphs section
    menu_options = [
        ("Home", "🏠"),
        ("ML Insights", "🧠"),
        ("Security Reports", "📄"),
        ("About", "ℹ️")
    ]

    for label, icon in menu_options:
        is_active = (st.session_state.current_page == label)
        btn_type = "primary" if is_active else "secondary"
        if st.button(f"{icon}  {label}", key=f"nav_{label}", use_container_width=True, type=btn_type):
            st.session_state.current_page = label
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="border-top: 1px solid #1e293b; padding-top: 1.2rem; text-align: left; padding-left: 4px;">
        <div style="font-size: 0.82rem; color: #64748b; font-style: italic; margin-bottom: 6px;">"Safer Inboxes<br>Brighter Tomorrows"</div>
        <div style="font-size: 0.75rem; color: #475569; font-weight: 600;">v1.0.0</div>
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# HELPER: RUN ANALYSIS PIPELINE
# ==============================================================================
def run_full_pipeline(body_text: str, header_text: str):
    """Execute ML + Security Analyzers + VirusTotal URL Intelligence + Header Forensics + Gemini Report."""
    active_body = body_text.strip()
    active_headers = header_text.strip()
    
    if not active_body and not active_headers:
        st.warning("⚠️ Please enter email content or raw headers to analyze.")
        return None

    if detector is None:
        st.error("❌ Machine learning model is not available. Please train it first.")
        return None

    with st.spinner("🛡️ Scanning ML Classifier, VirusTotal URL Intelligence, Threat Engine & Gemini AI..."):
        try:
            # 1. ML Prediction (Untouched)
            scan_text = active_body if active_body else active_headers
            ml_result = detector.predict(scan_text)

            # 2. Heuristic URL Extraction & Rule Analyzers
            url_analyzer = URLAnalyzer()
            url_analysis = url_analyzer.analyze(active_body)

            # 3. VirusTotal URL Intelligence Lookup
            extracted_urls = url_analysis.get('unique_urls', [])
            vt_analysis = analyze_urls_with_virustotal(extracted_urls)

            keyword_analyzer = KeywordAnalyzer()
            keyword_analysis = keyword_analyzer.analyze(active_body)

            pattern_analyzer = PatternAnalyzer()
            pattern_analysis = pattern_analyzer.analyze(active_body)

            # 4. Header Security Forensics
            header_analyzer = HeaderAnalyzer()
            header_analysis = header_analyzer.analyze(active_headers)

            # 5. Risk Engine
            risk_engine = RiskEngine()
            risk_result = risk_engine.calculate_risk(
                ml_result=ml_result,
                url_analysis=url_analysis,
                keyword_analysis=keyword_analysis,
                pattern_analysis=pattern_analysis,
                header_analysis=header_analysis,
                vt_analysis=vt_analysis
            )

            # 6. Gemini AI Report Generator
            report_generator = ReportGenerator()
            report_result = report_generator.generate_report(
                ml_result=ml_result,
                url_analysis=url_analysis,
                keyword_analysis=keyword_analysis,
                pattern_analysis=pattern_analysis,
                risk_result=risk_result,
                header_analysis=header_analysis,
                vt_analysis=vt_analysis
            )

            results = {
                'email_text': active_body,
                'header_text': active_headers,
                'ml_result': ml_result,
                'url_analysis': url_analysis,
                'vt_analysis': vt_analysis,
                'keyword_analysis': keyword_analysis,
                'pattern_analysis': pattern_analysis,
                'header_analysis': header_analysis,
                'risk_result': risk_result,
                'report_result': report_result,
                'report_text': report_result.get('report_text', '')
            }
            st.session_state.analysis_results = results
            return results
        except Exception as e:
            st.error(f"Analysis Pipeline Error: {e}")
            return None


# ==============================================================================
# HELPER: RENDER RESULTS SECTION
# ==============================================================================
def render_results_dashboard(results: dict):
    """Render full structured results, VirusTotal findings, and PDF export button."""
    ml_res = results['ml_result']
    risk_res = results['risk_result']
    url_res = results['url_analysis']
    vt_res = results.get('vt_analysis', {})
    kw_res = results['keyword_analysis']
    pat_res = results['pattern_analysis']
    hdr_res = results['header_analysis']
    rep_res = results['report_result']

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 📊 Security Scan & Threat Audit")

    # Classification & Risk Score Row
    col_pred, col_risk = st.columns([1.2, 0.8])
    with col_pred:
        render_prediction_badge(ml_res['prediction'], ml_res['spam_probability'])
        render_confidence_gauge(ml_res['spam_probability'], ml_res['ham_probability'])

    with col_risk:
        render_risk_badge(risk_res['risk_level'], risk_res['risk_score'])
        st.markdown("<br>", unsafe_allow_html=True)
        if risk_res.get('contributing_factors'):
            for factor in risk_res['contributing_factors']:
                st.caption(f"• **{factor['factor']}** (`+{factor['points']} pts`): {factor['description']}")
        else:
            st.caption("No significant threat triggers identified.")

    # VirusTotal URL Threat Intelligence Section
    if vt_res and vt_res.get('urls_detected', 0) > 0:
        st.markdown("<br>", unsafe_allow_html=True)
        render_virustotal_card(vt_res)

    # 4 Indicator Cards
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### 🔍 Threat Indicator Breakdown")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_indicator_card("Heuristic URLs", url_res['suspicious_url_count'], url_res['suspicious_urls'], "🔗")
    with c2:
        all_kw = [w for words in kw_res.get('found_keywords', {}).values() for w in words]
        render_indicator_card("Keyword Triggers", kw_res['total_suspicious_keywords'], all_kw, "🔑")
    with c3:
        render_indicator_card("Pattern Anomalies", len(pat_res.get('patterns_found', [])), pat_res.get('patterns_found', []), "📝")
    with c4:
        h_cnt = len(hdr_res.get('anomalies', [])) if hdr_res.get('has_headers') else 0
        render_indicator_card("Header Anomalies", h_cnt, hdr_res.get('anomalies', []), "🛡️")

    # Header Forensics Card (if headers analyzed)
    if hdr_res.get('has_headers'):
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 🛡️ Email Header Forensics & Authentication (SPF/DKIM/DMARC)")
        render_header_security_card(hdr_res)

    # AI Security Report
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("#### 🧠 AI-Generated Explainable Security Report")
    with st.container():
        st.markdown('<div class="dark-card">', unsafe_allow_html=True)
        source_label = "Google Gemini AI" if rep_res.get('source') == 'gemini' else "Deterministic Security Engine (Offline Fallback)"
        st.caption(f"Generated via: **{source_label}**")
        st.text(rep_res.get('report_text', ''))
        st.markdown('</div>', unsafe_allow_html=True)

    # PDF Download Section
    st.markdown("<br>", unsafe_allow_html=True)
    col_pdf_l, col_pdf_r = st.columns([1.5, 1])
    with col_pdf_l:
        st.markdown("##### 📥 Export Official Security Audit Report")
        st.caption("Download the complete findings, ML classification, VirusTotal verdicts, and AI guidance as a PDF.")
    with col_pdf_r:
        try:
            pdf_bytes = generate_pdf_report(results)
            st.download_button(
                label="📄 Download Security Audit Report (PDF)",
                data=pdf_bytes,
                file_name="MailGuard_Security_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )
        except Exception as e:
            st.warning(f"PDF generation note: {e}")


# ==============================================================================
# PAGE 1: HOME (THE MAIN DASHBOARD)
# ==============================================================================
if st.session_state.current_page == "Home":
    # Hero Banner — fixed layout (no top cut, fully visible)
    hero_col_l, hero_col_r = st.columns([1.55, 0.85], gap="medium")
    
    with hero_col_l:
        st.markdown("""
        <div class="hero-container">
            <div class="top-badge">AI-POWERED EMAIL SECURITY & VIRUSTOTAL THREAT INTEL</div>
            <div class="hero-title">MailGuard AI</div>
            <div class="hero-tagline">Detect Spam. Stop Threats. <span>Stay Safe.</span></div>
            <div class="hero-description">
                An intelligent email analysis system that detects spam, phishing, and malicious content using Machine Learning, VirusTotal URL Intelligence, and Google Gemini AI.
            </div>
            <div class="hero-pills">
                <div class="hero-pill">
                    <div class="hero-pill-icon">⚡</div>
                    <div>
                        <div class="hero-pill-title">AI Detection</div>
                        <div class="hero-pill-subtitle">Powered by ML</div>
                    </div>
                </div>
                <div class="hero-pill">
                    <div class="hero-pill-icon">🛡️</div>
                    <div>
                        <div class="hero-pill-title">Threat Analysis</div>
                        <div class="hero-pill-subtitle">VirusTotal + Headers</div>
                    </div>
                </div>
                <div class="hero-pill">
                    <div class="hero-pill-icon">📄</div>
                    <div>
                        <div class="hero-pill-title">Detailed Reports</div>
                        <div class="hero-pill-subtitle">Powered by Gemini</div>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with hero_col_r:
        st.markdown("""
        <div class="shield-card">
            <div style="position: absolute; top: 14px; left: 16px;"><span class="shield-badge-spam">⚠️ Spam</span></div>
            <div style="position: absolute; top: 14px; right: 16px;"><span class="shield-badge-phish">🎣 Phishing</span></div>
            <div style="font-size: 92px; line-height: 1; filter: drop-shadow(0 0 14px rgba(56,189,248,0.55)); margin-top: 18px;">🛡️</div>
            <div style="font-size: 28px; margin-top: -52px; margin-bottom: 18px; background: #38bdf8; width: 56px; height: 38px; border-radius: 7px; display: flex; align-items: center; justify-content: center; border: 2px solid #ffffff; box-shadow: 0 2px 10px rgba(0,0,0,0.4);">✉️</div>
            <div style="margin-top: 10px;"><span class="shield-badge-safe">✅ Safe</span></div>
            <div style="margin-top: 12px; font-size: 0.66rem; font-weight: 800; letter-spacing: 0.2em; color: #475569; text-align: center;">ANALYZE • DETECT • PROTECT</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Analyze section — ONLY on Home (as requested)
    main_col_left, main_col_right = st.columns([1.35, 0.65], gap="medium")

    with main_col_left:
        st.markdown("""
        <div class="card-header-title">✉️ Analyze an Email</div>
        <div class="card-header-subtitle">Paste your email content below or upload a .eml file to check for spam, phishing, malicious URLs, or header spoofing.</div>
        """, unsafe_allow_html=True)

        input_mode = st.radio(
            "Input Mode",
            ["📄 Paste Email Text", "📤 Upload .eml File", "📎 Raw RFC Headers (Optional)"],
            horizontal=True,
            label_visibility="collapsed"
        )

        if input_mode == "📄 Paste Email Text":
            email_body_input = st.text_area(
                "Email Body",
                value=st.session_state.email_body,
                height=180,
                placeholder="Paste your email content here (Subject and Body with links)...",
                label_visibility="collapsed"
            )
            st.session_state.email_body = email_body_input

        elif input_mode == "📤 Upload .eml File":
            uploaded_eml = st.file_uploader("Upload .eml or .txt message file", type=['eml', 'txt'])
            if uploaded_eml:
                raw_content = uploaded_eml.read().decode('utf-8', errors='ignore')
                st.session_state.email_header = raw_content
                st.session_state.email_body = raw_content
                st.success(f"✅ Loaded {uploaded_eml.name} ({len(raw_content)} chars)")

        else:
            email_hdr_input = st.text_area(
                "Email Headers",
                value=st.session_state.email_header,
                height=180,
                placeholder="From: ...\nReturn-Path: ...\nReceived-SPF: ...\nAuthentication-Results: ...",
                label_visibility="collapsed"
            )
            st.session_state.email_header = email_hdr_input

        # Action Buttons Row
        c_btn1, c_btn2, c_btn3 = st.columns([1.2, 0.9, 0.9])
        with c_btn1:
            analyze_clicked = st.button("🔍 Analyze Email", type="primary", use_container_width=True)
        with c_btn2:
            if st.button("🚨 Phishing Demo", use_container_width=True):
                st.session_state.email_body = "URGENT: Your bank account access has been suspended! Verify your credentials at https://verify-banking-portal.xyz/login immediately or face permanent termination. Also see http://192.168.1.1/auth."
                st.session_state.email_header = "From: Security <security@official-bank.com>\nReturn-Path: <bounce@scammer-host.xyz>\nReceived-SPF: fail\nAuthentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail"
                st.rerun()
        with c_btn3:
            if st.button("✅ Safe Demo", use_container_width=True):
                st.session_state.email_body = "Hi team, Just sharing the updated project timeline at https://docs.python.org. Looking forward to our discussion on Wednesday at 2 PM."
                st.session_state.email_header = "From: team@company.com\nReturn-Path: <team@company.com>\nReceived-SPF: pass\nAuthentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass"
                st.rerun()

    with main_col_right:
        st.markdown("""
        <div class="card-header-title">📊 Quick Stats</div>
        <div class="card-header-subtitle">Recent training data — live from <code>models/metrics.json</code></div>
        """, unsafe_allow_html=True)

        # Recent train data from metrics.json (live)
        _m = telemetry.get('metrics', {})
        _total = _m.get('total_samples', telemetry.get('total_emails', 0))
        _train = _m.get('train_size', 0)
        _val = _m.get('val_size', 0)
        _test = _m.get('test_size', 0)
        _acc = _m.get('test_accuracy', _m.get('accuracy', telemetry.get('model_accuracy', 0)))
        _val_acc = _m.get('val_accuracy', _m.get('cv_mean', 0))
        _ds_name = os.path.basename(_m.get('dataset_path','')) if _m.get('dataset_path') else telemetry.get('dataset_name','')
        t_total = f"{_total:,}" if _total else "N/A"
        t_train = f"{_train:,}" if _train else "N/A"
        t_acc = f"{_acc:.2%}" if _acc else "Untrained"
        t_val = f"{_val_acc:.2%}" if _val_acc else "N/A"
        t_split = _m.get('split_ratio', '80/10/10') if _m else "N/A"
        val_label = "Val Accuracy" if _m.get('val_accuracy') else "CV Mean (5-fold)"

        # Show dataset badge
        if _ds_name:
            st.caption(f"📦 Active Model Dataset: **{_ds_name}** • Split: `{t_split}` • Train `{t_train}` / Val `{_val:,}` / Test `{_test:,}`" if _val and _test else f"📦 Dataset: **{_ds_name}**")

        stat_c1, stat_c2 = st.columns(2)
        with stat_c1:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-icon-wrapper" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa;">📦</div>
                    <div>
                        <div class="stat-val">{t_total}</div>
                        <div class="stat-label">Total Trained</div>
                    </div>
                </div>
                <div class="stat-trend" style="color: #60a5fa;">✓</div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-icon-wrapper" style="background: rgba(168, 85, 247, 0.15); color: #c084fc;">🎯</div>
                    <div>
                        <div class="stat-val">{t_acc}</div>
                        <div class="stat-label">Test Accuracy</div>
                    </div>
                </div>
                <div class="stat-trend" style="color: #c084fc;">★</div>
            </div>
            """, unsafe_allow_html=True)

        with stat_c2:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-icon-wrapper" style="background: rgba(34, 197, 94, 0.15); color: #4ade80;">🏋️</div>
                    <div>
                        <div class="stat-val">{t_train}</div>
                        <div class="stat-label">Train Size</div>
                    </div>
                </div>
                <div class="stat-trend" style="color: #4ade80;">⚡</div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-left">
                    <div class="stat-icon-wrapper" style="background: rgba(6, 182, 212, 0.15); color: #22d3ee;">🧪</div>
                    <div>
                        <div class="stat-val">{t_val}</div>
                        <div class="stat-label">{val_label}</div>
                    </div>
                </div>
                <div class="stat-trend" style="color: #22d3ee;">◆</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div class="quote-box">
            <span style="font-size: 1.5rem; color: #3b82f6;">❝</span>
            <div>
                <div class="quote-text">"AI & threat intelligence for a safer digital tomorrow."</div>
                <div class="quote-author">— MailGuard AI</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Execute Analysis if button was clicked
    if analyze_clicked:
        run_full_pipeline(st.session_state.email_body, st.session_state.email_header)

    # Render Results if available in Session State
    if st.session_state.analysis_results:
        render_results_dashboard(st.session_state.analysis_results)

    # Bottom 4 Feature Cards
    st.markdown("<br><br>", unsafe_allow_html=True)
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)

    with f_col1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon-box" style="background: rgba(59, 130, 246, 0.15); color: #60a5fa;">🛡️</div>
            <div>
                <div class="feature-title">Spam Detection</div>
                <div class="feature-desc">Identify unwanted and suspicious emails</div>
            </div>
            <div class="feature-arrow">➔</div>
        </div>
        """, unsafe_allow_html=True)

    with f_col2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon-box" style="background: rgba(239, 68, 68, 0.15); color: #f87171;">🎣</div>
            <div>
                <div class="feature-title">VirusTotal Intel</div>
                <div class="feature-desc">Query global antivirus engines for malicious links</div>
            </div>
            <div class="feature-arrow">➔</div>
        </div>
        """, unsafe_allow_html=True)

    with f_col3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon-box" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc;">📄</div>
            <div>
                <div class="feature-title">AI-Powered Reports</div>
                <div class="feature-desc">Detailed analysis using Google Gemini</div>
            </div>
            <div class="feature-arrow">➔</div>
        </div>
        """, unsafe_allow_html=True)

    with f_col4:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon-box" style="background: rgba(20, 184, 166, 0.15); color: #5eead4;">⏱️</div>
            <div>
                <div class="feature-title">Model Insights</div>
                <div class="feature-desc">Explore live metrics and dataset stats</div>
            </div>
            <div class="feature-arrow">➔</div>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# PAGE 2: ML INSIGHTS — TRAINING GRAPHS & MODEL INTERNALS (READ-ONLY)
# ==============================================================================
elif st.session_state.current_page == "ML Insights":
    st.markdown("## 🧠 ML Insights — Training Graphs & Model Internals")
    # Dynamic label: show actual dataset path from metrics.json, not hardcoded path
    _ds_label = "models/metrics.json"
    try:
        _m_tmp = json.load(open(os.path.join(os.path.dirname(__file__), '..', 'models', 'metrics.json'), encoding='utf-8'))
        _ds_label = _m_tmp.get('dataset_path', _ds_label)
    except Exception: pass
    st.markdown(f"All graphs are **read-only** — trained artifacts from `models/` and `{_ds_label}` (actual data, no hardcoded values, ML not re-trained).")
    st.markdown("---")

    # ---- Top metrics row (dynamic from telemetry) ----
    acc = telemetry['model_accuracy']
    cv_m = telemetry['cv_mean']
    rep = telemetry['classification_report']
    spam_prec = rep.get('spam', {}).get('precision', 0.0) if rep else 0.0
    spam_rec = rep.get('spam', {}).get('recall', 0.0) if rep else 0.0

    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("Test Accuracy", f"{acc:.2%}" if acc else "N/A", help="From models/metrics.json")
    with m2: st.metric("CV Mean (5-fold)", f"{cv_m:.2%}" if cv_m else "N/A")
    with m3: st.metric("Spam Precision", f"{spam_prec:.2%}" if spam_prec else "N/A")
    with m4: st.metric("Spam Recall", f"{spam_rec:.2%}" if spam_rec else "N/A")

    # Train/test & vectorizer info — ACTUAL values from metrics.json, not hardcoded 0.8/0.2 calc
    _metrics_for_sizes = {}
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'models', 'metrics.json'), encoding='utf-8') as _f:
            _metrics_for_sizes = json.load(_f)
    except Exception: pass
    _train_n = _metrics_for_sizes.get('train_size')
    _val_n = _metrics_for_sizes.get('val_size')
    _test_n = _metrics_for_sizes.get('test_size')
    # fallback to telemetry df if metrics missing (first run)
    if _train_n is None:
        _train_n = int(telemetry.get('df', pd.DataFrame()).shape[0]*0.8) if not telemetry.get('df', pd.DataFrame()).empty else 'N/A'
    if _test_n is None:
        _test_n = int(telemetry.get('df', pd.DataFrame()).shape[0]*0.1) if not telemetry.get('df', pd.DataFrame()).empty else 'N/A'
    info_c1, info_c2, info_c3, info_c4 = st.columns(4)
    with info_c1: st.caption(f"**Train size:** {_train_n:,}" if isinstance(_train_n, int) else f"**Train size:** {_train_n}")
    with info_c2: st.caption(f"**Val/Test size:** {_val_n:,}/{_test_n:,}" if isinstance(_val_n, int) and isinstance(_test_n, int) else f"**Val/Test:** {_val_n}/{_test_n}")
    with info_c3:
        try:
            import joblib as _jl
            _vec = _jl.load(os.path.join(os.path.dirname(__file__), '..', 'models', 'tfidf_vectorizer.pkl'))
            st.caption(f"**Vocab:** {len(_vec.vocabulary_):,} • ngram {(1,2)}")
        except Exception: st.caption("**Vectorizer:** TF-IDF (5000, 1-2 gram)")
    with info_c4: st.caption("**Model:** Logistic Regression (C=1.0, max_iter=1000)")

    st.markdown("<br>", unsafe_allow_html=True)

    # ---- Row 1: Confusion Matrix + Classification breakdown ----
    c_cm, c_bar = st.columns(2)
    with c_cm:
        st.markdown("#### Confusion Matrix")
        cm_data = telemetry['confusion_matrix']
        if cm_data and len(cm_data)==2:
            fig_cm = px.imshow(cm_data, x=['Ham','Spam'], y=['Ham','Spam'], labels=dict(x="Predicted", y="Actual", color="Count"), color_continuous_scale='Blues', text_auto=True)
            fig_cm.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", margin=dict(l=10,r=10,t=10,b=10))
            st.plotly_chart(fig_cm, use_container_width=True)
        else: st.info("Train the model to generate confusion matrix.")
    with c_bar:
        st.markdown("#### Precision / Recall / F1 per Class")
        if rep and 'spam' in rep and 'ham' in rep:
            metrics_df = pd.DataFrame({'Metric': ['Precision','Recall','F1'], 'Ham': [rep['ham']['precision'],rep['ham']['recall'],rep['ham']['f1-score']], 'Spam': [rep['spam']['precision'],rep['spam']['recall'],rep['spam']['f1-score']]})
            fig_bar = px.bar(metrics_df, x='Metric', y=['Ham','Spam'], barmode='group', color_discrete_sequence=['#22c55e','#ef4444'])
            fig_bar.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", legend_title_text="")
            st.plotly_chart(fig_bar, use_container_width=True)
        else: st.info("No classification_report found.")

    # Detailed report table
    if rep and 'spam' in rep:
        with st.expander("📋 Full Classification Report (from metrics.json)", expanded=False):
            rep_df = pd.DataFrame(rep).T
            st.dataframe(rep_df.style.format("{:.3f}", subset=pd.IndexSlice[['ham','spam','macro avg','weighted avg'], ['precision','recall','f1-score']]), use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ---- Row 2: TF-IDF Top Features (read-only from pkl) + Dataset pie ----
    f_col1, f_col2 = st.columns(2)
    with f_col1:
        st.markdown("#### 🔤 Top TF-IDF Features (LogReg Coefficients)")
        st.caption("Positive = spam indicative, Negative = ham indicative — cached from `spam_model.pkl` (no retrain)")
        try:
            top_spam, top_ham = get_tfidf_top_features()
            if top_spam and top_ham:
                spam_df = pd.DataFrame(top_spam, columns=['Feature','Weight'])
                ham_df = pd.DataFrame(top_ham, columns=['Feature','Weight'])
                c_s, c_h = st.columns(2)
                with c_s:
                    st.markdown("**Spam →**")
                    fig_s = px.bar(spam_df, x='Weight', y='Feature', orientation='h', color='Weight', color_continuous_scale='Reds')
                    fig_s.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", yaxis={'categoryorder':'total ascending'}, coloraxis_showscale=False, margin=dict(l=10,r=10,t=10,b=10), height=360)
                    st.plotly_chart(fig_s, use_container_width=True)
                with c_h:
                    st.markdown("**Ham →**")
                    fig_h = px.bar(ham_df, x='Weight', y='Feature', orientation='h', color='Weight', color_continuous_scale='Greens')
                    fig_h.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", yaxis={'categoryorder':'total ascending'}, coloraxis_showscale=False, margin=dict(l=10,r=10,t=10,b=10), height=360)
                    st.plotly_chart(fig_h, use_container_width=True)
            else: st.info("Model files not found.")
        except Exception as e: st.warning(f"Could not load top features: {e}")

    with f_col2:
        st.markdown("#### 🗄️ Dataset Distribution")
        df = telemetry['df']
        if not df.empty and 'label' in df.columns:
            class_counts = df['label'].astype(str).str.lower().value_counts()
            fig_pie = px.pie(values=class_counts.values, names=class_counts.index, color=class_counts.index, color_discrete_map={'spam':'#ef4444','ham':'#22c55e'}, hole=0.45)
            fig_pie.update_layout(paper_bgcolor="#0d1527", font_color="#e2e8f0", showlegend=True, margin=dict(l=10,r=10,t=10,b=10), height=280)
            st.plotly_chart(fig_pie, use_container_width=True)
            st.caption(f"Total {len(df):,} emails — Spam {int((df['label'].str.lower()=='spam').sum()):,} • Ham {int((df['label'].str.lower()=='ham').sum()):,}")
            # Top words bar
            st.markdown("**Top Words (raw text, >3 chars)**")
            all_words = ' '.join(df['text'].dropna().astype(str).str.lower()).split()
            filtered = [w for w in all_words if len(w)>3 and w.isalpha()]
            top_common = Counter(filtered).most_common(8)
            if top_common:
                top_df = pd.DataFrame(top_common, columns=['Word','Freq'])
                fig_w = px.bar(top_df, x='Freq', y='Word', orientation='h', color='Freq', color_continuous_scale='Blues')
                fig_w.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", yaxis={'categoryorder':'total ascending'}, coloraxis_showscale=False, height=280, margin=dict(l=10,r=10,t=10,b=10))
                st.plotly_chart(fig_w, use_container_width=True)
        else: st.info("Dataset not loaded.")



    # Samples preview
    df2 = telemetry['df']
    if not df2.empty:
        with st.expander(f"🔍 Active Dataset Samples — {telemetry['dataset_name']} (first 5 rows)"):
            st.dataframe(df2[['label','text']].head(5), use_container_width=True)

    with st.expander("Raw metrics.json"):
        try:
            with open(os.path.join(os.path.dirname(__file__), '..', 'models', 'metrics.json')) as f: st.json(json.load(f))
        except Exception as e: st.write(str(e))


# ==============================================================================
# PAGE 3: SECURITY REPORTS
# ==============================================================================
elif st.session_state.current_page == "Security Reports":
    st.markdown("## 📄 Security Audit Reports & History")
    st.markdown("View generated security audits, inspect AI explanations, and download reports.")
    st.markdown("---")

    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        st.markdown(f"**Latest Scan Timestamp:** `{results['report_result'].get('timestamp', 'Now')}`")
        st.markdown(f"**Verdict:** `{results['ml_result']['prediction'].upper()}` | **Risk Score:** `{results['risk_result']['risk_score']}/100 ({results['risk_result']['risk_level']})`")
        
        # VirusTotal summary if URLs present
        vt_data = results.get('vt_analysis', {})
        if vt_data and vt_data.get('urls_detected', 0) > 0:
            st.markdown(f"**VirusTotal Intel:** `{vt_data.get('urls_detected')} URLs scanned` | `Malicious: {vt_data.get('malicious_count')}` | `Suspicious: {vt_data.get('suspicious_count')}`")

        st.markdown("#### AI Security Explanation:")
        st.text_area("Report Content", value=results.get('report_text', ''), height=320)
        
        pdf_bytes = generate_pdf_report(results)
        st.download_button(
            label="📄 Download Security Audit Report (PDF)",
            data=pdf_bytes,
            file_name="MailGuard_Security_Audit.pdf",
            mime="application/pdf",
            type="primary"
        )
    else:
        st.info("ℹ️ No scans yet. Go to **Home** to analyze an email.")


# ==============================================================================
# PAGE 4: ABOUT
# ==============================================================================
elif st.session_state.current_page == "About":
    st.markdown("## ℹ️ About MailGuard AI")
    st.markdown("Architecture, design rationale, VirusTotal integration, and technology breakdown.")
    st.markdown("---")

    st.markdown("""
    ### 🏗️ Technical Architecture
    ```text
    USER EMAIL (+ Optional RFC Headers)
                    |
                    v
           Streamlit Dashboard
                    |
        +-----------+-----------------------+
        v                                   v
    ML CLASSIFIER                   SECURITY ANALYZERS
    (TF-IDF / Hashing               * URL Extractor
     + Logistic / SGD)              * VirusTotal API v3 Threat Intel
     [READ-ONLY / UNTOUCHED]        * Keyword & Pattern Analyzers
        |                           * SPF / DKIM / DMARC Forensics
        |                                   |
        +-----------------+-----------------+
                          v
                 Risk Scoring Engine
                  (0 - 100 Points)
                          |
                          v
                  Google Gemini AI
            (Explainable Security Report)
                          |
                          v
            Interactive UI + PDF Export
    ```

    ### 🛡️ Why This Architecture?
    1. **Independent ML Spam Classifier**: The ML model makes mathematical predictions without external API dependencies.
    2. **VirusTotal URL Intelligence**: Live threat database lookup for URLs without touching ML features or model parameters.
    3. **Header Forensics**: Inspects domain spoofing, SPF, DKIM, and DMARC compliance to catch sophisticated spear-phishing attacks.
    4. **Explainable AI (XAI)**: Google Gemini explains findings and remediation without hallucinating detections.
    5. **Zero Hardcoded Data**: All UI statistics and performance charts are dynamically generated from live models and datasets.
    """)

# ==============================================================================
# FOOTER
# ==============================================================================
st.markdown("""
<div class="footer-container">
    <div>&copy; 2025 MailGuard AI. Built with <span style="color:#ef4444;">&#9829;</span> using Streamlit.</div>
    <div style="display: flex; gap: 16px;">
        <span style="cursor: pointer;">Privacy</span>
        <span>&bull;</span>
        <span style="cursor: pointer;">Terms</span>
        <span>&bull;</span>
        <span style="cursor: pointer;">Contact</span>
    </div>
</div>
""", unsafe_allow_html=True)
