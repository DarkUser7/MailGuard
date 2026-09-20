"""Custom CSS & UI Theme for MailGuard AI — fixed layout, no truncation."""

MODERN_DARK_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    /* Hide Streamlit header / Deploy button / hamburger */
    header[data-testid="stHeader"] {
        display: none !important;
    }
    [data-testid="stToolbar"] {
        display: none !important;
    }
    #MainMenu { visibility: hidden !important; }
    footer { visibility: hidden !important; }

    /* Global background */
    .stApp {
        background-color: #080c14;
        color: #e2e8f0;
    }

    /* Fix top padding — header is hidden so reduce gap */
    .block-container {
        padding-top: 1.0rem !important;
        padding-bottom: 2.5rem !important;
        max-width: 1380px !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0b111e !important;
        border-right: 1px solid #1a2538 !important;
        min-width: 260px !important;
    }
    [data-testid="stSidebar"] .block-container {
        padding-top: 1.5rem !important;
        padding-left: 1.0rem !important;
        padding-right: 1.0rem !important;
    }
    [data-testid="stSidebarNav"] { display: none !important; }

    /* Sidebar buttons — ensure proper spacing & no cut */
    [data-testid="stSidebar"] .stButton > button {
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        padding: 0.55rem 1rem !important;
        margin-bottom: 0.45rem !important;
        border: 1px solid #1e2d48 !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stSidebar"] .stButton > button[kind="secondary"] {
        background: #111a2e !important;
        color: #94a3b8 !important;
    }
    [data-testid="stSidebar"] .stButton > button[kind="secondary"]:hover {
        background: #16213a !important;
        color: #e2e8f0 !important;
        border-color: #2a3f62 !important;
    }
    [data-testid="stSidebar"] .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #3b82f6 0%, #6366f1 100%) !important;
        color: #ffffff !important;
        border: none !important;
        box-shadow: 0 4px 14px rgba(59,130,246,0.35) !important;
    }

    /* Badge */
    .top-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(59, 130, 246, 0.12);
        border: 1px solid rgba(59, 130, 246, 0.3);
        color: #60a5fa;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 4px 12px;
        border-radius: 9999px;
        margin-bottom: 12px;
    }

    .hero-container {
        background: linear-gradient(135deg, #0d1527 0%, #0a1120 50%, #080e1a 100%);
        border: 1px solid #1e2d48;
        border-radius: 16px;
        padding: 1.8rem 2rem;
        position: relative;
        overflow: hidden;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), 0 0 20px 0 rgba(59, 130, 246, 0.07);
    }
    .hero-title {
        font-size: 2.6rem;
        font-weight: 800;
        color: #ffffff;
        line-height: 1.1;
        margin-bottom: 0.4rem;
        letter-spacing: -0.02em;
    }
    .hero-tagline {
        font-size: 1.2rem;
        font-weight: 700;
        color: #94a3b8;
        margin-bottom: 0.7rem;
    }
    .hero-tagline span { color: #38bdf8; }
    .hero-description {
        font-size: 0.92rem;
        color: #94a3b8;
        max-width: 620px;
        line-height: 1.6;
        margin-bottom: 1.4rem;
    }
    .hero-pills { display: flex; flex-wrap: wrap; gap: 10px; }
    .hero-pill {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        background: #111a2e;
        border: 1px solid #20314f;
        padding: 7px 14px;
        border-radius: 12px;
    }
    .hero-pill-icon {
        display: flex; align-items: center; justify-content: center;
        width: 30px; height: 30px; border-radius: 8px;
        background: rgba(59, 130, 246, 0.15); color: #60a5fa; font-size: 0.95rem;
    }
    .hero-pill-title { font-size: 0.84rem; font-weight: 700; color: #f1f5f9; line-height: 1.2; }
    .hero-pill-subtitle { font-size: 0.72rem; color: #64748b; }

    /* Shield card — ensure not cut */
    .shield-card {
        background: radial-gradient(circle at center, rgba(59, 130, 246, 0.18) 0%, rgba(8, 12, 20, 0) 70%);
        border: 1px solid #1e2d48;
        border-radius: 16px;
        padding: 1.5rem 1.2rem;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        position: relative;
        min-height: 280px;
        overflow: visible;
    }

    /* Cards */
    .dark-card {
        background-color: #0d1527;
        border: 1px solid #1e2d48;
        border-radius: 14px;
        padding: 1.25rem;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .card-header-title {
        display: flex; align-items: center; gap: 8px;
        font-size: 1.08rem; font-weight: 700; color: #ffffff; margin-bottom: 0.25rem;
    }
    .card-header-subtitle { font-size: 0.82rem; color: #718096; margin-bottom: 1.0rem; }

    /* Stat cards */
    .stat-card {
        background: #111a2e;
        border: 1px solid #1e2e4a;
        border-radius: 12px;
        padding: 0.9rem 1rem;
        display: flex; align-items: center; justify-content: space-between;
        margin-bottom: 0.7rem;
        transition: transform 0.2s, border-color 0.2s;
    }
    .stat-card:hover { transform: translateY(-2px); border-color: #3b82f6; }
    .stat-left { display: flex; align-items: center; gap: 10px; }
    .stat-icon-wrapper {
        width: 38px; height: 38px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center; font-size: 1.1rem; flex-shrink: 0;
    }
    .stat-val { font-size: 1.3rem; font-weight: 800; color: #ffffff; line-height: 1.1; }
    .stat-label { font-size: 0.73rem; color: #8899ac; font-weight: 500; }
    .stat-trend { font-size: 1.0rem; }

    .quote-box {
        background: rgba(17, 26, 46, 0.6);
        border: 1px solid #1a2840;
        border-radius: 12px;
        padding: 0.9rem 1.1rem;
        margin-top: 0.7rem;
        display: flex; gap: 10px; align-items: center;
    }
    .quote-text { font-size: 0.82rem; color: #94a3b8; font-style: italic; }
    .quote-author { font-size: 0.72rem; color: #64748b; font-weight: 600; margin-top: 4px; text-align: right; }

    /* Feature cards */
    .feature-card {
        background: #0d1527;
        border: 1px solid #1e2d48;
        border-radius: 14px;
        padding: 1.1rem 1.2rem;
        display: flex; align-items: flex-start; gap: 12px;
        transition: all 0.25s ease; height: 100%;
    }
    .feature-card:hover { border-color: #3b82f6; transform: translateY(-3px); box-shadow: 0 8px 24px rgba(59, 130, 246, 0.15); }
    .feature-icon-box {
        width: 42px; height: 42px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center; font-size: 1.25rem; flex-shrink: 0;
    }
    .feature-title { font-size: 0.94rem; font-weight: 700; color: #ffffff; margin-bottom: 2px; }
    .feature-desc { font-size: 0.78rem; color: #8899ac; line-height: 1.35; }
    .feature-arrow { color: #3b82f6; font-weight: bold; font-size: 1.0rem; margin-left: auto; padding-top: 2px; }

    /* Inputs */
    .stTextArea textarea {
        background-color: #0a0f1d !important;
        border: 1px solid #1e2c44 !important;
        color: #f1f5f9 !important;
        border-radius: 10px !important;
        font-size: 0.9rem !important;
    }
    .stTextArea textarea:focus { border-color: #3b82f6 !important; box-shadow: 0 0 0 1px #3b82f6 !important; }
    .stRadio > div { gap: 1.2rem; }

    .stButton button[kind="primary"] {
        background: linear-gradient(90deg, #3b82f6 0%, #6366f1 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.6rem 1.6rem !important;
        box-shadow: 0 4px 16px rgba(59, 130, 246, 0.35) !important;
    }
    .stButton button[kind="primary"]:hover { transform: translateY(-1px) !important; box-shadow: 0 6px 22px rgba(59, 130, 246, 0.5) !important; }

    /* Badges */
    .shield-badge-spam {
        background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #f87171;
        font-size: 0.74rem; font-weight: 700; padding: 3px 10px; border-radius: 9999px;
    }
    .shield-badge-phish {
        background: rgba(6, 182, 212, 0.15); border: 1px solid #06b6d4; color: #22d3ee;
        font-size: 0.74rem; font-weight: 700; padding: 3px 10px; border-radius: 9999px;
    }
    .shield-badge-safe {
        background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #4ade80;
        font-size: 0.74rem; font-weight: 700; padding: 3px 10px; border-radius: 9999px;
    }

    /* Risk */
    .risk-critical { background: linear-gradient(135deg, #ef4444, #b91c1c); color: white; padding: 12px; border-radius: 10px; font-weight: 800; text-align: center; }
    .risk-high { background: linear-gradient(135deg, #f97316, #c2410c); color: white; padding: 12px; border-radius: 10px; font-weight: 800; text-align: center; }
    .risk-medium { background: linear-gradient(135deg, #eab308, #a16207); color: black; padding: 12px; border-radius: 10px; font-weight: 800; text-align: center; }
    .risk-low { background: linear-gradient(135deg, #22c55e, #15803d); color: white; padding: 12px; border-radius: 10px; font-weight: 800; text-align: center; }

    /* Metric cards for ML section */
    .ml-metric-card {
        background: #0d1527;
        border: 1px solid #1e2d48;
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
    }
    .ml-metric-value { font-size: 1.6rem; font-weight: 800; color: #fff; }
    .ml-metric-label { font-size: 0.75rem; color: #8899ac; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.05em; }

    .footer-container {
        margin-top: 3rem; padding-top: 1.2rem;
        border-top: 1px solid #1a2538;
        display: flex; justify-content: space-between; align-items: center;
        color: #64748b; font-size: 0.8rem;
    }

    /* Ensure plotly charts fit */
    [data-testid="stPlotlyChart"] { background: transparent; }
</style>
"""
