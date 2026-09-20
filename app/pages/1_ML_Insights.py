"""ML Insights — Training graphs (read-only, no retrain)."""
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import streamlit as st
import pandas as pd
import plotly.express as px
from collections import Counter
from app.styles import MODERN_DARK_CSS

st.set_page_config(page_title="ML Insights — MailGuard AI", page_icon="🧠", layout="wide")
st.markdown(MODERN_DARK_CSS, unsafe_allow_html=True)

st.title("🧠 ML Insights — Training Graphs & Model Internals")
st.caption("Read-only artifacts from `models/metrics.json` + actual dataset (no retraining, no hardcoded data).")
st.divider()

# Load telemetry - DYNAMIC: reads actual metrics.json + discovers actual dataset (same as Home)
import os as _os, json as _js, pandas as _pd
metrics_p = _os.path.join(_os.path.dirname(__file__), "..", "..", "models", "metrics.json")
m = {}
dataset_path_from_metrics = None
if _os.path.exists(metrics_p):
    with open(metrics_p, encoding='utf-8') as f: m = _js.load(f)
    dataset_path_from_metrics = m.get('dataset_path')

# Dynamic dataset discovery (priority: path recorded in metrics.json -> 50k -> cleaned -> raw -> any csv)
candidate_paths = []
if dataset_path_from_metrics:
    if _os.path.isabs(dataset_path_from_metrics):
        candidate_paths.append(dataset_path_from_metrics)
    else:
        candidate_paths.append(_os.path.join(_os.path.dirname(__file__), "..", "..", dataset_path_from_metrics))
candidate_paths.extend([
    _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "processed", "email_dataset_50k.csv"),
    _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "processed", "cleaned_dataset.csv"),
    _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "raw", "email_dataset.csv"),
])
# Also scan data/ folders for any csv
for _folder in ['processed', 'raw']:
    _d_dir = _os.path.join(_os.path.dirname(__file__), "..", "..", "data", _folder)
    if _os.path.exists(_d_dir):
        for _f in _os.listdir(_d_dir):
            if _f.endswith('.csv'):
                _p = _os.path.join(_d_dir, _f)
                if _p not in candidate_paths:
                    candidate_paths.append(_p)

df = _pd.DataFrame()
dataset_name = "N/A"
for _p in candidate_paths:
    if _os.path.exists(_p):
        try:
            df = _pd.read_csv(_p)
            dataset_name = _os.path.basename(_p)
            break
        except: pass
if not df.empty:
    st.caption(f"**Dataset:** `{dataset_name}` | **Rows:** {len(df):,} | **Source:** `{dataset_path_from_metrics or dataset_name}` (from `models/metrics.json`)")

acc, cv_m = m.get("accuracy",0), m.get("cv_mean",0)
rep = m.get("classification_report",{})
c1,c2,c3,c4 = st.columns(4)
c1.metric("Test Accuracy", f"{acc:.2%}" if acc else "N/A")
c2.metric("CV Mean", f"{cv_m:.2%}" if cv_m else "N/A")
c3.metric("Spam Precision", f"{rep.get('spam',{}).get('precision',0):.2%}" if rep else "N/A")
c4.metric("Spam Recall", f"{rep.get('spam',{}).get('recall',0):.2%}" if rep else "N/A")

# Confusion + bar
a,b = st.columns(2)
with a:
    st.markdown("#### Confusion Matrix")
    cm = m.get("confusion_matrix", m.get("test_confusion_matrix", [[0,0],[0,0]]))
    # No hardcoded fallback like [[19,2],[0,26]] - uses actual metrics.json; shows placeholder only if not trained
    if cm == [[0,0],[0,0]]:
        st.info("Model not trained yet — train first to generate actual confusion matrix (no hardcoded data).")
    else:
        fig = px.imshow(cm, x=["Ham","Spam"], y=["Ham","Spam"], text_auto=True, color_continuous_scale="Blues", labels=dict(color="Count"))
        fig.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0")
        st.plotly_chart(fig, use_container_width=True)
with b:
    st.markdown("#### Per-Class F1")
    if rep:
        d = pd.DataFrame([{"Class":k,"F1":v["f1-score"]} for k,v in rep.items() if k in ("ham","spam")])
        fig2 = px.bar(d, x="F1", y="Class", orientation="h", color="Class", color_discrete_map={"ham":"#22c55e","spam":"#ef4444"})
        fig2.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", showlegend=False)
        st.plotly_chart(fig2, use_container_width=True)

# Top TF-IDF features
st.markdown("#### 🔤 Top TF-IDF Features (LogReg coefficients)")
try:
    import joblib
    mp = _os.path.join(_os.path.dirname(__file__), "..", "..", "models", "spam_model.pkl")
    vp = _os.path.join(_os.path.dirname(__file__), "..", "..", "models", "tfidf_vectorizer.pkl")
    if _os.path.exists(mp) and _os.path.exists(vp):
        mdl = joblib.load(mp); vec = joblib.load(vp)
        coef = mdl.coef_[0]; feats = vec.get_feature_names_out()
        pairs = list(zip(feats, coef))
        top_spam = sorted(pairs, key=lambda x: x[1], reverse=True)[:10]
        top_ham = sorted(pairs, key=lambda x: x[1])[:10]
        s1,s2 = st.columns(2)
        with s1:
            st.markdown("**Spam indicative →**")
            sdf = pd.DataFrame(top_spam, columns=["Feature","Weight"])
            fig = px.bar(sdf, x="Weight", y="Feature", orientation="h", color="Weight", color_continuous_scale="Reds")
            fig.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", yaxis={'categoryorder':'total ascending'}, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
        with s2:
            st.markdown("**Ham indicative →**")
            hdf = pd.DataFrame(top_ham, columns=["Feature","Weight"])
            fig = px.bar(hdf, x="Weight", y="Feature", orientation="h", color="Weight", color_continuous_scale="Greens")
            fig.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", yaxis={'categoryorder':'total ascending'}, coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
except Exception as e: st.warning(str(e))

# Dataset pie
if not df.empty:
    st.markdown("#### 🗄️ Dataset Distribution (Active)")
    cc = df['label'].astype(str).str.lower().value_counts()
    fig = px.pie(values=cc.values, names=cc.index, hole=0.45, color=cc.index, color_discrete_map={'spam':'#ef4444','ham':'#22c55e'})
    fig.update_layout(paper_bgcolor="#0d1527", font_color="#e2e8f0")
    st.plotly_chart(fig, use_container_width=True)

# ── All Datasets Overview (same as Home) ──
st.markdown("### 🗄️ All Available Datasets (Frontend Auto-Updated)")
import glob as _glob
_all = []
for _d in [_os.path.join(_os.path.dirname(__file__), "..", "..", "data", "processed"), _os.path.join(_os.path.dirname(__file__), "..", "..", "data", "raw")]:
    if _os.path.exists(_d):
        for _fp in _glob.glob(_os.path.join(_d, "*.csv")):
            try:
                _lab = _pd.read_csv(_fp, usecols=['label'])
                _n = len(_lab)
                _spam = int((_lab['label'].astype(str).str.lower()=='spam').sum())
                _ham = int((_lab['label'].astype(str).str.lower()=='ham').sum())
                _sz = round(_os.path.getsize(_fp)/(1024*1024),1)
                _all.append({"Dataset": _os.path.basename(_fp), "Rows": f"{_n:,}", "_rows": _n, "Ham": f"{_ham:,}", "Spam": f"{_spam:,}", "Size MB": _sz, "Path": _fp.replace("\\","/")})
            except: pass
_all = sorted(_all, key=lambda x: x["_rows"], reverse=True)
if _all:
    st.dataframe(_pd.DataFrame([{k:v for k,v in d.items() if k!="_rows"} for d in _all]), use_container_width=True, hide_index=True)
    _cmp = _pd.DataFrame([{"Dataset": d["Dataset"], "Rows": d["_rows"]} for d in _all])
    fig_cmp = px.bar(_cmp, x="Dataset", y="Rows", color="Dataset", text_auto=True)
    fig_cmp.update_layout(paper_bgcolor="#0d1527", plot_bgcolor="#0d1527", font_color="#e2e8f0", showlegend=False, height=300)
    st.plotly_chart(fig_cmp, use_container_width=True)
    st.caption("Select active dataset via Home sidebar selector. Model metrics from `models/metrics.json` auto-update after 1M training.")
    # dataset selector for this page too
    _labels = [d["Dataset"] + f" ({d['Rows']})" for d in _all]
    _sel = st.selectbox("📂 Active Dataset Preview", _labels, index=0)
    _idx = _labels.index(_sel)
    _chosen = _all[_idx]["Path"]
    try:
        _pdf = _pd.read_csv(_chosen)
        st.dataframe(_pdf[['label','text']].head(5), use_container_width=True)
    except: pass
