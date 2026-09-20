# 🛡️ MailGuard AI — Intelligent Email Spam Detection & Security Analysis

## Overview
MailGuard AI is an intelligent email security analysis system that combines machine learning spam detection with rule-based security analysis and AI-powered report generation.

**Key Design:** The machine learning model performs classification, the rule-based security analyzers identify threat indicators (suspicious URLs, high-urgency keywords, structural anomalies), and the Gemini AI engine generates explainable, natural-language security reports with actionable remediation advice.

---

## Architecture

```text
                     +---------------------------------------+
                     |              User Email               |
                     +-------------------+-------------------+
                                         |
                                         v
                     +---------------------------------------+
                     |           Pre-processing              |
                     |   (Cleaning, Tokenization, Regex)     |
                     +---------+-------------------+---------+
                               |                   |
            +------------------+                   +-------------------+
            v                                                          v
+-------------------------------+              +-----------------------------------+
|      ML Spam Classifier       |              |        Security Analyzers         |
|   (TF-IDF + Logistic Reg.)    |              |                                   |
|  - Prediction: Spam / Ham     |              |  - URL Analyzer (IP, Shorteners)  |
|  - Probabilities & Confidence |              |  - Keyword Analyzer (Urgency, etc)|
+---------------+---------------+              |  - Pattern Analyzer (Caps, Punct) |
                |                              +-----------------+-----------------+
                |                                                |
                +-----------------------+------------------------+
                                        |
                                        v
                     +---------------------------------------+
                     |             Risk Engine               |
                     |  - Weighted Threat Scoring (0 - 100)  |
                     |  - Risk Levels: LOW to CRITICAL       |
                     +------------------+--------------------+
                                        |
                                        v
                     +---------------------------------------+
                     |           Gemini AI Engine            |
                     |  - 5-Section Explainable Report       |
                     |  - Actionable Remediation Guidance    |
                     |  - Built-in Deterministic Fallback    |
                     +------------------+--------------------+
                                        |
                                        v
                     +---------------------------------------+
                     |       Presentation & Export Layer     |
                     |  - Streamlit Multi-Page Dashboard     |
                     |  - Downloadable PDF Security Reports  |
                     +---------------------------------------+
```

---

## Features
- **ML Spam Detection**: High-accuracy TF-IDF feature extraction with Logistic Regression classification providing confidence and class probability estimates.
- **Security Analysis**:
  - **URL Analyzer**: Identifies raw IP addresses, URL shorteners (e.g. `bit.ly`), suspicious TLDs (`.xyz`, `.top`, `.click`), and phishing paths.
  - **Keyword Analyzer**: Scans for urgency triggers, financial lures, threatening language, and suspicious call-to-actions.
  - **Pattern Analyzer**: Flags excessive capitalization, repeated punctuation (`!!!`), embedded HTML tags, and phone/monetary anomalies.
- **Weighted Risk Scoring (0–100)**: Multi-factor risk engine categorizing threats into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk tiers with explicit point breakdowns.
- **Gemini AI Report Generation**: Google Gemini 2.0 integration translating technical indicators into user-friendly security explanations (with automatic offline fallback).
- **PDF Report Export**: Generates professional PDF security audit reports styled with severity badges and security disclaimers.
- **Interactive Streamlit Dashboard**: Clean, multi-page web UI featuring live email analysis, threat indicator breakdown, and AI report review.

---

## Tech Stack
- **Core Language**: Python 3.10+
- **Machine Learning & Data**: Scikit-learn, Pandas, NumPy, Joblib, NLTK
- **Web Interface**: Streamlit
- **Generative AI**: Google Gemini API (`google-genai`), Python-dotenv
- **Document Export**: FPDF2
- **Visualization**: Plotly, Matplotlib, WordCloud
- **Testing**: Pytest

---

## Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd MailGuard
```

### 2. Create and Activate a Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` and configure your Google Gemini API key:
```bash
cp .env.example .env
```
Open `.env` and set your key:
```env
GEMINI_API_KEY=your_actual_api_key_here
```

### 5. Generate Dataset & Train the Model
Train the spam classification model:
```bash
# Optional: regenerate sample dataset if needed
python generate_dataset.py

# Train the TF-IDF + Logistic Regression model
python ml/src/train.py
```
This saves `spam_model.pkl`, `tfidf_vectorizer.pkl`, and `metrics.json` inside the `models/` directory.

### 6. Run the Application
Launch the Streamlit web dashboard:
```bash
streamlit run app/streamlit_app.py
```

### 7. Run the Test Suite
Execute unit tests using pytest:
```bash
pytest tests/
```

---

## Project Structure

```text
MailGuard/
├── .env.example              # Environment configuration template
├── .gitignore                # Git ignore rules for models, env, and temporary files
├── requirements.txt          # Project dependencies
├── README.md                 # Project documentation and setup guide
├── generate_dataset.py       # Script to generate synthetic email datasets
├── data/
│   └── raw/
│       └── email_dataset.csv # Raw training dataset of spam & ham emails
├── ml/
│   ├── __init__.py
│   └── src/
│       ├── __init__.py
│       ├── preprocessing.py  # Text cleaning, normalization, and stopword removal
│       ├── train.py          # TF-IDF vectorization and Logistic Regression training
│       ├── evaluate.py       # Model performance evaluation and confusion matrix
│       └── predict.py        # SpamDetector inference engine
├── analyzer/
│   ├── __init__.py
│   ├── url_analyzer.py       # URL extraction, shortener & suspicious TLD/IP detection
│   ├── keyword_analyzer.py   # Intent-based keyword detection (urgency, finance, threat, action)
│   ├── pattern_analyzer.py   # Capitalization, punctuation, and structural anomaly analysis
│   └── risk_engine.py        # Weighted risk calculation (0-100) and severity rating
├── gemini/
│   ├── __init__.py
│   ├── client.py             # Google Gemini API client wrapper
│   ├── prompts.py            # Structured prompts & system instructions
│   └── report_generator.py   # AI security report generator with local fallback
├── reports/
│   ├── __init__.py
│   └── pdf_generator.py      # PDF report generation with FPDF2
├── app/
│   ├── streamlit_app.py      # Main Streamlit application entry point
│   ├── components.py         # Reusable UI widgets and layout cards
│   └── pages/
│       ├── 1_Analyze_Email.py       # Interactive email analysis interface
│       └── 2_Detection_Report.py    # Detailed security breakdown and PDF download
└── tests/
    ├── __init__.py           # Test package initializer
    ├── test_model.py         # ML model prediction and probability tests
    ├── test_analyzer.py      # Rule-based analyzers and risk engine tests
    └── test_gemini.py        # Prompt formatting, fallback generator, and client tests
```

---

## How It Works

1. **User inputs email text**: The user pastes raw email content into the Streamlit web dashboard.
2. **ML model classifies email**: TF-IDF transforms the cleaned email text, and Logistic Regression predicts `spam` or `ham` with confidence and probability metrics.
3. **Security analyzers scan for threats**:
   - URL analyzer inspects hyperlinks for IP addresses, shorteners, and suspicious domains.
   - Keyword analyzer detects psychological triggers (urgency, threats, financial lures).
   - Pattern analyzer assesses text anomalies (ALL CAPS, excessive punctuation, HTML).
4. **Risk engine calculates weighted score**: Aggregates findings from both the ML model and security analyzers to produce a 0–100 score and risk rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. **Gemini generates explanation report**: The Google Gemini model synthesizes an explainable report broken down into 5 standard sections (Summary, Detected Issues, Analysis, Risk Interpretation, Recommended Actions). If an API key is not configured, the built-in offline template generator is automatically utilized.
6. **User can download PDF report**: The complete findings and risk breakdown can be exported as a professional PDF report.

---

## API Key
- MailGuard AI uses Google Gemini to generate natural language security reports.
- You can get a free Gemini API key from [Google AI Studio](https://aistudio.google.com/).
- Never commit your `.env` file or API keys to version control.
- If no API key is provided, MailGuard AI will automatically fall back to its deterministic rule-based template report generator without interrupting analysis.

---

## License
This project is licensed under the [MIT License](LICENSE).
