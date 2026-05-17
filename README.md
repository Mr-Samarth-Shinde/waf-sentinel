# 🛡️ WAF SENTINEL — Intelligent Web Application Firewall

<div align="center">

![WAF Sentinel](https://img.shields.io/badge/WAF-SENTINEL-00d4ff?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![ML](https://img.shields.io/badge/ML-RandomForest%20%2B%20XGBoost-orange?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-3.1.0-green?style=for-the-badge&logo=flask)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=for-the-badge)

**An AI-powered Web Application Firewall that detects and blocks web attacks in real time using Machine Learning trained on 893,000+ payloads.**

[🌐 Live API](https://waf-sentinel.onrender.com/waf-dashboard/health) • [📊 Dashboard](https://mr-samarth-shinde.github.io/waf-sentinel) • [📁 Source Code](https://github.com/Mr-Samarth-Shinde/waf-sentinel)

</div>

---

## 🎯 What is WAF Sentinel?

WAF Sentinel is an **Intelligent Web Application Firewall** built from scratch as a personal cybersecurity project. It sits between the internet and your web application, intercepting every HTTP request and analyzing it using a trained Machine Learning ensemble model to detect and block attacks before they reach your server.

Unlike traditional WAFs that rely only on static rules, WAF Sentinel uses **Machine Learning** to detect novel attack patterns and evasion techniques — trained on a dataset of over 893,000 labeled payloads.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **ML Detection** | Random Forest + XGBoost ensemble trained on 893k payloads |
| 🔍 **Multi-Attack Detection** | SQLi, XSS, LFI, RCE, SSRF, XXE, Command Injection |
| 🛡️ **OWASP Rules** | Fallback rule engine for edge cases the ML misses |
| 📊 **Live Dashboard** | Real-time attack visualization and statistics |
| 🔬 **Payload Lab** | Interactive payload tester with quick-attack buttons |
| 📋 **Event Log** | Full audit trail of every intercepted request |
| 🔄 **Proxy Mode** | Transparent HTTP proxy — drop-in protection |
| ⚡ **Fast** | Sub-millisecond inference per request |
| ☁️ **Cloud Deployed** | Live on Render with GitHub Pages dashboard |

---

## 🚨 Attack Types Detected

```
┌─────────────────────────────────────────────────────────────┐
│  SQLi   → SQL Injection (basic, UNION, blind, time-based)   │
│  XSS    → Cross-Site Scripting (script, onerror, SVG, URI)  │
│  LFI    → Local File Inclusion (traversal, PHP wrappers)    │
│  RCE    → Remote Code Execution (shell, pipe, backtick)     │
│  SSRF   → Server-Side Request Forgery (localhost, metadata) │
│  XXE    → XML External Entity injection                     │
│  CMDi   → Command Injection (&&, |, $(), backtick)          │
│  Evasion→ Case variation, URL encoding, comment injection   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture

```
                    Internet
                       │
                       ▼
            ┌─────────────────────┐
            │    HTTP Request     │
            └─────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────┐
│           WAF SENTINEL PROXY             │
│  ┌────────────────────────────────────┐  │
│  │      Feature Extraction Layer      │  │
│  │  URL decode → Normalize → Tokenize │  │
│  └────────────────────────────────────┘  │
│                    │                     │
│  ┌─────────────────▼──────────────────┐  │
│  │       ML Detection Engine          │  │
│  │  ┌──────────────┐ ┌─────────────┐  │  │
│  │  │ Random Forest│ │  XGBoost    │  │  │
│  │  └──────┬───────┘ └──────┬──────┘  │  │
│  │         └────────┬────────┘         │  │
│  │           Ensemble Score            │  │
│  └─────────────────────────────────────┘  │
│                    │                     │
│  ┌─────────────────▼──────────────────┐  │
│  │  Score ≥ 0.75  →  BLOCK  (403)     │  │
│  │  Score ≥ 0.65  →  OWASP Check      │  │
│  │  Score < 0.65  →  ALLOW            │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
          │                    │
          ▼                    ▼
     BLOCK (403)         Forward to Backend
     Log Attack          Log Request
```

---

## 📊 Model Performance

| Metric | Value |
|---|---|
| **Training Dataset** | 893,079 labeled payloads |
| **Attack Categories** | 7 |
| **F1 Score** | 1.0000 |
| **AUC-ROC** | 1.0000 |
| **Precision** | 100% |
| **Recall** | 100% |
| **False Positives** | 0 / 20,000 test samples |

### Test Results
```
              precision    recall  f1-score   support
      Benign       1.00      1.00      1.00      7381
   Malicious       1.00      1.00      1.00     12619
    accuracy                           1.00     20000
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.11 |
| **ML Models** | Scikit-learn (Random Forest), XGBoost |
| **Features** | TF-IDF Character N-grams + 26 hand-crafted features |
| **Backend** | Flask 3.1, Flask-CORS |
| **Proxy** | Flask middleware (transparent HTTP proxy) |
| **Database** | SQLite (attack log storage) |
| **Dashboard** | HTML5, CSS3, JavaScript, Chart.js |
| **Deployment** | Render.com (backend), GitHub Pages (frontend) |

---

## 📁 Project Structure

```
waf-sentinel/
├── waf/
│   ├── proxy.py           # Main WAF proxy + Dashboard API
│   ├── model_loader.py    # Load models + predict payloads
│   ├── preprocessor.py    # Feature extraction pipeline
│   └── startup.py         # Auto-train models on first run
├── training/
│   ├── train.py           # Model training script
│   ├── build_dataset.py   # Dataset collection + labeling
│   └── notebooks/
│       └── eda.py         # Exploratory data analysis
├── dashboard/
│   └── frontend/
│       └── index.html     # Cybersecurity dashboard UI
├── models/                # Saved ML models (auto-generated)
│   ├── rf_model.pkl
│   ├── xgb_model.pkl
│   ├── preprocessor.pkl
│   └── ensemble_config.pkl
├── data/
│   └── processed/
│       └── dataset.csv    # Labeled payload dataset
├── logs/
│   └── attacks.db         # SQLite attack log
├── test_waf.py            # Automated test suite (11/11 ✅)
├── practical_demo.py      # Live attack demonstration
├── vulnerable_app.py      # Demo target application
├── requirements.txt
├── render.yaml
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Git

### Installation

```bash
# Clone the repo
git clone https://github.com/Mr-Samarth-Shinde/waf-sentinel.git
cd waf-sentinel

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Train models (first time — takes ~5 mins)
python training/train.py
```

### Run the WAF

```bash
python waf/proxy.py
```

### Open Dashboard

Open `dashboard/frontend/index.html` in your browser — or visit the live version:
**https://mr-samarth-shinde.github.io/waf-sentinel**

---

## 🔬 Live Demo

### Run a full attack demonstration

**Terminal 1 — WAF:**
```bash
python waf/proxy.py
```

**Terminal 2 — Vulnerable Target App:**
```bash
python vulnerable_app.py
```

**Terminal 3 — Attack Demo:**
```bash
python practical_demo.py
```

### Test via API

```bash
# Test SQLi payload
curl -X POST https://waf-sentinel.onrender.com/waf-dashboard/test \
  -H "Content-Type: application/json" \
  -d "{\"payload\": \"' OR 1=1--\"}"

# Response:
# {"action":"BLOCK","score":0.9849,"attack_type":"sqli","blocked":true}
```

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/waf-dashboard/stats` | GET | Live statistics — total, blocked, by type |
| `/waf-dashboard/logs` | GET | Last 200 intercepted requests |
| `/waf-dashboard/test` | POST | Analyze any payload `{"payload":"..."}` |
| `/waf-dashboard/health` | GET | Service health check |

---

## 🧪 Automated Test Results

```
======================================================================
  Test                      Expected   Got      Score    Status
======================================================================
  SQLi basic                BLOCK      BLOCK    0.9849   ✅
  SQLi UNION                BLOCK      BLOCK    0.9400   ✅
  XSS script tag            BLOCK      BLOCK    0.9750   ✅
  XSS onerror               BLOCK      BLOCK    0.9498   ✅
  LFI traversal             BLOCK      BLOCK    0.9925   ✅
  RCE whoami                BLOCK      BLOCK    1.0000   ✅
  SSRF localhost            BLOCK      BLOCK    0.9750   ✅
  Benign search             ALLOW      ALLOW    0.4964   ✅
  Benign login              ALLOW      ALLOW    0.1598   ✅
  Benign pagination         ALLOW      ALLOW    0.2083   ✅
  Benign product            ALLOW      ALLOW    0.2022   ✅
======================================================================
  Results: 11 passed, 0 failed ✅
  False Positives: 0/3 ✅
======================================================================
```

---

## ☁️ Deployment

### Live URLs
- **WAF API:** https://waf-sentinel.onrender.com
- **Dashboard:** https://mr-samarth-shinde.github.io/waf-sentinel
- **Health:** https://waf-sentinel.onrender.com/waf-dashboard/health

### Deploy your own (free)

1. Fork this repo
2. Sign up at [Render.com](https://render.com)
3. **New Web Service** → connect your fork
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn --bind 0.0.0.0:$PORT --timeout 120 waf.proxy:app`
6. Enable **GitHub Pages** → `/dashboard/frontend` for the dashboard

---

## 🔑 Key Design Decisions

**Why Random Forest + XGBoost ensemble?**
Both models see the same features but learn differently — RF captures broad patterns, XGBoost focuses on difficult borderline cases. Averaging their scores reduces false positives significantly.

**Why character-level TF-IDF?**
Character n-grams (2–3 chars) catch obfuscated payloads like `SeLeCt`, URL-encoded strings, and comment-injected SQL that word-level features miss.

**Why 26 hand-crafted features?**
Entropy, special char ratio, keyword presence, and encoding detection give the model interpretable signals that pure TF-IDF misses on very short payloads.

---

## 👨‍💻 Author

**Samarth Shinde**
- GitHub: [@Mr-Samarth-Shinde](https://github.com/Mr-Samarth-Shinde)
- Project: [WAF Sentinel](https://github.com/Mr-Samarth-Shinde/waf-sentinel)

---

## 📄 License



<div align="center">


⭐ Star this repo if you found it useful!

</div>
