# waf/startup.py
import os, sys
sys.path.insert(0, os.path.abspath("."))

def ensure_models():
    models_needed = [
        "models/rf_model.pkl",
        "models/xgb_model.pkl",
        "models/preprocessor.pkl",
        "models/ensemble_config.pkl"
    ]
    if all(os.path.exists(m) for m in models_needed):
        print("[+] Models found!")
        return

    print("[!] Training lightweight models for cloud deployment...")
    import random, joblib
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier
    import scipy.sparse as sp
    from waf.preprocessor import WAFPreprocessor

    os.makedirs("models", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)

    # ── Compact dataset — fits in 512MB ──────────────────────────────────────
    MALICIOUS = [
        "' OR 1=1--", "1 UNION SELECT * FROM users",
        "' AND SLEEP(5)--", "admin'--", "1; DROP TABLE users--",
        "SELECT * FROM users WHERE 1=1",
        "<script>alert('xss')</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)",
        "../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php",
        ";whoami", "| cat /etc/passwd", "`id`",
        "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data",
        "<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>",
        "SeLeCt * FrOm users", "%27%20OR%201%3D1--",
    ] * 300  # 6000 malicious samples

    BENIGN = [
        "?q=python+tutorial", "?username=alice&password=secure123",
        "?id=42&category=laptops", "?page=3&limit=20",
        "?lang=en&region=US&uid=123", "?min=100&max=5000",
        "?sort=price&order=asc", "?search=mobile+phones",
        "?user_id=99&tab=settings", "?format=json&version=2",
        "/home", "/about", "/products", "/contact",
        "?color=blue&size=medium", "?currency=USD&country=US",
    ] * 400  # 6000 benign samples

    random.seed(42)
    rows = (
        [{"payload": p, "label": 1, "attack_type": "attack"} for p in MALICIOUS] +
        [{"payload": p, "label": 0, "attack_type": "benign"} for p in BENIGN]
    )
    random.shuffle(rows)
    df = pd.DataFrame(rows)
    print(f"[+] Training samples: {len(df)}")

    X = df["payload"].tolist()
    y = df["label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("[*] Fitting preprocessor (small TF-IDF)...")
    from waf.preprocessor import WAFPreprocessor
    pre = WAFPreprocessor()
    # Override to small vocab for cloud
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import StandardScaler
    pre.tfidf = TfidfVectorizer(
        analyzer='char', ngram_range=(2,3),
        max_features=500,  # much smaller than local 1500
        sublinear_tf=True
    )
    pre.scaler = StandardScaler(with_mean=False)

    X_tr = pre.fit_transform(X_train)
    X_te = pre.transform(X_test)
    pre.fitted = True
    pre.save("models/preprocessor.pkl")

    X_tr_d = X_tr.toarray() if sp.issparse(X_tr) else X_tr
    X_te_d = X_te.toarray() if sp.issparse(X_te) else X_te

    print("[*] Training Random Forest (small)...")
    rf = RandomForestClassifier(
        n_estimators=50,     # small — fits in 512MB
        max_depth=15,
        class_weight="balanced",
        n_jobs=1,            # single thread to save RAM
        random_state=42
    )
    rf.fit(X_tr_d, y_train)
    joblib.dump(rf, "models/rf_model.pkl")
    print("[+] RF done!")

    print("[*] Training XGBoost (small)...")
    xgb = XGBClassifier(
        n_estimators=50,     # small
        max_depth=4,
        learning_rate=0.3,
        tree_method="hist",
        n_jobs=1,
        verbosity=0,
        random_state=42
    )
    xgb.fit(X_tr_d, y_train)
    joblib.dump(xgb, "models/xgb_model.pkl")
    print("[+] XGB done!")

    joblib.dump({
        "rf_weight": 0.5, "xgb_weight": 0.5,
        "threshold": 0.75, "version": "1.0",
        "models": ["rf", "xgb"]
    }, "models/ensemble_config.pkl")

    from sklearn.metrics import f1_score
    rf_p  = rf.predict_proba(X_te_d)[:, 1]
    xgb_p = xgb.predict_proba(X_te_d)[:, 1]
    ens   = rf_p * 0.5 + xgb_p * 0.5
    pred  = (ens > 0.5).astype(int)
    print(f"[+] Cloud model F1: {f1_score(y_test, pred):.4f}")
    print("[+] All models ready!")

if __name__ == "__main__":
    ensure_models()