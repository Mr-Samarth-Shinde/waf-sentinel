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
        print("[+] All models found!")
        return

    print("[!] Models not found — training now (~3 mins)...")
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

    MALICIOUS = [
        "' OR 1=1--", "1 UNION SELECT * FROM users",
        "' AND SLEEP(5)--", "admin'--", "1; DROP TABLE users--",
        "SELECT * FROM users WHERE 1=1", "' OR 'x'='x",
        "<script>alert('xss')</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)",
        "../../etc/passwd", "../../etc/shadow",
        "php://filter/convert.base64-encode/resource=index.php",
        ";whoami", "| cat /etc/passwd", "`id`", "$(whoami)",
        "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data",
        "gopher://localhost:6379/", "<!DOCTYPE foo [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>",
        "SeLeCt * FrOm users", "%27%20OR%201%3D1--", "SEL/**/ECT * FROM users",
    ] * 1200

    BENIGN = [
        "?q=python+tutorial", "?username=alice&password=secure123",
        "?id=42&category=laptops", "?page=3&limit=20",
        "?lang=en&region=US&uid=123", "?min=100&max=5000",
        "?sort=price&order=asc", "?search=mobile+phones",
        "?user_id=99&tab=settings", "?format=json&version=2",
        "?name=john&email=john@example.com", "?token=abc123xyz",
        "/home", "/about", "/products", "/contact",
        "?tag=technology&author=admin", "?color=blue&size=medium",
        "?currency=USD&country=US", "?year=2024&month=01",
    ] * 1400

    random.seed(42)
    rows = (
        [{"payload": p, "label": 1, "attack_type": "attack"} for p in MALICIOUS] +
        [{"payload": p, "label": 0, "attack_type": "benign"} for p in BENIGN]
    )
    random.shuffle(rows)
    df = pd.DataFrame(rows)
    df.to_csv("data/processed/dataset.csv", index=False)
    print(f"[+] Generated {len(df)} training samples")

    X = df["payload"].tolist()
    y = df["label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("[*] Fitting preprocessor...")
    pre = WAFPreprocessor()
    X_tr = pre.fit_transform(X_train)
    X_te = pre.transform(X_test)
    pre.save("models/preprocessor.pkl")

    X_tr_d = X_tr.toarray() if sp.issparse(X_tr) else X_tr
    X_te_d = X_te.toarray() if sp.issparse(X_te) else X_te

    print("[*] Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=20,
        class_weight="balanced", n_jobs=-1, random_state=42)
    rf.fit(X_tr_d, y_train)
    joblib.dump(rf, "models/rf_model.pkl")

    print("[*] Training XGBoost...")
    xgb = XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.2,
        tree_method="hist", n_jobs=-1, verbosity=0, random_state=42)
    xgb.fit(X_tr_d, y_train)
    joblib.dump(xgb, "models/xgb_model.pkl")

    joblib.dump({
        "rf_weight": 0.5, "xgb_weight": 0.5,
        "threshold": 0.75, "version": "1.0",
        "models": ["rf", "xgb"]
    }, "models/ensemble_config.pkl")

    print("[+] Training complete! Models ready.")

if __name__ == "__main__":
    ensure_models()