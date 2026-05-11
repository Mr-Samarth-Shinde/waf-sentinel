# training/train.py — ULTRA FAST VERSION
import os, sys
sys.path.insert(0, os.path.abspath("."))

import numpy as np
import pandas as pd
import joblib
import scipy.sparse as sp
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
from sklearn.utils import resample
from xgboost import XGBClassifier

DATA_PATH   = "data/processed/dataset.csv"
SAMPLE_SIZE = 80_000    # train on 80k — very fast, very accurate
EVAL_SIZE   = 10_000    # evaluate on 10k sample — no need for full 133k
os.makedirs("models", exist_ok=True)
os.makedirs("data/cache", exist_ok=True)

# ── 1. Load ───────────────────────────────────────────────────────────────────
print("[1/5] Loading dataset...")
df = pd.read_csv(DATA_PATH).dropna(subset=["payload","label"])
df["payload"] = df["payload"].astype(str)
df["label"]   = df["label"].astype(int)
print(f"      Loaded {len(df)} rows")

# ── 2. Sample BEFORE splitting — work on 100k total only ─────────────────────
print("[2/5] Sampling 100k rows for speed...")
df = df.sample(n=100_000, random_state=42).reset_index(drop=True)

X_raw = df["payload"].tolist()
y     = df["label"].values

X_train, X_test, y_train, y_test = train_test_split(
    X_raw, y, test_size=0.2, random_state=42, stratify=y)
X_train, X_val, y_train, y_val = train_test_split(
    X_train, y_train, test_size=0.1, random_state=42, stratify=y_train)

print(f"      Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

# ── 3. Features — use cache if available ─────────────────────────────────────
print("[3/5] Extracting features...")
from waf.preprocessor import WAFPreprocessor

CACHE = "data/cache/features.pkl"
if os.path.exists(CACHE):
    print("      Loading cached features...")
    cache = joblib.load(CACHE)
    X_tr, X_v, X_te, y_train, y_val, y_test = (
        cache["X_tr"], cache["X_v"], cache["X_te"],
        cache["y_tr"], cache["y_v"], cache["y_te"]
    )
    pre = WAFPreprocessor.load("models/preprocessor.pkl")
else:
    pre  = WAFPreprocessor()
    X_tr = pre.fit_transform(X_train)
    pre.save("models/preprocessor.pkl")
    print("      Transforming val/test...")
    X_v  = pre.transform(X_val)
    X_te = pre.transform(X_test)
    joblib.dump({
        "X_tr": X_tr, "X_v": X_v, "X_te": X_te,
        "y_tr": y_train, "y_v": y_val, "y_te": y_test
    }, CACHE)
    print("      Features cached → data/cache/features.pkl")

# Convert to dense once
print("      Converting to dense arrays...")
X_tr_d = X_tr.toarray() if sp.issparse(X_tr) else X_tr
X_v_d  = X_v.toarray()  if sp.issparse(X_v)  else X_v
X_te_d = X_te.toarray() if sp.issparse(X_te) else X_te
print(f"      Shape: {X_tr_d.shape}")

# ── 4. Train RF (load if exists) ──────────────────────────────────────────────
print("[4/5] Training models...")
if os.path.exists("models/rf_model.pkl"):
    print("      RF already trained — loading...")
    rf = joblib.load("models/rf_model.pkl")
else:
    print("      Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=20,
        class_weight="balanced", n_jobs=-1, random_state=42
    )
    rf.fit(X_tr_d, y_train)
    joblib.dump(rf, "models/rf_model.pkl")
    print("      RF saved!")

if os.path.exists("models/xgb_model.pkl"):
    print("      XGB already trained — loading...")
    xgb = joblib.load("models/xgb_model.pkl")
else:
    print("      Training XGBoost...")
    xgb = XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.2,
        subsample=0.8, colsample_bytree=0.8,
        tree_method="hist", n_jobs=-1,
        eval_metric="logloss", verbosity=0, random_state=42
    )
    xgb.fit(X_tr_d, y_train)
    joblib.dump(xgb, "models/xgb_model.pkl")
    print("      XGB saved!")

# ── 5. Evaluate ───────────────────────────────────────────────────────────────
print("[5/5] Evaluating ensemble...")
rf_proba  = rf.predict_proba(X_te_d)[:, 1]
xgb_proba = xgb.predict_proba(X_te_d)[:, 1]
ens_proba = (rf_proba * 0.5) + (xgb_proba * 0.5)
ens_pred  = (ens_proba > 0.5).astype(int)

print("\n── Results ─────────────────────────────────────────────")
print(classification_report(y_test, ens_pred, target_names=["Benign","Malicious"]))
print(f"AUC  : {roc_auc_score(y_test, ens_proba):.4f}")
print(f"F1   : {f1_score(y_test, ens_pred):.4f}")
cm = confusion_matrix(y_test, ens_pred)
print(f"\nConfusion Matrix:")
print(f"            Benign  Malicious")
print(f"  Benign   {cm[0][0]:>7} {cm[0][1]:>9}")
print(f"  Malicious{cm[1][0]:>7} {cm[1][1]:>9}")

joblib.dump({
    "rf_weight": 0.5, "xgb_weight": 0.5,
    "threshold": 0.85, "version": "1.0",
    "models": ["rf","xgb"]
}, "models/ensemble_config.pkl")

print("\n✅ All done! Models ready in models/")