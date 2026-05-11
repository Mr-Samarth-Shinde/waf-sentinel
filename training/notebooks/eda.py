# training/notebooks/eda.py
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from waf.preprocessor import extract_features, FEATURE_NAMES

df = pd.read_csv("data/processed/dataset.csv")

print("── Dataset Overview ──")
print(f"Total samples : {len(df)}")
print(f"Malicious     : {(df.label==1).sum()}")
print(f"Benign        : {(df.label==0).sum()}")
print(f"\nAttack types:\n{df.attack_type.value_counts()}\n")

# Extract features for all rows
print("[*] Extracting features (this takes ~1 min)...")
feats = pd.DataFrame(
    [extract_features(p) for p in df.payload],
    columns=FEATURE_NAMES
)
feats['label'] = df.label.values

# Plot 1 — Attack type distribution
plt.figure(figsize=(10,4))
df.attack_type.value_counts().plot(kind='bar', color='steelblue', edgecolor='black')
plt.title("Attack Type Distribution")
plt.tight_layout()
plt.savefig("data/processed/attack_distribution.png")
print("[+] Saved attack_distribution.png")

# Plot 2 — Feature comparison: malicious vs benign
fig, axes = plt.subplots(2, 3, figsize=(14, 8))
cols = ["length","entropy","keyword_count","special_ratio","has_sql","has_xss"]
for ax, col in zip(axes.flat, cols):
    feats.groupby('label')[col].mean().plot(kind='bar', ax=ax, color=['green','red'])
    ax.set_title(col)
    ax.set_xticklabels(['Benign','Malicious'], rotation=0)
plt.suptitle("Feature Averages: Benign vs Malicious")
plt.tight_layout()
plt.savefig("data/processed/feature_comparison.png")
print("[+] Saved feature_comparison.png")
plt.show()