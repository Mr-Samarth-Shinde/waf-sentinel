# waf/preprocessor.py
import re
import math
import urllib.parse
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import os

os.makedirs("models", exist_ok=True)

# ── Dangerous keyword lists ───────────────────────────────────────────────────
SQLI_KEYWORDS    = ["select","union","insert","update","delete","drop","exec",
                    "execute","xp_","sp_","cast","convert","char","nchar",
                    "varchar","alter","create","truncate","--","/*","*/","@@"]

XSS_KEYWORDS     = ["<script","</script","onerror","onload","onmouseover",
                    "alert(","confirm(","prompt(","javascript:","vbscript:",
                    "document.cookie","document.write","innerHTML","eval(",
                    "fromcharcode","&#","\\x3c","\\u003c"]

RCE_KEYWORDS     = ["cmd","exec","system","passthru","shell_exec","popen",
                    "proc_open","eval(","assert(","preg_replace","call_user",
                    "/bin/sh","/bin/bash","whoami","ls -","cat /etc","wget ",
                    "curl ","nc ","netcat","python -c","perl -e","ruby -e"]

LFI_KEYWORDS     = ["../","..\\","etc/passwd","etc/shadow","boot.ini",
                    "proc/self","var/log","php://","file://","zip://",
                    "expect://","data://","input://","filter://"]

SSRF_KEYWORDS    = ["127.0.0.1","localhost","0.0.0.0","169.254","192.168.",
                    "10.0.","172.16.","file:///","dict://","gopher://",
                    "ftp://","http://localhost","https://localhost"]

XXE_KEYWORDS     = ["<!entity","<!doctype","system(","public ","cdata",
                    "dtd","xmlns","xml version","processing-instruction"]

CMD_KEYWORDS     = ["|","||","&&","`;","`","$(","$((",">{","2>&1",
                    ">/dev/null","ping -","nslookup ","tracert ","net user",
                    "net localgroup","sc query","tasklist"]

ALL_KEYWORDS = (SQLI_KEYWORDS + XSS_KEYWORDS + RCE_KEYWORDS +
                LFI_KEYWORDS  + SSRF_KEYWORDS + XXE_KEYWORDS + CMD_KEYWORDS)

# ── Entropy helper ────────────────────────────────────────────────────────────
def entropy(text):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

# ── Core normalizer ───────────────────────────────────────────────────────────
def normalize(payload):
    p = str(payload)
    # multi-pass URL decode (handles double encoding)
    for _ in range(3):
        decoded = urllib.parse.unquote(p)
        if decoded == p:
            break
        p = decoded
    # HTML entity decode basics
    p = p.replace("&lt;","<").replace("&gt;",">").replace("&amp;","&") \
         .replace("&quot;",'"').replace("&#39;","'")
    # hex decode \x41 → A
    p = re.sub(r'\\x([0-9a-fA-F]{2})',
               lambda m: chr(int(m.group(1), 16)), p)
    # unicode decode \u0041 → A
    p = re.sub(r'\\u([0-9a-fA-F]{4})',
               lambda m: chr(int(m.group(1), 16)), p)
    return p.lower().strip()

# ── Feature extraction ────────────────────────────────────────────────────────
def extract_features(payload):
    p   = normalize(payload)
    raw = str(payload)

    length          = len(p)
    special_chars   = len(re.findall(r'[<>\'"\(\)\[\]{};,\|&=\+\-\*\/\\@!#%\^`~]', p))
    special_ratio   = special_chars / max(length, 1)
    digit_ratio     = sum(c.isdigit() for c in p) / max(length, 1)
    alpha_ratio     = sum(c.isalpha() for c in p) / max(length, 1)
    space_count     = p.count(' ')
    url_encoded     = len(re.findall(r'%[0-9a-f]{2}', raw.lower()))
    num_params      = p.count('=')
    num_quotes      = p.count("'") + p.count('"')
    num_comments    = p.count('--') + p.count('/*') + p.count('#')
    payload_entropy = entropy(p)
    word_count      = len(p.split())
    has_sql         = int(any(k in p for k in SQLI_KEYWORDS))
    has_xss         = int(any(k in p for k in XSS_KEYWORDS))
    has_rce         = int(any(k in p for k in RCE_KEYWORDS))
    has_lfi         = int(any(k in p for k in LFI_KEYWORDS))
    has_ssrf        = int(any(k in p for k in SSRF_KEYWORDS))
    has_xxe         = int(any(k in p for k in XXE_KEYWORDS))
    has_cmd         = int(any(k in p for k in CMD_KEYWORDS))
    keyword_count   = sum(1 for k in ALL_KEYWORDS if k in p)
    has_concat      = int('||' in p or '+' in p or 'concat' in p)
    has_sleep       = int('sleep(' in p or 'waitfor' in p or 'benchmark(' in p)
    has_encoding    = int(url_encoded > 0 or '\\x' in raw or '&#' in p)
    num_tags        = len(re.findall(r'<[a-z]+', p))
    has_script      = int('<script' in p or 'javascript:' in p)
    path_traversal  = p.count('../') + p.count('..\\')

    return [
        length, special_chars, special_ratio, digit_ratio, alpha_ratio,
        space_count, url_encoded, num_params, num_quotes, num_comments,
        payload_entropy, word_count, has_sql, has_xss, has_rce, has_lfi,
        has_ssrf, has_xxe, has_cmd, keyword_count, has_concat, has_sleep,
        has_encoding, num_tags, has_script, path_traversal,
    ]

FEATURE_NAMES = [
    "length","special_chars","special_ratio","digit_ratio","alpha_ratio",
    "space_count","url_encoded","num_params","num_quotes","num_comments",
    "entropy","word_count","has_sql","has_xss","has_rce","has_lfi",
    "has_ssrf","has_xxe","has_cmd","keyword_count","has_concat","has_sleep",
    "has_encoding","num_tags","has_script","path_traversal",
]

# ── Full pipeline ─────────────────────────────────────────────────────────────
class WAFPreprocessor:
    def __init__(self):
        self.tfidf  = TfidfVectorizer(
            analyzer='char', ngram_range=(2,4),
            max_features=1500,          # reduced from 3000 to save RAM
            sublinear_tf=True
        )
        self.scaler = StandardScaler(with_mean=False)  # sparse-compatible
        self.fitted = False

    def fit_transform(self, payloads):
        from scipy.sparse import hstack, csr_matrix
        normalized  = [normalize(p) for p in payloads]

        print("      [*] Fitting TF-IDF...")
        tfidf_feats = self.tfidf.fit_transform(normalized)      # stays SPARSE

        print("      [*] Extracting hand-crafted features...")
        hand_feats  = csr_matrix(
            np.array([extract_features(p) for p in payloads], dtype=np.float32)
        )

        print("      [*] Scaling hand features...")
        hand_scaled = self.scaler.fit_transform(hand_feats)     # sparse in/out

        self.fitted = True
        print("      [*] Stacking feature matrix...")
        return hstack([hand_scaled, tfidf_feats])               # stays SPARSE

    def transform(self, payloads):
        from scipy.sparse import hstack, csr_matrix
        if not self.fitted:
            raise RuntimeError("Call fit_transform first")
        if isinstance(payloads, str):
            payloads = [payloads]
        normalized  = [normalize(p) for p in payloads]
        tfidf_feats = self.tfidf.transform(normalized)
        hand_feats  = csr_matrix(
            np.array([extract_features(p) for p in payloads], dtype=np.float32)
        )
        hand_scaled = self.scaler.transform(hand_feats)
        return hstack([hand_scaled, tfidf_feats])

    def save(self, path="models/preprocessor.pkl"):
        joblib.dump(self, path)
        print(f"[+] Preprocessor saved → {path}")

    @staticmethod
    def load(path="models/preprocessor.pkl"):
        return joblib.load(path)


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    samples = [
        "' OR 1=1--",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "; ls -la",
        "hello world",
        "user=john&page=1",
    ]
    for s in samples:
        feats = extract_features(s)
        print(f"\nPayload : {s}")
        print(f"Entropy : {feats[10]:.3f}")
        print(f"Keywords: {feats[19]}")
        print(f"Has SQL : {feats[12]} | XSS: {feats[13]} | RCE: {feats[14]}")