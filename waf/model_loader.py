# waf/model_loader.py
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath("."))

import joblib
import scipy.sparse as sp

BENIGN_KEYWORDS = [
    "tutorial", "search", "page=", "limit=", "sort=", "lang=",
    "python", "java", "category", "product", "filter", "region",
    "name=", "user=", "email=", "id=", "q=", "min=", "max="
]

ATTACK_KEYWORDS = [
    "select", "union", "script", "alert", "passwd", "whoami",
    "exec", "drop", "onerror", "javascript", "../", "127.0.0.1",
    "entity", "cmd", "wget", "curl", "sleep(", "1=1", "--",
    "localhost", "169.254", "0.0.0.0", "file:///", "gopher://"
]

SSRF_PATTERNS = [
    "127.0.0.1", "localhost", "169.254", "0.0.0.0",
    "file:///", "gopher://", "http://127.", "https://127.", "@127."
]


class WAFModel:
    def __init__(self):
        self.rf           = None
        self.xgb          = None
        self.preprocessor = None
        self.config       = None
        self.loaded       = False

    def load(self, model_dir="models"):
        print("[*] Loading WAF models...")
        sys.path.insert(0, os.path.abspath("."))
        self.rf           = joblib.load(f"{model_dir}/rf_model.pkl")
        self.xgb          = joblib.load(f"{model_dir}/xgb_model.pkl")
        self.preprocessor = joblib.load(f"{model_dir}/preprocessor.pkl")
        self.config       = joblib.load(f"{model_dir}/ensemble_config.pkl")
        self.loaded       = True
        print("[+] Models loaded!")

    def predict(self, payload):
        if not self.loaded:
            raise RuntimeError("Call load() first")

        feats   = self.preprocessor.transform([payload])
        feats_d = feats.toarray() if sp.issparse(feats) else feats

        rf_s  = float(self.rf.predict_proba(feats_d)[0][1])
        xgb_s = float(self.xgb.predict_proba(feats_d)[0][1])
        score = rf_s * 0.5 + xgb_s * 0.5

        p_lower    = payload.lower()
        has_attack = any(k in p_lower for k in ATTACK_KEYWORDS)
        benign_hits = sum(1 for k in BENIGN_KEYWORDS if k in p_lower)

        # reduce score only if no attack signals
        if not has_attack and benign_hits >= 1:
            score = score * 0.55

        # boost score for SSRF patterns the model undersees
        if any(k in p_lower for k in SSRF_PATTERNS):
            score = max(score, 0.80)

        if score >= 0.75:
            action = "BLOCK"
        elif score >= 0.65:
            action = "REVIEW"
        else:
            action = "ALLOW"

        return action, round(score, 4), self._attack_type(payload)

    def _attack_type(self, payload):
        p = payload.lower()
        if any(k in p for k in ["select","union","drop","--","1=1","sleep("]):  return "sqli"
        if any(k in p for k in ["<script","onerror","alert(","javascript:"]):   return "xss"
        if any(k in p for k in ["../","etc/passwd","php://"]):                  return "lfi"
        if any(k in p for k in ["cmd","whoami","/bin/","wget ","curl "]):       return "rce"
        if any(k in p for k in ["127.0.0.1","localhost","169.254","0.0.0.0"]): return "ssrf"
        if any(k in p for k in ["<!entity","xmlns","cdata"]):                   return "xxe"
        if any(k in p for k in [" && "," | ","` ","$("]):                      return "cmdi"
        return "benign"


if __name__ == "__main__":
    waf = WAFModel()
    waf.load()

    tests = [
        ("' OR 1=1--",                    "SQLi"),
        ("<script>alert('xss')</script>", "XSS"),
        ("../../etc/passwd",              "LFI"),
        (";whoami",                       "RCE"),
        ("http://127.0.0.1/admin",        "SSRF"),
        ("?q=python+tutorial",            "Benign"),
        ("?name=john&page=1",             "Benign"),
    ]

    print(f"\n{'Payload':<40} {'Expected':<10} {'Action':<8} {'Score'}")
    print("─" * 70)
    for payload, expected in tests:
        action, score, atype = waf.predict(payload)
        flag = "✅" if (action != "ALLOW") == (expected != "Benign") else "❌"
        print(f"{payload:<40} {expected:<10} {action:<8} {score} {flag}")