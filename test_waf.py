# test_waf.py
import requests

BASE = "http://localhost:5000"

tests = [
    ("SQLi basic",        "' OR 1=1--",                        "BLOCK"),
    ("SQLi UNION",        "1 UNION SELECT * FROM users",        "BLOCK"),
    ("XSS script tag",    "<script>alert('xss')</script>",      "BLOCK"),
    ("XSS onerror",       "<img src=x onerror=alert(1)>",       "BLOCK"),
    ("LFI traversal",     "../../etc/passwd",                   "BLOCK"),
    ("RCE whoami",        ";whoami",                            "BLOCK"),
    ("SSRF localhost",    "http://127.0.0.1/admin",             "BLOCK"),
    ("Benign search",     "?q=python+tutorial",                 "ALLOW"),
    ("Benign login",      "?username=john&password=pass123",    "ALLOW"),
    ("Benign pagination", "?page=1&limit=20&sort=date",         "ALLOW"),
    ("Benign product",    "?id=42&category=electronics",        "ALLOW"),
]

print("=" * 70)
print(f"  {'Test':<25} {'Expected':<10} {'Got':<8} {'Score':<8} {'Status'}")
print("=" * 70)

passed = failed = 0
for desc, payload, expected in tests:
    try:
        r = requests.post(
            f"{BASE}/waf-dashboard/test",
            json={"payload": payload},
            timeout=5
        )
        data   = r.json()
        action = data.get("action", "?")
        score  = data.get("score", 0)
        ok     = "✅" if action == expected else "❌"
        if action == expected: passed += 1
        else:                  failed += 1
        print(f"  {desc:<25} {expected:<10} {action:<8} {score:<8} {ok}")
    except Exception as e:
        print(f"  {desc:<25} ERROR: {e}")
        failed += 1

print("=" * 70)
print(f"  Results: {passed} passed, {failed} failed out of {len(tests)} tests")
print("=" * 70)

print("\n── False Positive Check ─────────────────────────────────────────────")
fp_tests = [
    "?name=john&page=1",
    "?min=10&max=500&category=shoes",
    "?lang=en&region=US&uid=42",
]
for p in fp_tests:
    try:
        r = requests.post(f"{BASE}/waf-dashboard/test", json={"payload": p}, timeout=5)
        d = r.json()
        flag = "✅ ALLOW" if d["action"] == "ALLOW" else f"⚠️  {d['action']} (score={d['score']})"
        print(f"  {p:<45} {flag}")
    except Exception as e:
        print(f"  {p:<45} ERROR: {e}")