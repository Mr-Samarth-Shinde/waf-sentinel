import os, csv, random, hashlib

PAYLOADS_DIR = "data/raw_payloads"
OUTPUT_FILE = "data/processed/dataset.csv"
os.makedirs("data/processed", exist_ok=True)

# Attack type - folder keywords to search

ATTACK_MAP = {
    "sqli": ["SQL","sql","SQLi","sqli","Injection"],
    "xss":  ["XSS","xss","Cross-Site"],
    "rce":  ["RCE","rce","Remote-Code","Command"],
    "lfi":  ["LFI","lfi","File-Inclusion","Path-Traversal"],
    "ssrf": ["SSRF","ssrf","Server-Side"],
    "xxe":  ["XXE","xxe","XML"],
    "cmdinjection":["Command-Injection","Shell","shell"],
}

rows = []
seen = set()

def add(payload, label, attack_type):
    h = hashlib.md5(payload.encode()).hexdigest()
    if h in seen or not payload.strip():
        return
    seen.add(h)
    rows.append({"payload": payload.strip(),"label":label,"attack_type":attack_type})

    # 1. Collect malicious payloads from cloned repos

for root, dirs, files in os.walk(PAYLOADS_DIR):
    for fname in files:
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(root, fname)
        attack_type = "unknown"
        for atype, keywords in ATTACK_MAP.items():
            if any(kw.lower() in fpath.lower() for kw in keywords):
                attack_type = atype
                break
        if attack_type == "unknown":
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        add(line, 1, attack_type)
        except Exception:
            pass

print(f"[+] Malicious payloads collected: {len(rows)}")

# ── 2. Generate realistic benign traffic samples ──────────────────────────────
BENIGN_TEMPLATES = [
    "SELECT * FROM products WHERE id={n}",
    "username=user{n}&password=pass{n}",
    "search={word}&page={n}",
    "id={n}&category=electronics",
    "name=John{n}&email=john{n}@gmail.com",
    "q=python+tutorial+{n}",
    "filter=price&min={n}&max={n2}",
    "token=abcdef{n}xyz&action=view",
    "file=report_{n}.pdf",
    "lang=en&region=US&uid={n}",
    "/home", "/about", "/contact", "/products", "/login",
    "user_id={n}&role=student",
    "comment=Great+post+number+{n}!",
    "page=1&limit=20&sort=date",
]
WORDS = ["apple","banana","laptop","phone","book","shirt","shoes","table","chair","camera"]

benign_target = len(rows)  # match malicious count for balance
added_benign  = 0
while added_benign < benign_target:
    t = random.choice(BENIGN_TEMPLATES)
    n  = random.randint(1, 99999)
    n2 = n + random.randint(10, 500)
    w  = random.choice(WORDS)
    payload = t.format(n=n, n2=n2, word=w) if "{" in t else t
    add(payload, 0, "benign")
    added_benign += 1

print(f"[+] Benign samples generated: {added_benign}")

# ── 3. Shuffle and save ───────────────────────────────────────────────────────
random.shuffle(rows)
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["payload","label","attack_type"])
    writer.writeheader()
    writer.writerows(rows)

print(f"\n✅ Dataset saved → {OUTPUT_FILE}")
print(f"   Total rows  : {len(rows)}")
malicious = sum(1 for r in rows if r['label']=='1' or r['label']==1)
benign    = len(rows) - malicious
print(f"   Malicious   : {malicious}")
print(f"   Benign      : {benign}")

# ── 4. Show attack type breakdown ────────────────────────────────────────────
from collections import Counter
counts = Counter(r['attack_type'] for r in rows)
print("\n── Attack type breakdown ──")
for k,v in counts.most_common():
    print(f"   {k:<20} {v}")