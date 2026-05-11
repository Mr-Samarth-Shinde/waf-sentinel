# waf/proxy.py
import sys, os
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from waf.startup import ensure_models
ensure_models()

import sqlite3
import datetime
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests as req_lib
from waf.model_loader import WAFModel

app   = Flask(__name__)
CORS(app)
DB     = "logs/attacks.db"
TARGET = os.environ.get("WAF_TARGET", "http://127.0.0.1:8080")

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    os.makedirs("logs", exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT, ip TEXT, method TEXT, path TEXT,
        payload     TEXT, score REAL, action TEXT, attack_type TEXT
    )""")
    con.commit()
    con.close()

def log_event(ip, method, path, payload, score, action, attack_type):
    con = sqlite3.connect(DB)
    con.execute(
        "INSERT INTO logs (timestamp,ip,method,path,payload,score,action,attack_type) VALUES (?,?,?,?,?,?,?,?)",
        (datetime.datetime.utcnow().isoformat(), ip, method, path, payload, score, action, attack_type)
    )
    con.commit()
    con.close()

# ── Payload extractor ─────────────────────────────────────────────────────────
def extract_payload(r):
    parts = []
    if r.query_string:
        parts.append(r.query_string.decode("utf-8", errors="ignore"))
    if r.content_type and "json" in r.content_type:
        parts.append(r.get_data(as_text=True))
    elif r.form:
        parts.append("&".join(f"{k}={v}" for k, v in r.form.items()))
    else:
        parts.append(r.get_data(as_text=True))
    for h in ["user-agent", "referer", "x-forwarded-for", "cookie"]:
        if h in r.headers:
            parts.append(r.headers[h])
    return " | ".join(filter(None, parts))

# ── OWASP fallback rules ──────────────────────────────────────────────────────
OWASP_RULES = {
    "sqli": ["union select","union all select","' or ","1=1--",
             "sleep(","waitfor delay","benchmark("],
    "xss":  ["<script","javascript:","vbscript:","onerror=",
             "onload=","document.cookie","alert("],
    "lfi":  ["etc/passwd","etc/shadow","boot.ini",
             "../../../../","php://filter","php://input"],
    "rce":  ["cmd.exe","/bin/sh","/bin/bash","|whoami",
             ";whoami","$(whoami)","wget http","curl http"],
    "ssrf": ["127.0.0.1","0.0.0.0","169.254.169.254",
             "http://localhost","https://localhost","file:///",
             "http://127.","https://127.","@127.","@localhost",
             "gopher://","dict://"],
    "xxe":  ["<!entity","<!doctype","cdata["],
}

def owasp_check(payload):
    p = payload.lower()
    for attack_type, patterns in OWASP_RULES.items():
        if any(pat in p for pat in patterns):
            return attack_type
    return None

# ── Main intercept ────────────────────────────────────────────────────────────
@app.before_request
def intercept():
    if request.path.startswith("/waf-dashboard"):
        return None
    payload = extract_payload(request)
    if not payload.strip():
        return None
    ip     = request.remote_addr
    method = request.method
    path   = request.path
    action, score, attack_type = model.predict(payload)
    log_event(ip, method, path, payload, score, action, attack_type)
    if action == "BLOCK":
        print(f"[BLOCK] {ip} | {attack_type.upper()} | score={score}")
        return jsonify({"error":"Request blocked by WAF",
                        "attack_type":attack_type,"score":score,"code":403}), 403
    if action == "REVIEW":
        detected = owasp_check(payload)
        if detected:
            log_event(ip, method, path, payload, score, "BLOCK-OWASP", detected)
            return jsonify({"error":"Blocked by OWASP rules",
                            "attack_type":detected,"score":score,"code":403}), 403
    return None

# ── Proxy forward ─────────────────────────────────────────────────────────────
@app.route("/", defaults={"path":""}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/<path:path>",            methods=["GET","POST","PUT","DELETE","PATCH"])
def proxy(path):
    try:
        resp = req_lib.request(
            method=request.method, url=f"{TARGET}/{path}",
            headers={k:v for k,v in request.headers if k.lower()!="host"},
            data=request.get_data(), params=request.args,
            timeout=10, allow_redirects=False)
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
    except req_lib.exceptions.ConnectionError:
        return jsonify({"message":"WAF active — backend offline"}), 200

# ── Dashboard API ─────────────────────────────────────────────────────────────
@app.route("/waf-dashboard/logs")
def api_logs():
    con  = sqlite3.connect(DB)
    rows = con.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    con.close()
    keys = ["id","timestamp","ip","method","path","payload","score","action","attack_type"]
    return jsonify([dict(zip(keys,r)) for r in rows])

@app.route("/waf-dashboard/stats")
def api_stats():
    con     = sqlite3.connect(DB)
    total   = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    blocked = con.execute("SELECT COUNT(*) FROM logs WHERE action LIKE 'BLOCK%'").fetchone()[0]
    by_type = con.execute("SELECT attack_type, COUNT(*) FROM logs GROUP BY attack_type").fetchall()
    recent  = con.execute("SELECT timestamp, action FROM logs ORDER BY id DESC LIMIT 50").fetchall()
    con.close()
    return jsonify({"total":total,"blocked":blocked,"allowed":total-blocked,
                    "by_type":dict(by_type),
                    "recent":[{"timestamp":r[0],"action":r[1]} for r in recent]})

@app.route("/waf-dashboard/test", methods=["POST"])
def api_test():
    payload = (request.json or {}).get("payload","")
    if not payload:
        return jsonify({"error":"No payload provided"}), 400
    action, score, attack_type = model.predict(payload)
    return jsonify({"payload":payload,"action":action,"score":score,
                    "attack_type":attack_type,"blocked":action in("BLOCK","REVIEW")})

@app.route("/waf-dashboard/health")
def health():
    return jsonify({"status":"ok","version":"1.0","models":["rf","xgb"]})

# ── Initialize on startup (works for both gunicorn and direct run) ────────────
init_db()
model = WAFModel()
model.load()

# ── Direct run ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*55}")
    print(f"  WAF Proxy    → http://0.0.0.0:{port}")
    print(f"  Dashboard    → http://localhost:{port}/waf-dashboard/stats")
    print(f"{'='*55}\n")
    app.run(host="0.0.0.0", port=port, debug=False)