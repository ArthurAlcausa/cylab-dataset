#!/usr/bin/env python3
"""Sam scale batch: many gated py/js/ts synthetic pairs. No VigIA."""
import json, subprocess, tempfile, itertools
from pathlib import Path

ROOT = Path("/workspace/cylab-dataset")
RULES = ROOT / "rules"
SEMGREP = ROOT / ".venv" / "bin" / "semgrep"
OUT = ROOT / "contributions" / "sam-py-js" / "sam_batch5.jsonl"

existing = set()
for p in ROOT.rglob("*.jsonl"):
    if "_raw" in str(p):
        continue
    try:
        for line in p.open():
            try:
                existing.add(json.loads(line)["id"])
            except Exception:
                pass
    except Exception:
        pass

TEMPLATES = []

tables = ["users", "orders", "accounts", "sessions", "payments", "invoices", "tickets", "devices"]
fields = ["email", "name", "id", "sku", "token", "city", "status", "ref"]
for i, (t, f) in enumerate(itertools.product(tables, fields)):
    if i >= 40:
        break
    TEMPLATES.append(dict(
        id=f"cylab-sam-py-sqli-b5-{i:03d}", lang="python", cwe="CWE-89", rule="cylab.python.sql-injection",
        before=f'def q(cur, v):\n    cur.execute(f"SELECT * FROM {t} WHERE {f} = \'{{v}}\'")\n',
        after=f'def q(cur, v):\n    cur.execute("SELECT * FROM {t} WHERE {f} = ?", (v,))\n',
        expl=f"SELECT em {t}.{f} com f-string = SQLi (CWE-89).",
    ))

for i, c in enumerate(["ls", "cat", "grep", "tar", "curl", "wget", "find", "uname", "head", "sort"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-py-cmdi-b5-{i:03d}", lang="python", cwe="CWE-78", rule="cylab.python.command-injection",
        before=f'import subprocess\ndef run(arg):\n    subprocess.call("{c} " + arg, shell=True)\n',
        after=f'import subprocess\ndef run(arg):\n    subprocess.run(["{c}", arg], check=False)\n',
        expl=f"shell=True com {c} (CWE-78).",
    ))

for i, k in enumerate(["api_key", "secret", "password", "token", "auth_token", "access_secret", "db_password", "jwt_secret", "private_key", "client_secret"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-py-secret-b5-{i:03d}", lang="python", cwe="CWE-798", rule="cylab.python.hardcoded-secret",
        before=f'{k} = "hardcoded-value-{i:04d}-CHANGE"\ndef get():\n    return {k}\n',
        after=f'import os\ndef get():\n    return os.environ["{k.upper()}"]\n',
        expl=f"{k} literal (CWE-798).",
    ))

for i, algo in enumerate(["md5", "sha1"]):
    for j in range(6):
        TEMPLATES.append(dict(
            id=f"cylab-sam-py-hash-b5-{i}{j}", lang="python", cwe="CWE-328", rule="cylab.python.weak-hash",
            before=f"import hashlib\ndef h(x):\n    return hashlib.{algo}(x.encode()).hexdigest()\n",
            after="import hashlib\ndef h(x):\n    return hashlib.sha256(x.encode()).hexdigest()\n",
            expl=f"{algo} fraco (CWE-328).",
        ))

for i in range(10):
    TEMPLATES.append(dict(
        id=f"cylab-sam-py-deser-b5-{i:03d}", lang="python", cwe="CWE-502", rule="cylab.python.insecure-deserialization",
        before="import yaml\ndef load(s):\n    return yaml.load(s)\n",
        after="import yaml\ndef load(s):\n    return yaml.safe_load(s)\n",
        expl="yaml.load inseguro (CWE-502).",
    ))

for i, t in enumerate(["users", "posts", "cart", "logs", "files", "jobs", "msgs", "roles", "events", "alerts"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-js-sqli-b5-{i:03d}", lang="javascript", cwe="CWE-89", rule="cylab.javascript.sql-injection",
        before=f'function q(db, id) {{\n  return db.query("SELECT * FROM {t} WHERE id = " + id);\n}}\n',
        after=f'function q(db, id) {{\n  return db.query("SELECT * FROM {t} WHERE id = ?", [id]);\n}}\n',
        expl=f"SQLi em {t} (CWE-89).",
    ))

for i in range(12):
    TEMPLATES.append(dict(
        id=f"cylab-sam-js-xss-b5-{i:03d}", lang="javascript", cwe="CWE-79", rule="cylab.javascript.xss-innerhtml",
        before=f"function show{i}(el, t) {{\n  el.innerHTML = t;\n}}\n",
        after=f"function show{i}(el, t) {{\n  el.textContent = t;\n}}\n",
        expl="innerHTML (CWE-79).",
    ))

for i, k in enumerate(["secretKey", "apiToken", "password", "authSecret", "privateToken", "sessionSecret", "hmacKey", "appSecret"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-js-secret-b5-{i:03d}", lang="javascript", cwe="CWE-798", rule="cylab.javascript.hardcoded-secret",
        before=f'const {k} = "literal-secret-{i}-xx";\nexports.k = {k};\n',
        after=f'const {k} = process.env.{k.upper()};\nif (!{k}) throw new Error("missing");\nexports.k = {k};\n',
        expl=f"{k} literal (CWE-798).",
    ))

for i, c in enumerate(["ls", "cat", "zip", "ping", "whoami", "id", "dig", "nmap"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-js-cmdi-b5-{i:03d}", lang="javascript", cwe="CWE-78", rule="cylab.javascript.command-injection",
        before=f'const {{ exec }} = require("child_process");\nfunction r(a){{ exec("{c} " + a); }}\n',
        after=f'const {{ execFile }} = require("child_process");\nfunction r(a){{ execFile("{c}", [a]); }}\n',
        expl=f"exec {c} (CWE-78).",
    ))

for i in range(10):
    TEMPLATES.append(dict(
        id=f"cylab-sam-js-hash-b5-{i:03d}", lang="javascript", cwe="CWE-328", rule="cylab.javascript.weak-hash",
        before='const crypto=require("crypto");\nfunction h(s){return crypto.createHash("md5").update(s).digest("hex");}\n',
        after='const crypto=require("crypto");\nfunction h(s){return crypto.createHash("sha256").update(s).digest("hex");}\n',
        expl="md5 (CWE-328).",
    ))

for i, t in enumerate(["orders", "customers", "inventory", "shipments", "coupons", "vendors", "warehouses", "returns"]):
    TEMPLATES.append(dict(
        id=f"cylab-sam-ts-sqli-b5-{i:03d}", lang="typescript", cwe="CWE-89", rule="cylab.typescript.sql-injection",
        before=f'export function q(db: any, id: string) {{\n  return db.query("SELECT * FROM {t} WHERE id = \'" + id + "\'");\n}}\n',
        after=f'export function q(db: any, id: string) {{\n  return db.query("SELECT * FROM {t} WHERE id = $1", [id]);\n}}\n',
        expl=f"TS SQLi {t} (CWE-89).",
    ))

for i in range(10):
    TEMPLATES.append(dict(
        id=f"cylab-sam-ts-rand-b5-{i:03d}", lang="typescript", cwe="CWE-338", rule="cylab.typescript.insecure-randomness",
        before=f"export function r{i}(){{ return Math.random().toString(36); }}\n",
        after=f'import {{ randomBytes }} from "crypto";\nexport function r{i}(){{ return randomBytes(16).toString("hex"); }}\n',
        expl="Math.random (CWE-338).",
    ))

for i in range(10):
    TEMPLATES.append(dict(
        id=f"cylab-sam-ts-xss-b5-{i:03d}", lang="typescript", cwe="CWE-79", rule="cylab.typescript.xss-dangerously-set",
        before=f"export const H{i} = ({{ h }}: {{ h: string }}) => <div dangerouslySetInnerHTML={{{{ __html: h }}}} />;\n",
        after=f"export const H{i} = ({{ h }}: {{ h: string }}) => <div>{{h}}</div>;\n",
        expl="dangerouslySetInnerHTML (CWE-79).",
    ))

# cache hits by (rule, code hash) to speed up identical afters
cache = {}

def hits(rule, code, lang):
    key = (rule, code, lang)
    if key in cache:
        return cache[key]
    ext = {"python": ".py", "javascript": ".js", "typescript": ".tsx"}[lang]
    cfg = RULES / f"{rule}.yaml"
    if not cfg.exists():
        cache[key] = -1
        return -1
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / f"s{ext}"
        f.write_text(code)
        r = subprocess.run(
            [str(SEMGREP), "--config", str(cfg), "--quiet", "--json", str(f)],
            capture_output=True, text=True,
        )
        try:
            d = json.loads(r.stdout or "{}")
        except Exception:
            d = {}
        n = len(d.get("results") or [])
        cache[key] = n
        return n

ok = []
fail = 0
for idx, p in enumerate(TEMPLATES):
    if p["id"] in existing:
        continue
    b = hits(p["rule"], p["before"], p["lang"])
    a = hits(p["rule"], p["after"], p["lang"])
    if b >= 1 and a == 0:
        ok.append(dict(
            id=p["id"], lang=p["lang"], cwe=p["cwe"], source="sintetico-cylab", license="CC-BY-4.0",
            opengrep_rule=p["rule"], before=p["before"], after=p["after"],
            explanation_pt=p["expl"], split="train",
            gate={"before_hits": b, "after_hits": a},
        ))
    else:
        fail += 1
        if fail <= 10:
            print("FAIL", p["id"], b, a)
    if (idx + 1) % 30 == 0:
        print(f"progress {idx+1}/{len(TEMPLATES)} ok={len(ok)} fail={fail}")

OUT.parent.mkdir(parents=True, exist_ok=True)
with OUT.open("w") as f:
    for r in ok:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("templates", len(TEMPLATES), "OK", len(ok), "FAIL", fail, "->", OUT)
