#!/usr/bin/env python3
"""Sam batch6: diverse py/js/ts pairs (less near-clone)."""
import json, subprocess, tempfile, textwrap
from pathlib import Path

ROOT = Path("/workspace/cylab-dataset")
RULES = ROOT / "rules"
SEMGREP = ROOT / ".venv" / "bin" / "semgrep"
OUT = ROOT / "contributions" / "sam-py-js" / "sam_batch6.jsonl"

# Ensure extra rules exist
EXTRA = {
"cylab.python.ssl-verify-false.yaml": """
rules:
  - id: cylab.python.ssl-verify-false
    message: TLS verify disabled
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: requests.get(..., verify=False, ...)
      - pattern: requests.post(..., verify=False, ...)
""",
"cylab.python.log-secret.yaml": """
rules:
  - id: cylab.python.log-secret
    message: logging password
    severity: ERROR
    languages: [python]
    pattern: logging.info(..., $P, ...)
    metavariable-regex:
      metavariable: $P
      regex: (?i).*(password|senha|secret|token).*
""",
"cylab.javascript.disable-tls.yaml": """
rules:
  - id: cylab.javascript.disable-tls
    message: rejectUnauthorized false
    severity: ERROR
    languages: [javascript]
    pattern: "rejectUnauthorized: false"
""",
"cylab.javascript.eval-user.yaml": """
rules:
  - id: cylab.javascript.eval-user
    message: eval
    severity: ERROR
    languages: [javascript]
    pattern: eval(...)
""",
"cylab.python.assert-auth.yaml": """
rules:
  - id: cylab.python.assert-auth
    message: assert auth
    severity: ERROR
    languages: [python]
    pattern: assert $U.is_admin
""",
"cylab.python.flask-debug.yaml": """
rules:
  - id: cylab.python.flask-debug
    message: flask debug
    severity: ERROR
    languages: [python]
    pattern: app.run(..., debug=True, ...)
""",
"cylab.javascript.cors-star.yaml": """
rules:
  - id: cylab.javascript.cors-star
    message: cors star
    severity: ERROR
    languages: [javascript]
    pattern: res.setHeader("Access-Control-Allow-Origin", "*")
""",
"cylab.python.xml-xxe.yaml": """
rules:
  - id: cylab.python.xml-xxe
    message: xxe
    severity: ERROR
    languages: [python]
    pattern: etree.parse($X)
""",
}
for name, body in EXTRA.items():
    p = RULES / name
    if not p.exists():
        p.write_text(textwrap.dedent(body).lstrip())

existing = set()
for p in ROOT.rglob("*.jsonl"):
    if "_raw" in str(p):
        continue
    for line in p.open():
        try:
            existing.add(json.loads(line)["id"])
        except Exception:
            pass

P = []

def add(**kw):
    P.append(kw)

# --- diverse Python ---
for i, lib in enumerate(["urlopen", "Request"]):
    add(id=f"cylab-sam-py-ssrf-b6-{i}", lang="python", cwe="CWE-918", rule="cylab.python.ssrf",
        before=f"import urllib.request\ndef fetch(u):\n    return urllib.request.{lib}(u).read() if False else urllib.request.urlopen(u).read()\n" if lib=="urlopen" else
        "import urllib.request\ndef fetch(u):\n    return urllib.request.urlopen(urllib.request.Request(u)).read()\n",
        after="import urllib.request\nfrom urllib.parse import urlparse\nOK={'api.example.com'}\ndef fetch(u):\n    if urlparse(u).hostname not in OK: raise ValueError('no')\n    return urllib.request.urlopen(u, timeout=5).read()\n",
        expl="SSRF via urllib (CWE-918).")

for i in range(8):
    add(id=f"cylab-sam-py-ssrf-req-b6-{i}", lang="python", cwe="CWE-918", rule="cylab.python.ssrf",
        before=f"import requests\ndef p{i}(url):\n    return requests.get(url).text\n",
        after=f"import requests\nfrom urllib.parse import urlparse\nOK={{'cdn.example.com'}}\ndef p{i}(url):\n    if urlparse(url).hostname not in OK: raise ValueError('no')\n    return requests.get(url, timeout=5).text\n",
        expl="requests.get URL user (CWE-918).")

for i, path in enumerate(["uploads", "static", "data", "tmp", "reports", "exports", "avatars", "docs"]):
    add(id=f"cylab-sam-py-path-b6-{i}", lang="python", cwe="CWE-22", rule="cylab.python.path-traversal",
        before=f"import os\ndef read_{i}(name):\n    return open(os.path.join('{path}', name)).read()\n",
        after=f"from pathlib import Path\ndef read_{i}(name):\n    root=Path('{path}').resolve()\n    t=(root/name).resolve()\n    if not str(t).startswith(str(root)): raise ValueError('trav')\n    return t.read_text()\n",
        expl=f"path join {path} (CWE-22).")

for i in range(6):
    add(id=f"cylab-sam-py-ssl-b6-{i}", lang="python", cwe="CWE-295", rule="cylab.python.ssl-verify-false",
        before=f"import requests\ndef g{i}(url):\n    return requests.get(url, verify=False)\n",
        after=f"import requests\ndef g{i}(url):\n    return requests.get(url, timeout=5)\n",
        expl="verify=False (CWE-295).")

for i in range(6):
    add(id=f"cylab-sam-py-debug-b6-{i}", lang="python", cwe="CWE-489", rule="cylab.python.flask-debug",
        before=f"app.run(host='0.0.0.0', port={8000+i}, debug=True)\n",
        after=f"import os\napp.run(host='0.0.0.0', port={8000+i}, debug=os.getenv('DEBUG')=='1')\n",
        expl="Flask debug=True (CWE-489).")

for i in range(6):
    add(id=f"cylab-sam-py-assert-b6-{i}", lang="python", cwe="CWE-617", rule="cylab.python.assert-auth",
        before=f"def admin_action_{i}(user):\n    assert user.is_admin\n    return True\n",
        after=f"def admin_action_{i}(user):\n    if not user.is_admin: raise PermissionError('no')\n    return True\n",
        expl="assert auth (CWE-617).")

for i in range(5):
    add(id=f"cylab-sam-py-xxe-b6-{i}", lang="python", cwe="CWE-611", rule="cylab.python.xml-xxe",
        before=f"from lxml import etree\ndef parse_{i}(p):\n    return etree.parse(p)\n",
        after=f"from lxml import etree\ndef parse_{i}(p):\n    return etree.parse(p, etree.XMLParser(resolve_entities=False, no_network=True))\n",
        expl="XXE etree.parse (CWE-611).")

for i, meth in enumerate(["execute", "executemany"]):
    for j, op in enumerate(["DELETE", "UPDATE", "INSERT INTO t(a) VALUES"]):
        # only execute patterns match bill rule well for f-string
        if meth != "execute":
            continue
        add(id=f"cylab-sam-py-sqli-b6-{i}{j}", lang="python", cwe="CWE-89", rule="cylab.python.sql-injection",
            before=f'def q(cur, v):\n    cur.execute(f"{op} {{v}}")\n' if "VALUES" not in op else f'def q(cur, v):\n    cur.execute(f"INSERT INTO t(a) VALUES (\'{{v}}\')")\n',
            after='def q(cur, v):\n    cur.execute("SELECT 1 WHERE x=?", (v,))\n',
            expl="SQL f-string (CWE-89).")

# more distinct SQLi with % and format and +
for i, style in enumerate(["pct", "fmt", "plus"]):
    for j in range(5):
        if style == "pct":
            b=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = %s" % v)\n'
            a=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = %s", (v,))\n'
        elif style == "fmt":
            b=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = {{}}".format(v))\n'
            a=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = ?", (v,))\n'
        else:
            b=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = " + v)\n'
            a=f'def q{j}(cur, v):\n    cur.execute("SELECT * FROM t{j} WHERE id = ?", (v,))\n'
        add(id=f"cylab-sam-py-sqli-{style}-b6-{j}", lang="python", cwe="CWE-89", rule="cylab.python.sql-injection", before=b, after=a, expl=f"SQLi {style} (CWE-89).")

for i, shellcmd in enumerate(["os.system", "subprocess.call"]):
    for j, c in enumerate(["ping", "nslookup", "traceroute", "host"]):
        if shellcmd == "os.system":
            b=f'import os\ndef r{j}(h):\n    os.system("{c} " + h)\n'
            a=f'import subprocess\ndef r{j}(h):\n    subprocess.run(["{c}", h], check=False)\n'
            rule="cylab.python.command-injection"
        else:
            b=f'import subprocess\ndef r{j}(h):\n    subprocess.call("{c} " + h, shell=True)\n'
            a=f'import subprocess\ndef r{j}(h):\n    subprocess.run(["{c}", h], check=False)\n'
            rule="cylab.python.command-injection"
        add(id=f"cylab-sam-py-cmdi-{i}-{j}-b6", lang="python", cwe="CWE-78", rule=rule, before=b, after=a, expl=f"cmdi {c} (CWE-78).")

for i, k in enumerate(["stripe_secret", "openai_api_key", "sendgrid_password", "slack_token", "github_secret", "aws_secret"]):
    add(id=f"cylab-sam-py-sec-b6-{i}", lang="python", cwe="CWE-798", rule="cylab.python.hardcoded-secret",
        before=f'{k} = "sk_live_example_{i}_xxxxxxxx"\ndef cfg():\n    return {k}\n',
        after=f'import os\ndef cfg():\n    return os.environ["{k.upper()}"]\n',
        expl=f"{k} hardcoded (CWE-798).")

for i in range(8):
    add(id=f"cylab-sam-py-pickle-b6-{i}", lang="python", cwe="CWE-502", rule="cylab.python.insecure-deserialization",
        before=f"import pickle\ndef load{i}(b):\n    return pickle.loads(b)\n",
        after=f"import json\ndef load{i}(b):\n    return json.loads(b)\n",
        expl="pickle.loads (CWE-502).")

for i in range(6):
    add(id=f"cylab-sam-py-yaml-b6-{i}", lang="python", cwe="CWE-502", rule="cylab.python.insecure-deserialization",
        before=f"import yaml\ndef y{i}(s):\n    return yaml.load(s)\n",
        after=f"import yaml\ndef y{i}(s):\n    return yaml.safe_load(s)\n",
        expl="yaml.load (CWE-502).")

for i, algo in enumerate(["md5", "sha1"]):
    for j in range(4):
        add(id=f"cylab-sam-py-hash-b6-{algo}-{j}", lang="python", cwe="CWE-328", rule="cylab.python.weak-hash",
            before=f"import hashlib\ndef d{j}(x):\n    return hashlib.{algo}(x).hexdigest()\n",
            after=f"import hashlib\ndef d{j}(x):\n    return hashlib.sha256(x).hexdigest()\n",
            expl=f"{algo} (CWE-328).")

# --- JS diverse ---
for i in range(8):
    add(id=f"cylab-sam-js-eval-b6-{i}", lang="javascript", cwe="CWE-95", rule="cylab.javascript.eval-user",
        before=f"function run{i}(expr) {{ return eval(expr); }}\n",
        after=f"function run{i}(expr) {{\n  if (!/^[0-9+\\-*/().\\s]+$/.test(expr)) throw new Error('bad');\n  return Function('\"use strict\"; return (' + expr + ')')();\n}}\n",
        expl="eval (CWE-95).")

for i in range(8):
    add(id=f"cylab-sam-js-cors-b6-{i}", lang="javascript", cwe="CWE-942", rule="cylab.javascript.cors-star",
        before=f"function cors{i}(res) {{ res.setHeader(\"Access-Control-Allow-Origin\", \"*\"); }}\n",
        after=f"function cors{i}(res, o) {{ if (o === \"https://app.example.com\") res.setHeader(\"Access-Control-Allow-Origin\", o); }}\n",
        expl="CORS * (CWE-942).")

for i in range(6):
    add(id=f"cylab-sam-js-tls-b6-{i}", lang="javascript", cwe="CWE-295", rule="cylab.javascript.disable-tls",
        before=f"const https = require('https');\nconst a{i} = new https.Agent({{ rejectUnauthorized: false }});\n",
        after=f"const https = require('https');\nconst a{i} = new https.Agent({{ rejectUnauthorized: true }});\n",
        expl="rejectUnauthorized false (CWE-295).")

for i, t in enumerate(["accounts", "ledger", "audit", "billing", "catalog", "inbox", "notify", "prefs"]):
    add(id=f"cylab-sam-js-sqli-b6-{i}", lang="javascript", cwe="CWE-89", rule="cylab.javascript.sql-injection",
        before=f"function q(db, x) {{ return db.query(`SELECT * FROM {t} WHERE k = '${{x}}'`); }}\n",
        after=f"function q(db, x) {{ return db.query('SELECT * FROM {t} WHERE k = ?', [x]); }}\n",
        expl=f"JS SQLi {t} (CWE-89).")

for i in range(8):
    add(id=f"cylab-sam-js-xss-b6-{i}", lang="javascript", cwe="CWE-79", rule="cylab.javascript.xss-innerhtml",
        before=f"function paint{i}(node, html) {{ node.innerHTML = html; }}\n",
        after=f"function paint{i}(node, text) {{ node.textContent = text; }}\n",
        expl="innerHTML (CWE-79).")

for i, c in enumerate(["ffmpeg", "convert", "sox", "jq", "yq", "rg"]):
    add(id=f"cylab-sam-js-cmdi-b6-{i}", lang="javascript", cwe="CWE-78", rule="cylab.javascript.command-injection",
        before=f'const {{ exec }} = require("child_process");\nfunction r(a){{ exec("{c} " + a); }}\n',
        after=f'const {{ execFile }} = require("child_process");\nfunction r(a){{ execFile("{c}", [a]); }}\n',
        expl=f"exec {c} (CWE-78).")

for i, k in enumerate(["stripeSecret", "webhookSecret", "cookieSecret", "oauthSecret", "encryptKey", "signingKey"]):
    add(id=f"cylab-sam-js-sec-b6-{i}", lang="javascript", cwe="CWE-798", rule="cylab.javascript.hardcoded-secret",
        before=f'const {k} = "prod-secret-value-{i}";\nmodule.exports = {{ {k} }};\n',
        after=f'const {k} = process.env.{k.upper()};\nif (!{k}) throw new Error("missing");\nmodule.exports = {{ {k} }};\n',
        expl=f"{k} literal (CWE-798).")

for i in range(6):
    add(id=f"cylab-sam-js-path-b6-{i}", lang="javascript", cwe="CWE-22", rule="cylab.javascript.path-traversal",
        before=f'const path=require("path"); const fs=require("fs");\nfunction r{i}(n){{ return fs.readFileSync(path.join("/var/data", n), "utf8"); }}\n',
        after=f'const path=require("path"); const fs=require("fs");\nfunction r{i}(n){{\n  const root=path.resolve("/var/data");\n  const full=path.resolve(root, n);\n  if (!full.startsWith(root+path.sep)) throw new Error("trav");\n  return fs.readFileSync(full, "utf8");\n}}\n',
        expl="path traversal (CWE-22).")

# --- TS ---
for i, t in enumerate(["subscriptions", "entitlements", "features", "quotas", "tenants", "workspaces"]):
    add(id=f"cylab-sam-ts-sqli-b6-{i}", lang="typescript", cwe="CWE-89", rule="cylab.typescript.sql-injection",
        before=f'export function q(db: any, id: string) {{ return db.query("SELECT * FROM {t} WHERE id=\'" + id + "\'"); }}\n',
        after=f'export function q(db: any, id: string) {{ return db.query("SELECT * FROM {t} WHERE id=$1", [id]); }}\n',
        expl=f"TS SQLi {t} (CWE-89).")

for i in range(8):
    add(id=f"cylab-sam-ts-rand-b6-{i}", lang="typescript", cwe="CWE-338", rule="cylab.typescript.insecure-randomness",
        before=f"export function nonce{i}() {{ return Math.random().toString(16); }}\n",
        after=f'import {{ randomBytes }} from "crypto";\nexport function nonce{i}() {{ return randomBytes(16).toString("hex"); }}\n',
        expl="Math.random (CWE-338).")

for i in range(8):
    add(id=f"cylab-sam-ts-xss-b6-{i}", lang="typescript", cwe="CWE-79", rule="cylab.typescript.xss-dangerously-set",
        before=f"export const Box{i} = ({{ html }}: {{ html: string }}) => <section dangerouslySetInnerHTML={{{{ __html: html }}}} />;\n",
        after=f"export const Box{i} = ({{ html }}: {{ html: string }}) => <section>{{html}}</section>;\n",
        expl="dangerouslySetInnerHTML (CWE-79).")

for i in range(6):
    add(id=f"cylab-sam-ts-redir-b6-{i}", lang="typescript", cwe="CWE-601", rule="cylab.typescript.open-redirect",
        before=f"export function go{i}(res: any, next: string) {{ res.redirect(next); }}\n",
        after=f"export function go{i}(res: any, next: string) {{\n  if (!next.startsWith('/') || next.startsWith('//')) throw new Error('bad');\n  res.redirect(next);\n}}\n",
        expl="open redirect (CWE-601).")

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
        r = subprocess.run([str(SEMGREP), "--config", str(cfg), "--quiet", "--json", str(f)], capture_output=True, text=True)
        try:
            d = json.loads(r.stdout or "{}")
        except Exception:
            d = {}
        n = len(d.get("results") or [])
        cache[key] = n
        return n

ok, fail = [], 0
for idx, p in enumerate(P):
    if p["id"] in existing:
        continue
    b = hits(p["rule"], p["before"], p["lang"])
    a = hits(p["rule"], p["after"], p["lang"])
    if b >= 1 and a == 0:
        ok.append(dict(id=p["id"], lang=p["lang"], cwe=p["cwe"], source="sintetico-cylab", license="CC-BY-4.0",
            opengrep_rule=p["rule"], before=p["before"], after=p["after"], explanation_pt=p["expl"], split="train",
            gate={"before_hits": b, "after_hits": a}))
    else:
        fail += 1
        if fail <= 15:
            print("FAIL", p["id"], b, a)
    if (idx + 1) % 40 == 0:
        print(f"progress {idx+1}/{len(P)} ok={len(ok)}")

with OUT.open("w") as f:
    for r in ok:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("candidates", len(P), "OK", len(ok), "FAIL", fail, "->", OUT)
