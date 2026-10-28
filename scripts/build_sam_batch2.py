#!/usr/bin/env python3
"""Sam batch2: fix 3 gold + new py/js/ts pairs. Uses rules/ (Bill) + new rules. No VigIA."""
import json, subprocess, tempfile, textwrap
from pathlib import Path

ROOT = Path("/workspace/cylab-dataset")
RULES = ROOT / "rules"
OUT = ROOT / "contributions" / "sam-py-js" / "sam_batch2.jsonl"
SEMGREP = ROOT / ".venv" / "bin" / "semgrep"

# New rules for gaps
NEW_RULES = {
    "cylab.python.xml-xxe.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.python.xml-xxe
            message: "XML parser com entidades externas (CWE-611)"
            severity: ERROR
            languages: [python]
            metadata: {cwe: "CWE-611", source: sintetico-cylab}
            pattern: etree.parse($X)
        """),
    "cylab.python.flask-debug.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.python.flask-debug
            message: "Flask debug em producao (CWE-489)"
            severity: ERROR
            languages: [python]
            metadata: {cwe: "CWE-489", source: sintetico-cylab}
            pattern: app.run(..., debug=True, ...)
        """),
    "cylab.python.assert-auth.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.python.assert-auth
            message: "assert para autorizacao (CWE-617)"
            severity: ERROR
            languages: [python]
            metadata: {cwe: "CWE-617", source: sintetico-cylab}
            pattern: |
              assert $USER.is_admin
        """),
    "cylab.javascript.react-href.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.javascript.react-href
            message: "href com javascript: (CWE-79)"
            severity: ERROR
            languages: [javascript, typescript]
            metadata: {cwe: "CWE-79", source: sintetico-cylab}
            pattern-regex: 'href\\s*=\\s*\\{[^}]*\\}'
        """),
    "cylab.javascript.cors-star.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.javascript.cors-star
            message: "CORS *"
            severity: ERROR
            languages: [javascript]
            metadata: {cwe: "CWE-942", source: sintetico-cylab}
            pattern: res.setHeader("Access-Control-Allow-Origin", "*")
        """),
    "cylab.typescript.any-req-body.yaml": textwrap.dedent("""\
        rules:
          - id: cylab.typescript.any-req-body
            message: "req.body sem validacao tipada"
            severity: ERROR
            languages: [typescript]
            metadata: {cwe: "CWE-20", source: sintetico-cylab}
            pattern: |
              const $X: any = req.body
        """),
}

PAIRS = [
  # --- fixed 3 (aligned to Bill rules) ---
  {
    "id": "cylab-sam-py-sqli-002",
    "lang": "python",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.python.sql-injection",
    "before": 'import sqlite3\n\ndef by_name(conn, name):\n    cur = conn.cursor()\n    cur.execute(f"SELECT id FROM people WHERE name = \'{name}\'")\n    return cur.fetchall()\n',
    "after": 'import sqlite3\n\ndef by_name(conn, name):\n    cur = conn.cursor()\n    cur.execute("SELECT id FROM people WHERE name = ?", (name,))\n    return cur.fetchall()\n',
    "explanation_pt": "f-string no execute permite SQL injection (CWE-89). Use placeholder e tupla de parâmetros.",
  },
  {
    "id": "cylab-sam-py-secret-002",
    "lang": "python",
    "cwe": "CWE-798",
    "opengrep_rule": "cylab.python.hardcoded-secret",
    "before": 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n\ndef creds():\n    return {"secret": aws_secret}\n',
    "after": 'import os\n\ndef creds():\n    return {"secret": os.environ["AWS_SECRET_ACCESS_KEY"]}\n',
    "explanation_pt": "Segredo AWS no código (CWE-798). Use variável de ambiente ou IAM role.",
  },
  {
    "id": "cylab-sam-js-secret-002",
    "lang": "javascript",
    "cwe": "CWE-798",
    "opengrep_rule": "cylab.javascript.hardcoded-secret",
    "before": 'const apiToken = "ghp_exampleHardcodedToken000000";\n\nfunction headers() {\n  return { Authorization: "Bearer " + apiToken };\n}\n',
    "after": 'function headers() {\n  const apiToken = process.env.API_TOKEN;\n  if (!apiToken) throw new Error("API_TOKEN missing");\n  return { Authorization: "Bearer " + apiToken };\n}\n',
    "explanation_pt": "Token hardcoded (CWE-798). Leia de process.env.",
  },
  # --- new diversity ---
  {
    "id": "cylab-sam-py-xxe-001",
    "lang": "python",
    "cwe": "CWE-611",
    "opengrep_rule": "cylab.python.xml-xxe",
    "before": 'from lxml import etree\n\ndef parse_upload(path):\n    return etree.parse(path)\n',
    "after": 'from lxml import etree\n\ndef parse_upload(path):\n    parser = etree.XMLParser(resolve_entities=False, no_network=True)\n    return etree.parse(path, parser)\n',
    "explanation_pt": "Parser XML padrão pode resolver entidades externas (XXE, CWE-611). Desative entidades e rede.",
  },
  {
    "id": "cylab-sam-py-debug-001",
    "lang": "python",
    "cwe": "CWE-489",
    "opengrep_rule": "cylab.python.flask-debug",
    "before": 'from flask import Flask\napp = Flask(__name__)\n\nif __name__ == "__main__":\n    app.run(host="0.0.0.0", debug=True)\n',
    "after": 'from flask import Flask\nimport os\napp = Flask(__name__)\n\nif __name__ == "__main__":\n    app.run(host="0.0.0.0", debug=os.getenv("FLASK_DEBUG") == "1")\n',
    "explanation_pt": "debug=True expõe interactive debugger (CWE-489). Só ative via config explícita de ambiente.",
  },
  {
    "id": "cylab-sam-py-assert-001",
    "lang": "python",
    "cwe": "CWE-617",
    "opengrep_rule": "cylab.python.assert-auth",
    "before": 'def delete_all(user):\n    assert user.is_admin\n    return wipe_db()\n',
    "after": 'def delete_all(user):\n    if not user.is_admin:\n        raise PermissionError("admin only")\n    return wipe_db()\n',
    "explanation_pt": "assert some com -O e não é controle de acesso (CWE-617). Use if + exceção.",
  },
  {
    "id": "cylab-sam-py-sqli-like-001",
    "lang": "python",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.python.sql-injection",
    "before": 'def search(conn, term):\n    conn.execute("SELECT * FROM docs WHERE title LIKE \'%" + term + "%\'")\n',
    "after": 'def search(conn, term):\n    conn.execute("SELECT * FROM docs WHERE title LIKE ?", (f"%{term}%",))\n',
    "explanation_pt": "LIKE com concatenação ainda é SQLi (CWE-89). Bind o padrão inteiro como parâmetro.",
  },
  {
    "id": "cylab-sam-py-cmdi-shell-001",
    "lang": "python",
    "cwe": "CWE-78",
    "opengrep_rule": "cylab.python.command-injection",
    "before": 'import subprocess\n\ndef convert(path):\n    subprocess.call("convert " + path + " out.png", shell=True)\n',
    "after": 'import subprocess\n\ndef convert(path):\n    subprocess.run(["convert", path, "out.png"], check=False)\n',
    "explanation_pt": "shell=True com path externo = command injection (CWE-78). Lista de args sem shell.",
  },
  {
    "id": "cylab-sam-js-sqli-tpl-001",
    "lang": "javascript",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.javascript.sql-injection",
    "before": 'async function find(db, city) {\n  return db.query(`SELECT * FROM stores WHERE city = \'${city}\'`);\n}\n',
    "after": 'async function find(db, city) {\n  return db.query("SELECT * FROM stores WHERE city = ?", [city]);\n}\n',
    "explanation_pt": "Template string no SQL permite injeção (CWE-89). Parametrize.",
  },
  {
    "id": "cylab-sam-js-cors-001",
    "lang": "javascript",
    "cwe": "CWE-942",
    "opengrep_rule": "cylab.javascript.cors-star",
    "before": 'function setCors(res) {\n  res.setHeader("Access-Control-Allow-Origin", "*");\n}\n',
    "after": 'const ALLOWED = new Set(["https://app.example.com"]);\n\nfunction setCors(res, origin) {\n  if (ALLOWED.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin);\n}\n',
    "explanation_pt": "CORS * com credenciais/APIs sensíveis é perigoso (CWE-942). Allowlist de origens.",
  },
  {
    "id": "cylab-sam-js-ssrf-001",
    "lang": "javascript",
    "cwe": "CWE-918",
    "opengrep_rule": "cylab.javascript.ssrf",
    "before": 'const fetch = require("node-fetch");\n\nasync function proxy(url) {\n  const r = await fetch(url);\n  return r.text();\n}\n',
    "after": 'const fetch = require("node-fetch");\nconst { URL } = require("url");\nconst ALLOWED = new Set(["api.example.com"]);\n\nasync function proxy(url) {\n  const host = new URL(url).hostname;\n  if (!ALLOWED.has(host)) throw new Error("blocked");\n  const r = await fetch(url, { timeout: 5000 });\n  return r.text();\n}\n',
    "explanation_pt": "Fetch de URL arbitrária = SSRF (CWE-918). Valide host e use timeout.",
  },
  {
    "id": "cylab-sam-js-weakhash-001",
    "lang": "javascript",
    "cwe": "CWE-328",
    "opengrep_rule": "cylab.javascript.weak-hash",
    "before": 'const crypto = require("crypto");\n\nfunction fingerprint(pw) {\n  return crypto.createHash("md5").update(pw).digest("hex");\n}\n',
    "after": 'const crypto = require("crypto");\n\nfunction fingerprint(pw) {\n  const salt = crypto.randomBytes(16);\n  const hash = crypto.scryptSync(pw, salt, 32);\n  return salt.toString("hex") + ":" + hash.toString("hex");\n}\n',
    "explanation_pt": "MD5 não serve para senha (CWE-328). Use scrypt/bcrypt/argon2 com salt.",
  },
  {
    "id": "cylab-sam-ts-sqli-001",
    "lang": "typescript",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.typescript.sql-injection",
    "before": 'export async function getOrder(db: any, id: string) {\n  return db.query("SELECT * FROM orders WHERE id = \'" + id + "\'");\n}\n',
    "after": 'export async function getOrder(db: any, id: string) {\n  return db.query("SELECT * FROM orders WHERE id = $1", [id]);\n}\n',
    "explanation_pt": "Concatenação em SQL (CWE-89). Use bind $1.",
  },
  {
    "id": "cylab-sam-ts-xss-001",
    "lang": "typescript",
    "cwe": "CWE-79",
    "opengrep_rule": "cylab.typescript.xss-dangerously-set",
    "before": 'export function Html({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n',
    "after": 'import DOMPurify from "dompurify";\n\nexport function Html({ html }: { html: string }) {\n  const clean = DOMPurify.sanitize(html);\n  return <div dangerouslySetInnerHTML={{ __html: clean }} />;\n}\n',
    "explanation_pt": "dangerouslySetInnerHTML sem sanitize = XSS (CWE-79). Passe por DOMPurify ou evite HTML cru.",
  },
  {
    "id": "cylab-sam-ts-redirect-001",
    "lang": "typescript",
    "cwe": "CWE-601",
    "opengrep_rule": "cylab.typescript.open-redirect",
    "before": 'import { Redirect } from "express";\n\nexport function go(res: any, next: string) {\n  res.redirect(next);\n}\n',
    "after": 'export function go(res: any, next: string) {\n  if (!next.startsWith("/") || next.startsWith("//")) {\n    throw new Error("invalid redirect");\n  }\n  res.redirect(next);\n}\n',
    "explanation_pt": "redirect com URL externa = open redirect (CWE-601). Só permita paths relativos locais.",
  },
  {
    "id": "cylab-sam-ts-random-001",
    "lang": "typescript",
    "cwe": "CWE-338",
    "opengrep_rule": "cylab.typescript.insecure-randomness",
    "before": 'export function resetToken(): string {\n  return Math.random().toString(36).slice(2);\n}\n',
    "after": 'import { randomBytes } from "crypto";\n\nexport function resetToken(): string {\n  return randomBytes(32).toString("hex");\n}\n',
    "explanation_pt": "Math.random não é CSPRNG (CWE-338). Use crypto.randomBytes.",
  },
  {
    "id": "cylab-sam-js-path-002",
    "lang": "javascript",
    "cwe": "CWE-22",
    "opengrep_rule": "cylab.javascript.path-traversal",
    "before": 'const fs = require("fs");\nconst path = require("path");\n\nexports.download = (req, res) => {\n  const file = path.join(__dirname, "files", req.query.f);\n  res.sendFile(file);\n};\n',
    "after": 'const fs = require("fs");\nconst path = require("path");\n\nexports.download = (req, res) => {\n  const root = path.resolve(__dirname, "files");\n  const file = path.resolve(root, String(req.query.f || ""));\n  if (!file.startsWith(root + path.sep)) return res.status(400).end();\n  res.sendFile(file);\n};\n',
    "explanation_pt": "query.f sem resolve = path traversal (CWE-22). Normalize e cheque o prefixo.",
  },
  {
    "id": "cylab-sam-py-path-002",
    "lang": "python",
    "cwe": "CWE-22",
    "opengrep_rule": "cylab.python.path-traversal",
    "before": 'import os\n\ndef load_template(name):\n    return open(os.path.join("templates", name)).read()\n',
    "after": 'from pathlib import Path\n\ndef load_template(name):\n    root = Path("templates").resolve()\n    target = (root / name).resolve()\n    if not str(target).startswith(str(root)):\n        raise ValueError("traversal")\n    return target.read_text()\n',
    "explanation_pt": "join com name do usuário = traversal (CWE-22). resolve + prefix check.",
  },
  {
    "id": "cylab-sam-py-deser-001",
    "lang": "python",
    "cwe": "CWE-502",
    "opengrep_rule": "cylab.python.insecure-deserialization",
    "before": 'import yaml\n\ndef load_cfg(raw):\n    return yaml.load(raw)\n',
    "after": 'import yaml\n\ndef load_cfg(raw):\n    return yaml.safe_load(raw)\n',
    "explanation_pt": "yaml.load inseguro deserializa objetos arbitrários (CWE-502). Use safe_load.",
  },
  {
    "id": "cylab-sam-js-cmdi-002",
    "lang": "javascript",
    "cwe": "CWE-78",
    "opengrep_rule": "cylab.javascript.command-injection",
    "before": 'const { exec } = require("child_process");\n\nexports.zip = (req, res) => {\n  exec("zip -r out.zip " + req.body.dir, (e, out) => res.send(out));\n};\n',
    "after": 'const { execFile } = require("child_process");\n\nexports.zip = (req, res) => {\n  execFile("zip", ["-r", "out.zip", "--", req.body.dir], (e, out) => res.send(out));\n};\n',
    "explanation_pt": "exec com body.dir = command injection (CWE-78). execFile + args.",
  },
]

def ensure_new_rules():
    for name, body in NEW_RULES.items():
        (RULES / name).write_text(body)

def rule_path(rule_id: str) -> Path:
    # Bill rules are flat yaml named after id
    p = RULES / f"{rule_id}.yaml"
    if p.exists():
        return p
    raise FileNotFoundError(rule_id)

def count_hits(rule_id: str, code: str, lang: str) -> int:
    ext = {"python": ".py", "javascript": ".js", "typescript": ".tsx"}.get(lang, ".txt")
    cfg = rule_path(rule_id)
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / f"s{ext}"
        f.write_text(code)
        r = subprocess.run(
            [str(SEMGREP), "--config", str(cfg), "--quiet", "--json", str(f)],
            capture_output=True, text=True,
        )
        try:
            data = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        return len(data.get("results") or [])

def main():
    ensure_new_rules()
    ok, fail = [], []
    for raw in PAIRS:
        try:
            b = count_hits(raw["opengrep_rule"], raw["before"], raw["lang"])
            a = count_hits(raw["opengrep_rule"], raw["after"], raw["lang"])
        except Exception as e:
            print("ERR", raw["id"], e)
            fail.append(raw["id"])
            continue
        row = {
            "id": raw["id"],
            "lang": raw["lang"],
            "cwe": raw["cwe"],
            "source": "sintetico-cylab",
            "license": "CC-BY-4.0",
            "opengrep_rule": raw["opengrep_rule"],
            "before": raw["before"],
            "after": raw["after"],
            "explanation_pt": raw["explanation_pt"],
            "split": "train",
            "gate": {"before_hits": b, "after_hits": a},
        }
        if b >= 1 and a == 0:
            ok.append(row)
        else:
            print(f"FAIL {raw['id']}: before={b} after={a}")
            fail.append(raw["id"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for row in ok:
            # strip gate internals for merge? keep for Bill report
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"OK {len(ok)} FAIL {len(fail)} -> {OUT}")

if __name__ == "__main__":
    main()
