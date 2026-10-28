#!/usr/bin/env python3
"""Cylab v0.1 gold pairs — synthetic, no VigIA. Python + JS only (Sam slice)."""
import json, os, subprocess, tempfile, textwrap
from pathlib import Path

ROOT = Path("/workspace/cylab-dataset")
OUT = ROOT / "v0.1" / "pairs" / "sam_py_js_gold.jsonl"
RULES = ROOT / "v0.1" / "rules"
SEMGREP = ROOT / ".venv" / "bin" / "semgrep"

PAIRS = [
  {
    "id": "cylab-py-sqli-001",
    "lang": "python",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.python.sql-format",
    "before": 'def get_user(db, user_id):\n    q = f"SELECT * FROM users WHERE id = {user_id}"\n    return db.execute(q)\n',
    "after": 'def get_user(db, user_id):\n    q = "SELECT * FROM users WHERE id = ?"\n    return db.execute(q, (user_id,))\n',
    "explanation_pt": "Entrada interpolada em SQL permite injeção (CWE-89). Use placeholder e parâmetros bindados.",
  },
  {
    "id": "cylab-py-cmdi-001",
    "lang": "python",
    "cwe": "CWE-78",
    "opengrep_rule": "cylab.python.os-system",
    "before": 'import os\n\ndef ping_host(host):\n    os.system("ping -c 1 " + host)\n',
    "after": 'import subprocess\n\ndef ping_host(host):\n    subprocess.run(["ping", "-c", "1", host], check=False)\n',
    "explanation_pt": "os.system com concatenação permite command injection (CWE-78). Prefira subprocess com lista de args, sem shell.",
  },
  {
    "id": "cylab-py-path-001",
    "lang": "python",
    "cwe": "CWE-22",
    "opengrep_rule": "cylab.python.path-join-user",
    "before": 'from pathlib import Path\n\ndef read_user_file(name):\n    path = Path("/var/data") / name\n    return path.read_text()\n',
    "after": 'from pathlib import Path\n\ndef read_user_file(name):\n    base = Path("/var/data").resolve()\n    path = (base / name).resolve()\n    if not str(path).startswith(str(base)):\n        raise ValueError("path traversal")\n    return path.read_text()\n',
    "explanation_pt": "Nome de arquivo controlado pelo usuário pode escapar o diretório base (CWE-22). Normalize e confira o prefixo.",
  },
  {
    "id": "cylab-py-secret-001",
    "lang": "python",
    "cwe": "CWE-798",
    "opengrep_rule": "cylab.python.hardcoded-secret",
    "before": 'API_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxx"\n\ndef client():\n    return {"Authorization": f"Bearer {API_KEY}"}\n',
    "after": 'import os\n\ndef client():\n    api_key = os.environ["API_KEY"]\n    return {"Authorization": f"Bearer {api_key}"}\n',
    "explanation_pt": "Segredo hardcoded no código (CWE-798). Carregue de variável de ambiente ou cofre.",
  },
  {
    "id": "cylab-py-pickle-001",
    "lang": "python",
    "cwe": "CWE-502",
    "opengrep_rule": "cylab.python.pickle-loads",
    "before": 'import pickle\n\ndef load_session(blob):\n    return pickle.loads(blob)\n',
    "after": 'import json\n\ndef load_session(blob):\n    return json.loads(blob)\n',
    "explanation_pt": "pickle.loads em dados não confiáveis permite RCE (CWE-502). Use formato seguro (JSON) ou assinatura + allowlist.",
  },
  {
    "id": "cylab-py-ssrf-001",
    "lang": "python",
    "cwe": "CWE-918",
    "opengrep_rule": "cylab.python.requests-url-user",
    "before": 'import requests\n\ndef fetch(url):\n    return requests.get(url).text\n',
    "after": 'import requests\nfrom urllib.parse import urlparse\n\nALLOWED = {"api.example.com"}\n\ndef fetch(url):\n    host = urlparse(url).hostname\n    if host not in ALLOWED:\n        raise ValueError("host not allowed")\n    return requests.get(url, timeout=5).text\n',
    "explanation_pt": "URL controlada pelo usuário sem allowlist causa SSRF (CWE-918). Valide esquema/host e use timeout.",
  },
  {
    "id": "cylab-py-crypto-001",
    "lang": "python",
    "cwe": "CWE-328",
    "opengrep_rule": "cylab.python.md5-password",
    "before": 'import hashlib\n\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n',
    "after": 'import hashlib\nimport secrets\n\ndef hash_password(pw):\n    salt = secrets.token_bytes(16)\n    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)\n    return salt.hex() + ":" + dk.hex()\n',
    "explanation_pt": "MD5 não é adequado para senha (CWE-328). Use KDF com salt (PBKDF2/Argon2/bcrypt).",
  },
  {
    "id": "cylab-py-xss-tpl-001",
    "lang": "python",
    "cwe": "CWE-79",
    "opengrep_rule": "cylab.python.flask-unsafe-html",
    "before": 'from flask import Flask, request, Markup\napp = Flask(__name__)\n\n@app.get("/")\ndef index():\n    name = request.args.get("name", "")\n    return Markup(f"<h1>Olá {name}</h1>")\n',
    "after": 'from flask import Flask, request, escape\napp = Flask(__name__)\n\n@app.get("/")\ndef index():\n    name = request.args.get("name", "")\n    return f"<h1>Olá {escape(name)}</h1>"\n',
    "explanation_pt": "HTML com entrada crua causa XSS (CWE-79). Escape a saída ou use template com autoescape.",
  },
  {
    "id": "cylab-js-sqli-001",
    "lang": "javascript",
    "cwe": "CWE-89",
    "opengrep_rule": "cylab.javascript.sql-concat",
    "before": 'async function getUser(db, id) {\n  const q = "SELECT * FROM users WHERE id = " + id;\n  return db.query(q);\n}\n',
    "after": 'async function getUser(db, id) {\n  const q = "SELECT * FROM users WHERE id = ?";\n  return db.query(q, [id]);\n}\n',
    "explanation_pt": "Concatenar id na query SQL permite injeção (CWE-89). Use query parametrizada.",
  },
  {
    "id": "cylab-js-cmdi-001",
    "lang": "javascript",
    "cwe": "CWE-78",
    "opengrep_rule": "cylab.javascript.child-exec",
    "before": 'const { exec } = require("child_process");\n\nfunction listDir(userPath) {\n  exec("ls " + userPath, (err, out) => console.log(out));\n}\n',
    "after": 'const { execFile } = require("child_process");\n\nfunction listDir(userPath) {\n  execFile("ls", ["-la", "--", userPath], (err, out) => console.log(out));\n}\n',
    "explanation_pt": "exec com string montada permite command injection (CWE-78). Use execFile com args separados.",
  },
  {
    "id": "cylab-js-path-001",
    "lang": "javascript",
    "cwe": "CWE-22",
    "opengrep_rule": "cylab.javascript.path-join-user",
    "before": 'const fs = require("fs");\nconst path = require("path");\n\nfunction readUpload(name) {\n  return fs.readFileSync(path.join("/uploads", name), "utf8");\n}\n',
    "after": 'const fs = require("fs");\nconst path = require("path");\n\nfunction readUpload(name) {\n  const base = path.resolve("/uploads");\n  const full = path.resolve(base, name);\n  if (!full.startsWith(base + path.sep)) throw new Error("path traversal");\n  return fs.readFileSync(full, "utf8");\n}\n',
    "explanation_pt": "path.join com nome do usuário permite path traversal (CWE-22). Resolve e valide o prefixo.",
  },
  {
    "id": "cylab-js-secret-001",
    "lang": "javascript",
    "cwe": "CWE-798",
    "opengrep_rule": "cylab.javascript.hardcoded-jwt",
    "before": 'const JWT_SECRET = "supersecret123";\n\nfunction sign(payload, jwt) {\n  return jwt.sign(payload, JWT_SECRET);\n}\n',
    "after": 'function sign(payload, jwt) {\n  const secret = process.env.JWT_SECRET;\n  if (!secret) throw new Error("JWT_SECRET missing");\n  return jwt.sign(payload, secret);\n}\n',
    "explanation_pt": "Segredo JWT no código (CWE-798). Use variável de ambiente.",
  },
  {
    "id": "cylab-js-xss-001",
    "lang": "javascript",
    "cwe": "CWE-79",
    "opengrep_rule": "cylab.javascript.innerhtml-user",
    "before": 'function greet(el, name) {\n  el.innerHTML = "<p>Olá " + name + "</p>";\n}\n',
    "after": 'function greet(el, name) {\n  el.textContent = "";\n  const p = document.createElement("p");\n  p.textContent = "Olá " + name;\n  el.appendChild(p);\n}\n',
    "explanation_pt": "innerHTML com dados do usuário causa XSS (CWE-79). Use textContent/DOM APIs.",
  },
  {
    "id": "cylab-js-eval-001",
    "lang": "javascript",
    "cwe": "CWE-95",
    "opengrep_rule": "cylab.javascript.eval-user",
    "before": 'function runMath(expr) {\n  return eval(expr);\n}\n',
    "after": 'function runMath(expr) {\n  if (!/^[0-9+\\-*/().\\s]+$/.test(expr)) throw new Error("invalid");\n  return Function(\'"use strict"; return (\' + expr + \')\')();\n}\n',
    "explanation_pt": "eval em entrada arbitrária é code injection (CWE-95). Restrinja a expressão ou use parser seguro.",
  },
  {
    "id": "cylab-js-proto-001",
    "lang": "javascript",
    "cwe": "CWE-1321",
    "opengrep_rule": "cylab.javascript.merge-proto",
    "before": 'function merge(a, b) {\n  for (const k of Object.keys(b)) a[k] = b[k];\n  return a;\n}\n',
    "after": 'function merge(a, b) {\n  for (const k of Object.keys(b)) {\n    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;\n    a[k] = b[k];\n  }\n  return a;\n}\n',
    "explanation_pt": "Merge raso sem filtrar chaves especiais permite prototype pollution (CWE-1321).",
  },
]

# Minimal Semgrep rules (one pattern each) — enough to gate before vs after
RULE_YAMLS = {
  "cylab.python.sql-format": """
rules:
- id: cylab.python.sql-format
  message: SQL montado com f-string
  languages: [python]
  severity: ERROR
  pattern: f"SELECT ...
""",  # will fix properly below
}

def write_rules():
    RULES.mkdir(parents=True, exist_ok=True)
    specs = {
        "cylab.python.sql-format.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.sql-format
              message: SQL com f-string
              languages: [python]
              severity: ERROR
              pattern: |
                f"...{$X}..."
            """),
        "cylab.python.os-system.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.os-system
              message: os.system
              languages: [python]
              severity: ERROR
              pattern: os.system(...)
            """),
        "cylab.python.path-join-user.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.path-join-user
              message: path join sem resolve
              languages: [python]
              severity: ERROR
              pattern: |
                Path(...)/$NAME
              metavariable-regex:
                metavariable: $NAME
                regex: ^(name|filename|user_path|path)$
            """),
        "cylab.python.hardcoded-secret.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.hardcoded-secret
              message: secret literal
              languages: [python]
              severity: ERROR
              pattern: $KEY = "..."
              metavariable-regex:
                metavariable: $KEY
                regex: (API_KEY|SECRET|TOKEN)
            """),
        "cylab.python.pickle-loads.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.pickle-loads
              message: pickle.loads
              languages: [python]
              severity: ERROR
              pattern: pickle.loads(...)
            """),
        "cylab.python.requests-url-user.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.requests-url-user
              message: requests.get url param
              languages: [python]
              severity: ERROR
              pattern: requests.get($URL)
              pattern-not: requests.get($URL, ...)
            """),
        "cylab.python.md5-password.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.md5-password
              message: md5 password
              languages: [python]
              severity: ERROR
              pattern: hashlib.md5(...)
            """),
        "cylab.python.flask-unsafe-html.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.python.flask-unsafe-html
              message: Markup unsafe
              languages: [python]
              severity: ERROR
              pattern: Markup(...)
            """),
        "cylab.javascript.sql-concat.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.sql-concat
              message: SQL concat
              languages: [javascript]
              severity: ERROR
              pattern-regex: 'SELECT \\* FROM .*\\+'
            """),
        "cylab.javascript.child-exec.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.child-exec
              message: child_process exec
              languages: [javascript]
              severity: ERROR
              pattern: exec(...)
            """),
        "cylab.javascript.path-join-user.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.path-join-user
              message: path.join user
              languages: [javascript]
              severity: ERROR
              pattern: path.join(..., $NAME)
            """),
        "cylab.javascript.hardcoded-jwt.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.hardcoded-jwt
              message: hardcoded jwt
              languages: [javascript]
              severity: ERROR
              pattern: JWT_SECRET = "..."
            """),
        "cylab.javascript.innerhtml-user.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.innerhtml-user
              message: innerHTML
              languages: [javascript]
              severity: ERROR
              pattern: $EL.innerHTML = ...
            """),
        "cylab.javascript.eval-user.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.eval-user
              message: eval
              languages: [javascript]
              severity: ERROR
              pattern: eval(...)
            """),
        "cylab.javascript.merge-proto.yaml": textwrap.dedent("""\
            rules:
            - id: cylab.javascript.merge-proto
              message: unsafe merge
              languages: [javascript]
              severity: ERROR
              patterns:
                - pattern: |
                    for (const $K of Object.keys($B)) $A[$K] = $B[$K]
                - pattern-not: |
                    for (const $K of Object.keys($B)) { if (...) continue; $A[$K] = $B[$K] }
            """),
    }
    for name, body in specs.items():
        (RULES / name).write_text(body)
    return specs

def run_rule(rule_id: str, code: str, lang: str) -> int:
    ext = {"python": ".py", "javascript": ".js"}[lang]
    rule_file = RULES / f"{rule_id}.yaml"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / f"sample{ext}"
        p.write_text(code)
        r = subprocess.run(
            [str(SEMGREP), "--config", str(rule_file), "--quiet", "--json", str(p)],
            capture_output=True, text=True
        )
        try:
            data = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            data = {}
        return len(data.get("results") or [])

def main():
    write_rules()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    ok, fail = [], []
    for raw in PAIRS:
        before_hits = run_rule(raw["opengrep_rule"], raw["before"], raw["lang"])
        after_hits = run_rule(raw["opengrep_rule"], raw["after"], raw["lang"])
        row = {
            "id": raw["id"],
            "lang": raw["lang"],
            "cwe": raw["cwe"],
            "source": "cylab-synthetic",
            "license": "CC-BY-4.0",
            "opengrep_rule": raw["opengrep_rule"],
            "before": raw["before"],
            "after": raw["after"],
            "explanation_pt": raw["explanation_pt"],
            "split": "train",
            "gate": {"before_hits": before_hits, "after_hits": after_hits},
        }
        if before_hits >= 1 and after_hits == 0:
            ok.append(row)
        else:
            fail.append(row)
            print(f"FAIL {raw['id']}: before={before_hits} after={after_hits}")
    with OUT.open("w") as f:
        for row in ok:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"OK {len(ok)} FAIL {len(fail)} -> {OUT}")

if __name__ == "__main__":
    main()
