#!/usr/bin/env python3
"""Valida data/cylab-v0.1.jsonl (ou caminho passado)."""
import json, os, re, sys
KEYS = ["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
LANGS = {"python","javascript","typescript","java","php","csharp","c","cpp","sql","bash"}
BANNED = re.compile(r"vigia|cimbra", re.I)
path = sys.argv[1] if len(sys.argv) > 1 else "data/cylab-v0.1.jsonl"
root = os.path.dirname(os.path.dirname(os.path.abspath(path)))
errs, ids, holdout = [], set(), 0
for n, line in enumerate(open(path, encoding="utf-8"), 1):
    try: p = json.loads(line)
    except Exception as e: errs.append(f"L{n}: JSON invalido {e}"); continue
    if list(p.keys()) != KEYS: errs.append(f"L{n}: chaves {list(p.keys())}")
    for k in KEYS:
        if not isinstance(p.get(k), str) or not p[k].strip(): errs.append(f"L{n}: campo vazio/nulo {k}")
    if p.get("id") in ids: errs.append(f"L{n}: id duplicado")
    ids.add(p.get("id"))
    if p.get("lang") not in LANGS: errs.append(f"L{n}: lang {p.get('lang')}")
    if not re.fullmatch(r"CWE-\d+", p.get("cwe") or ""): errs.append(f"L{n}: cwe")
    num = (p.get("cwe") or "-").split("-")[-1]
    if not (p.get("source","").startswith("sintetico-cylab") and f"https://cwe.mitre.org/data/definitions/{num}.html" in p.get("source","")):
        errs.append(f"L{n}: source")
    if p.get("license") != "CC-BY-4.0": errs.append(f"L{n}: license")
    r = p.get("opengrep_rule") or ""
    if not re.fullmatch(rf"cylab\.{re.escape(p.get('lang',''))}\.[a-z0-9-]+", r): errs.append(f"L{n}: opengrep_rule {r}")
    elif not os.path.isfile(os.path.join(root, "rules", r + ".yaml")): errs.append(f"L{n}: regra ausente {r}")
    if p.get("before") == p.get("after"): errs.append(f"L{n}: before==after")
    if p.get("split") not in ("train","holdout"): errs.append(f"L{n}: split")
    holdout += p.get("split") == "holdout"
    if BANNED.search(line): errs.append(f"L{n}: string proibida (VigIA/CIMBRA)")
if holdout < 4: errs.append(f"holdout insuficiente: {holdout}")
if errs: print("\n".join(errs)); print(f"FALHOU: {len(errs)} erros"); sys.exit(1)
print(f"OK: {len(ids)} pares, {holdout} holdout"); 
