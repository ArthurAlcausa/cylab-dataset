#!/usr/bin/env python3
"""Filtra gate-pass + near-dup (vs FINAL mesmo lang, e interno), escreve candidatos + REPORT.md."""
import json,os,sys,statistics,collections,hashlib,difflib
R=os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."));sys.path.insert(0,R+"/scripts")
import gold_near_dup as nd
H=os.path.dirname(os.path.abspath(__file__)); THR=0.85
P=[json.loads(l) for l in open(H+"/elon_realism_raw.jsonl")]
G={g["id"]:g for g in json.load(open(H+"/gate-report.json"))}
F=[json.loads(l) for l in open(R+"/data/cylab-commercial-v0.3-gold.jsonl")]
fid={f["id"] for f in F}
Fl=collections.defaultdict(list)
for f in F:
    if f["lang"] in("c","cpp","bash"): Fl[f["lang"]].append((f["id"],nd.shingles(nd.norm_tokens(f["before"],f["lang"])),f["before"]))
kept=[];drops=[];sims={}
for p in P:
    g=G[p["id"]]
    if not g["passed"]: drops.append((p["id"],"gate_fail")); continue
    assert p["id"] not in fid
    sh=nd.shingles(nd.norm_tokens(p["before"],p["lang"]))
    best=max(((nd.jacc(sh,s),i,difflib.SequenceMatcher(None,p["before"],b).ratio()) for i,s,b in Fl[p["lang"]]),default=(0,None,0))
    bi=max((nd.jacc(sh,nd.shingles(nd.norm_tokens(k["before"],k["lang"]))) for k in kept if k["lang"]==p["lang"]),default=0)
    sims[p["id"]]=dict(max_jaccard_final=round(best[0],3),nearest_final=best[1],seqmatch_nearest=round(best[2],3),max_jaccard_internal=round(bi,3))
    if best[0]>=THR or best[2]>=THR: drops.append((p["id"],"near_dup_final")); continue
    if bi>=THR: drops.append((p["id"],"near_dup_internal")); continue
    kept.append(p)
with open(H+"/elon_realism_candidates.jsonl","w") as f:
    for p in kept: f.write(json.dumps(p,ensure_ascii=False)+"\n")
rep=json.load(open(H+"/gate-report.json"))
for r in rep: r.update(sims.get(r["id"],{})); r["kept"]=r["id"] in {k["id"] for k in kept}
json.dump(rep,open(H+"/gate-report.json","w"),indent=1,ensure_ascii=False)
L=lambda s:len(s.rstrip("\n").split("\n"))
bl=[L(p["before"]) for p in kept]
by=collections.Counter((p["lang"],p["cwe"]) for p in kept); bl_lang=collections.Counter(p["lang"] for p in kept)
sha=hashlib.sha256(open(R+"/data/cylab-commercial-v0.3-gold.jsonl","rb").read()).hexdigest()
md=["# Elon REALISM buffer (c/cpp/bash) — candidatos v0.4","",
f"- Gerados: {len(P)} | gate pass: {sum(g['passed'] for g in G.values())}/{len(P)} | mantidos: {len(kept)}",
f"- Drops: {len(drops)} " + (str(drops) if drops else ""),
f"- Linhas do before (mantidos): mediana {statistics.median(bl)}, min {min(bl)}, max {max(bl)}",
f"- Near-dup: limiar {THR} (Jaccard 4-gramas normalizados e SequenceMatcher bruto) vs FINAL mesmo lang + interno; max Jaccard vs FINAL = {max(s['max_jaccard_final'] for s in sims.values())}, max SeqMatch = {max(s['seqmatch_nearest'] for s in sims.values())}, max interno = {max(s['max_jaccard_internal'] for s in sims.values())}",
f"- Colisão de id com FINAL: 0 | FINAL sha256: `{sha}`",
"- split: todos `train` (Bill resplit no v0.4). Regras: todas de `rules-gold/`.","",
"## Por linguagem","",*[f"- {k}: {v}" for k,v in sorted(bl_lang.items())],"","## Por lang/CWE","","| lang | CWE | n |","|---|---|---|",
*[f"| {l} | {c} | {n} |" for (l,c),n in sorted(by.items())],"",
"## Arquivos","","- `pairs_c.py`, `pairs_cpp.py`, `pairs_bash.py` — fontes originais dos pares","- `gen_realism.py` → `elon_realism_raw.jsonl`",
"- gate: `scripts/gate_draft.py elon_realism_raw.jsonl --report gate-report.json`","- `finalize.py` → `elon_realism_candidates.jsonl`, este REPORT, similaridades no gate-report"]
open(H+"/REPORT.md","w").write("\n".join(md)+"\n"); print("\n".join(md))
