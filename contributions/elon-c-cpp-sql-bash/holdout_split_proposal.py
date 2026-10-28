#!/usr/bin/env python3
"""Proposta de split global train/holdout estavel (nao sobrescreve nada).
Estrato = (lang, opengrep_rule sem sufixo -gold). Dentro do estrato ordena por sha256(SALT+id) e
manda floor(n*PCT) para holdout, com minimo 1 se n>=3 (n<=2 -> tudo train). Deterministico e
estavel: adicionar pares novos nao move pares existentes, exceto na borda do estrato.
Uso: holdout_split_proposal.py in.jsonl --out proposal.json [--pct 0.15]"""
import json,hashlib,argparse,collections,math
SALT="cylab-holdout-v1:"
ap=argparse.ArgumentParser();ap.add_argument("inp");ap.add_argument("--out",required=True);ap.add_argument("--pct",type=float,default=0.15)
a=ap.parse_args()
P=[json.loads(l) for l in open(a.inp) if l.strip()]
st=collections.defaultdict(list)
for p in P: st[(p["lang"],p["opengrep_rule"].removesuffix("-gold"))].append(p["id"])
assign={};per=[]
for (lang,rule),ids in sorted(st.items()):
    ids=sorted(ids,key=lambda i:hashlib.sha256((SALT+i).encode()).hexdigest()); n=len(ids)
    k=0 if n<3 else max(1,math.floor(n*a.pct))
    for j,i in enumerate(ids): assign[i]="holdout" if j<k else "train"
    per.append(dict(lang=lang,rule=rule,n=n,holdout=k))
cur=collections.Counter((p["split"],assign[p["id"]]) for p in P)
bylang=collections.defaultdict(collections.Counter)
for p in P: bylang[p["lang"]][assign[p["id"]]]+=1
rep=dict(input=a.inp,salt=SALT,pct=a.pct,method=__doc__.strip().split("\n")[1:4],total=len(P),
 holdout=sum(v=="holdout" for v in assign.values()),by_lang={k:dict(v) for k,v in bylang.items()},
 diff_vs_current_split={f"{x}->{y}":c for (x,y),c in cur.items()},strata=per,assignment=assign)
json.dump(rep,open(a.out,"w"),indent=1,ensure_ascii=False)
print(f"total={len(P)} holdout={rep['holdout']} strata={len(per)} by_lang={rep['by_lang']}")
