#!/usr/bin/env python3
"""Gera candidatos REALISM (c/cpp/bash) -> elon_realism_raw.jsonl. Nao toca FINAL."""
import json,os,sys,re
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import pairs_c,pairs_cpp,pairs_bash
out=[];cnt={}
for lang,mod in (("c",pairs_c),("cpp",pairs_cpp),("bash",pairs_bash)):
    for cwe,rule,before,repl,expl in mod.P:
        after=before
        for old,new in repl:
            assert old in after,(rule,old[:60]); after=after.replace(old,new,1)
        n=cwe.split("-")[1]; k=(lang,n); cnt[k]=cnt.get(k,0)+1
        out.append(dict(id=f"cylab-elon-real-{lang}-{n}-{cnt[k]:04d}",lang=lang,cwe=cwe,
            source=f"sintetico-cylab https://cwe.mitre.org/data/definitions/{n}.html",license="CC-BY-4.0",
            opengrep_rule=rule,before=before,after=after,explanation_pt=expl,split="train"))
with open(sys.argv[1] if len(sys.argv)>1 else "elon_realism_raw.jsonl","w") as f:
    for p in out: f.write(json.dumps(p,ensure_ascii=False)+"\n")
print(len(out),"pares")
