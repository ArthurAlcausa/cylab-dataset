#!/usr/bin/env python3
import json, os, re, sys, glob, random
sys.path.insert(0, os.path.dirname(__file__))
from bill_templates import T, E
from gate_queue import gate
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT)
KEYS=["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
def sub(s,e):
    t,c,s1=e
    for k,v in [("@SC@",s1.capitalize()),("@CC@",c.capitalize()),("@CU@",s1.upper()),("@T@",t),("@S@",s1),("@C@",c)]: s=s.replace(k,v)
    return s
# regras
for tp in T:
    name=f"cylab.{tp['lang']}.{tp['slug']}"; rf=f"rules/{name}.yaml"
    y=(f"rules:\n  - id: {name}\n    message: \"{tp['exp'].split('(CWE')[0].strip()[:120].replace(chr(34),'')} (CWE-{tp['cwe']})\"\n"
       f"    severity: ERROR\n    languages: [{tp['rl']}]\n    metadata:\n      cwe: \"CWE-{tp['cwe']}\"\n      source: sintetico-cylab\n      author: bill-scale\n"
       f"    pattern-regex: '{tp['regex'].replace(chr(39),chr(39)*2)}'\n")
    if os.path.exists(rf) and "author: bill-scale" not in open(rf).read(): sys.exit("colisao de regra "+rf)
    open(rf,"w").write(y)
# dedup existente
seen_ids,seen_b=set(),set()
for f in ["data/cylab-v0.1.jsonl","data/queue-sam.jsonl","data/queue-markinho.jsonl"]+glob.glob("contributions/sam-py-js/*.jsonl")+glob.glob("contributions/markinho-java-php-sql-shell/**/*.jsonl",recursive=True):
    for l in open(f):
        if l.strip(): p=json.loads(l); seen_ids.add(p["id"]); seen_b.add(p["before"].strip())
cands=[]; n=0
for tp in T:
    for i,e in enumerate(E):
        b,a=tp["styles"][i%len(tp["styles"])]
        b,a=sub(b,e),sub(a,e)
        if b.strip() in seen_b or b==a: continue
        seen_b.add(b.strip()); n+=1
        cands.append(dict(id=f"cylab-bill-{tp['lang']}-{tp['cwe']}-{n:04d}",lang=tp["lang"],cwe=f"CWE-{tp['cwe']}",
          source=f"sintetico-cylab https://cwe.mitre.org/data/definitions/{tp['cwe']}.html",license="CC-BY-4.0",
          opengrep_rule=f"cylab.{tp['lang']}.{tp['slug']}",before=b,after=a,explanation_pt=sub(tp["exp"],e),split="holdout" if n%10==0 else "train"))
assert not ({c["id"] for c in cands}&seen_ids)
r=gate(cands); ok=[];fail=[]
for c,(hb,ha) in zip(cands,r): (ok if hb>0 and ha==0 else fail).append((c,hb,ha))
for c,hb,ha in fail: print("FAIL",c["id"],c["opengrep_rule"],hb,ha)
print(len(ok),"ok",len(fail),"fail")
good=[c for c,_,_ in ok]; random.Random(7).shuffle(good)
for f in glob.glob("contributions/bill-scale/batch_*.jsonl"): os.remove(f)
for k in range(0,len(good),100):
    with open(f"contributions/bill-scale/batch_{k//100+1:04d}.jsonl","w") as fh:
        for c in good[k:k+100]: fh.write(json.dumps({x:c[x] for x in KEYS},ensure_ascii=False)+"\n")
