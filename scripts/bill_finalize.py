import json,glob,collections,os
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEYS=["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
rows=[json.loads(l) for f in sorted(glob.glob("contributions/bill-scale/batch_*.jsonl")) for l in open(f)]
with open("data/queue-bill.jsonl","w") as fh:
    for r in rows: fh.write(json.dumps({k:r[k] for k in KEYS},ensure_ascii=False)+"\n")
allp={};src={}
for f in ["data/cylab-v0.1.jsonl","data/queue-sam.jsonl","data/queue-markinho.jsonl","data/queue-bill.jsonl"]:
    n=0
    for l in open(f):
        p=json.loads(l); k=(p["id"]); 
        if k not in allp and p["before"].strip() not in {q["before"].strip() for q in []}: allp[k]=p; n+=1
    src[f]=n
befores=collections.Counter(p["before"].strip() for p in allp.values())
bylang=collections.Counter(p["lang"] for p in allp.values())
bill=collections.Counter(r["lang"] for r in rows)
prog=dict(updated="2026-10-26",total_unique_ids=len(allp),dup_before_texts=sum(v-1 for v in befores.values() if v>1),
  by_source=src,by_lang_all=dict(sorted(bylang.items())),bill_by_lang=dict(sorted(bill.items())),
  bill_by_cwe=dict(collections.Counter(r["cwe"] for r in rows).most_common()),
  bill_holdout=sum(r["split"]=="holdout" for r in rows),bill_batches=sorted(glob.glob("contributions/bill-scale/batch_*.jsonl")),target=2000)
json.dump(prog,open("data/scale-progress.json","w"),indent=1,ensure_ascii=False); print(json.dumps(prog,indent=1))
