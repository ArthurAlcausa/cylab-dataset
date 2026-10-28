#!/usr/bin/env python3
"""Build v0.4 realism DRAFT (read-only on sources & v0.3-gold). Holdout: keep Sam's splits; others -> holdout iff int(sha256(id),16)%10==0."""
import json,hashlib,collections,difflib,re,itertools,os
SRC={"markinho":"contributions/markinho-java-php-sql-shell/realistic_v04_candidates.jsonl","bill":"contributions/bill-sql/realism_buffer.jsonl",
 "elon":"contributions/elon-c-cpp-sql-bash/realism/elon_realism_candidates.jsonl","sam":"contributions/sam-py-js/gold_realism_v0.4_candidates.jsonl"}
KEYS=["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
GOLD="data/cylab-commercial-v0.3-gold.jsonl"; OUT="data/cylab-commercial-v0.4-realism-DRAFT.jsonl"
sha=lambda f:hashlib.sha256(open(f,"rb").read()).hexdigest()
g0=sha(GOLD); gold=[json.loads(l) for l in open(GOLD)]; gids={r["id"] for r in gold}
rows=[];owner={};fixes=[]
for o,f in SRC.items():
  for l in open(f):
    if not l.strip(): continue
    r=json.loads(l); miss=[k for k in KEYS if not r.get(k)]
    if miss: fixes.append((r.get("id"),"missing",miss))
    i=r["id"]; n=1
    while i in gids or i in owner: n+=1; i=f'{r["id"]}-v04r{n}'
    if i!=r["id"]: fixes.append((r["id"],"renamed",i))
    r["id"]=i
    if o!="sam": r["split"]="holdout" if int(hashlib.sha256(i.encode()).hexdigest(),16)%10==0 else "train"
    owner[i]=o; rows.append({k:r[k] for k in KEYS})
with open(OUT,"w") as w:
  for r in rows: w.write(json.dumps(r,ensure_ascii=False)+"\n")
tok=lambda s:re.findall(r"\w+|[^\w\s]",s)
sh=lambda t:{tuple(t[i:i+5]) for i in range(max(1,len(t)-4))}
def sim(a,b):
  ta,tb=tok(a["before"]),tok(b["before"]); A,B=sh(ta),sh(tb)
  return difflib.SequenceMatcher(None,a["before"],b["before"],autojunk=False).ratio(),len(A&B)/len(A|B)
hits=[];maxs=[0,0]
by=collections.defaultdict(list)
for r in gold: by[(r["lang"],r["cwe"])].append(r)
for a,b in itertools.combinations(rows,2):
  if (a["lang"],a["cwe"])==(b["lang"],b["cwe"]):
    s,j=sim(a,b); maxs[0]=max(maxs[0],s,j)
    if s>=.85 or j>=.85: hits.append(dict(a=a["id"],b=b["id"],seq=round(s,3),jac=round(j,3),scope="intra"))
cmp=0
for a in rows:
  for b in by[(a["lang"],a["cwe"])]:
    cmp+=1; s,j=sim(a,b); maxs[1]=max(maxs[1],s,j)
    if s>=.85 or j>=.85: hits.append(dict(a=a["id"],b=b["id"],seq=round(s,3),jac=round(j,3),scope="vs_v0.3"))
C=lambda k:dict(collections.Counter(r[k] for r in rows))
meta=dict(draft=OUT,sha256_draft=sha(OUT),v03_gold=GOLD,sha256_v03_before=g0,sha256_v03_after=sha(GOLD),n=len(rows),
 by_owner=dict(collections.Counter(owner.values())),by_lang=C("lang"),by_cwe=C("cwe"),by_split=C("split"),
 split_by_owner={o:dict(collections.Counter(r["split"] for r in rows if owner[r["id"]]==o)) for o in SRC},
 holdout_ids=[r["id"] for r in rows if r["split"]=="holdout"],fixes=fixes,sources=SRC,
 near_dup=dict(method="SequenceMatcher ratio OR 5-token Jaccard >=0.85, same lang+cwe",hits=hits,max_score_intra=round(maxs[0],3),max_score_vs_v03=round(maxs[1],3),vs_v03_comparisons=cmp,drops=[]))
json.dump(meta,open("data/v0.4-realism-merge-meta.json","w"),indent=1,ensure_ascii=False)
print(json.dumps({k:v for k,v in meta.items() if k not in("holdout_ids",)},indent=1)[:3000])
