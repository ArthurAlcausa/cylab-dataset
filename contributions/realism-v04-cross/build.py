import json,re,statistics as st,collections as C,difflib,itertools,random
B={"markinho":"contributions/markinho-java-php-sql-shell/realistic_v04_candidates.jsonl","bill":"contributions/bill-sql/realism_buffer.jsonl","elon":"contributions/elon-c-cpp-sql-bash/realism/elon_realism_candidates.jsonl","sam":"contributions/sam-py-js/gold_realism_v0.4_candidates.jsonl"}
O="contributions/realism-v04-cross/"
L=lambda p:[json.loads(l) for l in open(p) if l.strip()]
final=L("data/cylab-commercial-v0.3-gold.jsonl");fid={r["id"] for r in final}
rows=[]
for o,p in B.items():
  for r in L(p): r["_owner"]=o; rows.append(r)
ids=C.Counter(r["id"] for r in rows)
inv={"total":len(rows),"final_v03_count":len(final),"per_buffer":{},"dup_ids_within_buffers":[i for i,c in ids.items() if c>1],"collisions_vs_final":sorted(i for i in ids if i in fid),"source_issues":[],"license_issues":[],"keys_seen":sorted({k for r in rows for k in r if k!="_owner"})}
def cnt(rs,k): return dict(C.Counter(str(r.get(k)) for r in rs).most_common())
def lines(rs): 
  v=[len(r.get("before","").splitlines()) for r in rs]
  return {"n":len(v),"median":st.median(v),"min":min(v),"max":max(v),"mean":round(st.mean(v),1)}
for o in B:
  rs=[r for r in rows if r["_owner"]==o]
  inv["per_buffer"][o]={"path":B[o],"count":len(rs),"lang":cnt(rs,"lang"),"cwe":cnt(rs,"cwe"),"split":cnt(rs,"split"),"source":cnt(rs,"source"),"before_lines":lines(rs)}
inv["overall"]={"lang":cnt(rows,"lang"),"cwe":cnt(rows,"cwe"),"split":cnt(rows,"split"),"before_lines":lines(rows)}
for r in rows:
  m=re.search(r"https://cwe\.mitre\.org/data/definitions/(\d+)\.html",r.get("source",""))
  if not m or "CWE-"+m.group(1)!=r.get("cwe"): inv["source_issues"].append(r["id"])
  if r.get("license")!="CC-BY-4.0": inv["license_issues"].append(r["id"])
json.dump(inv,open(O+"inventory.json","w"),indent=1,ensure_ascii=False)
def sh(t):
  w=re.findall(r"\w+|[^\w\s]",t); return {tuple(w[i:i+5]) for i in range(max(1,len(w)-4))}
def jac(a,b): return len(a&b)/len(a|b) if a|b else 0
flags=[];nc=0
for a,b in itertools.combinations(rows,2):
  if a["_owner"]==b["_owner"] or a["lang"]!=b["lang"] or a["cwe"]!=b["cwe"]: continue
  nc+=1;d={}
  for f in ("before","after"):
    d[f+"_seq"]=round(difflib.SequenceMatcher(None,a[f],b[f]).ratio(),3); d[f+"_jac"]=round(jac(sh(a[f]),sh(b[f])),3)
  mx=max(d.values())
  if mx>=0.85: flags.append({"a":a["id"],"b":b["id"],"owners":[a["_owner"],b["_owner"]],"lang":a["lang"],"cwe":a["cwe"],**d,"max":mx})
top=[]  # also report top pairs for context
json.dump({"threshold":0.85,"metrics":"SequenceMatcher ratio + 5-shingle Jaccard on before/after, cross-buffer same lang+cwe","pairs_compared":nc,"flagged":flags},open(O+"cross_near_dup_report.json","w"),indent=1)
# sample: round-robin per owner/lang/cwe diversity, ~22
random.seed(4)
g=C.defaultdict(list)
for r in rows: g[(r["_owner"],r["lang"],r["cwe"])].append(r)
keys=sorted(g,key=lambda k:-len(g[k]));samp=[r for r in rows if str(r.get("split")).lower()=="holdout"]
for k in keys:
  if not any((r["_owner"],r["lang"],r["cwe"])==k for r in samp): samp.append(random.choice(g[k]))
hold=[r for r in rows if str(r.get("split")).lower() in("holdout","test") and r not in samp]
samp+=hold[:max(0,4-sum(str(r.get("split")).lower() in("holdout","test") for r in samp))]
while len(samp)<22:
  pool=[r for r in rows if r not in samp]; samp.append(random.choice(pool))
samp=samp[:24]; samp.sort(key=lambda r:(r["_owner"],r["lang"],r["cwe"]))
json.dump([{"id":r["id"],"owner":r["_owner"],"lang":r["lang"],"cwe":r["cwe"],"split":r.get("split")} for r in samp],open(O+"sample_ids.json","w"),indent=1)
md=["# Checklist de overfitting — holdout realism v0.4","",f"Amostra: {len(samp)} pares de {len(rows)} (estratificada por buffer/lang/CWE). Fonte: `sample_ids.json`. Não altera FINAL v0.3-gold.","","Critérios por item:","- (a) O `after` corrige o bug real ou só silencia a regra?","- (b) Rename/ofuscação trivial do `before` ainda passaria pela regra (falso negativo)?","- (c) Sentido funcional do código (1–5).",""]
for o in B:
  ss=[r for r in samp if r["_owner"]==o]
  if not ss: continue
  md+= [f"## Fatia {o} ({len(ss)})",""]
  for r in ss:
    md+=[f"### `{r['id']}` — {r['lang']} / {r['cwe']} / split={r.get('split')} / regra `{r.get('opengrep_rule')}`","- [ ] (a) corrige de fato / só silencia: ____","- [ ] (b) rename/ofuscação passaria? (s/n): ____","- [ ] (c) sentido funcional 1–5: ____","- Revisor: ____  Obs.: ____",""]
open(O+"HOLDOUT_OVERFIT_CHECKLIST.md","w").write("\n".join(md))
print(json.dumps({k:inv[k] for k in("total","dup_ids_within_buffers","collisions_vs_final","source_issues","license_issues")}),nc,len(flags),[ (f["a"],f["b"],f["max"]) for f in flags][:10],len(samp),inv["overall"],C.Counter(r["_owner"] for r in samp))
