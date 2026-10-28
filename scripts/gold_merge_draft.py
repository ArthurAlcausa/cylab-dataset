#!/usr/bin/env python3
"""v0.3 gold DRAFT merge (self-contained; near-dup logic = my original gold_near_dup v1: 5-gram Jaccard>=0.9
on normalized before||after, stratum lang+cwe+rule-without--gold). Writes data/cylab-commercial-v0.3-gold-DRAFT.jsonl."""
import json,re,hashlib,collections
KEYS=["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
TOK=re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`|\b\d[\w.]*\b|[A-Za-z_$][\w$]*|\S')
COM=re.compile(r'(?m)(#(?!include|!).*$|//.*$|/\*[\s\S]*?\*/|^\s*--.*$)')
def toks(code):
    out=[];prev=None
    for t in TOK.findall(COM.sub(" ",code)):
        if t[0] in "\"'`": out.append("S")
        elif t[0].isdigit(): out.append("N")
        elif t[0].isalpha() or t[0] in "_$": out.append(("." if prev=="." else "")+t)
        else: out.append(t)
        prev=t
    return out
def norm(p,common):
    r=[]
    for part in ("before","after"):
        r+=[t if not(t[0].isalpha() or t[0] in "_$") or t in common else "ID" for t in toks(p[part])]+["||"]
    return r
def sh(ts,k=5): return {tuple(ts[i:i+k]) for i in range(max(1,len(ts)-k+1))}
def jac(a,b): return len(a&b)/len(a|b) if a|b else 1.0
def build_common(pairs):
    df=collections.Counter()
    for p in pairs: df.update({t for t in toks(p["before"]+"\n"+p["after"]) if t[0].isalpha() or t[0] in "_$"})
    return {t for t,c in df.items() if c>=max(3,0.01*len(pairs))}
C='contributions/'; 
nuc=[('sam',C+'sam-py-js/gold_candidates_py_js_ts.jsonl'),('markinho',C+'markinho-java-php-sql-shell/gold_java_php_csharp_sql.jsonl'),('elon',C+'elon-c-cpp-sql-bash/elon_gold.jsonl')]
fails=set(json.load(open('data/gold-progress.json'))['gate_fail_ids'])
out={};src={};dupid=0
for s,f in nuc:
  for l in open(f):
    if l.strip():
      p=json.loads(l)
      if p['id'] in out: dupid+=1; continue
      out[p['id']]={k:p[k] for k in KEYS};src[p['id']]=s
glob=[json.loads(l) for l in open('data/cylab-commercial-v0.3-gold-candidate.jsonl')]
common=build_common([json.loads(l) for l in open('data/cylab-commercial-v0.2.jsonl')])
st=lambda p:(p['lang'],p['cwe'],p['opengrep_rule'].removesuffix('-gold'))
idx=collections.defaultdict(list)
for p in out.values(): idx[st(p)].append(sh(norm(p,common)))
added=nd=0
for p in glob:
  if p['id'] in out: continue
  s=sh(norm(p,common))
  if any(jac(s,k)>=0.9 for k in idx[st(p)]): nd+=1; continue
  out[p['id']]={k:p[k] for k in KEYS};src[p['id']]='global-v0.3-candidate';idx[st(p)].append(s);added+=1
fd=[i for i in list(out) if i in fails]
for i in fd: del out[i]
asg=json.load(open(C+'elon-c-cpp-sql-bash/holdout_split_proposal_global.json'))['assignment']
splitsrc=collections.Counter()
for i,p in out.items():
  if i in asg: p['split']=asg[i]; splitsrc['elon_global_proposal']+=1
  else:
    h=int(hashlib.sha256(f"cylab-holdout-v1:{p['lang']}|{p['cwe']}|{i}".encode()).hexdigest(),16)%100
    p['split']='holdout' if h<10 else 'train'; splitsrc['hash_10pct']+=1
json.dump(dict(src=src,dup_ids_across_nuclei=dupid,global_added=added,global_skipped_near_dup=nd,dropped_known_gate_fail=fd,split_source=splitsrc),open('/tmp/w/merge_meta.json','w'))
with open('data/cylab-commercial-v0.3-gold-DRAFT.jsonl','w') as o:
  for p in out.values(): o.write(json.dumps(p,ensure_ascii=False)+'\n')
print(len(out),dupid,added,nd,fd,splitsrc)
