import json,sys,os,statistics,difflib,glob
sys.path.insert(0,'/workspace/cylab-dataset/scripts')
P=[];
def add(lang,cwe,rule,n,before,after,expl): P.append(dict(lang=lang,cwe=cwe,rule=rule,n=n,before=before,after=after,expl=expl))
for f in ['java.py','php.py','cs.py']: exec(open(f).read())
ROOT='/workspace/cylab-dataset'; OUT=ROOT+'/contributions/markinho-java-php-sql-shell/'
existing_ids=set(); finals=[]
for f in glob.glob(ROOT+'/data/*.jsonl')+glob.glob(ROOT+'/contributions/**/*.jsonl',recursive=True):
    if 'realistic_v04' in f: continue
    for l in open(f):
        try: d=json.loads(l)
        except: continue
        existing_ids.add(d.get('id')); finals.append(d)
pairs=[]
for p in P:
    pid=f"cylab-markinho-{p['lang']}-{p['cwe']}-{p['n']}"
    assert pid not in existing_ids, pid
    pairs.append({"id":pid,"lang":p['lang'],"cwe":"CWE-"+p['cwe'],"source":f"sintetico-cylab https://cwe.mitre.org/data/definitions/{p['cwe']}.html","license":"CC-BY-4.0","opengrep_rule":p['rule'],"before":p['before'],"after":p['after'],"explanation_pt":p['expl'],"split":"train"})
import importlib.util
spec=importlib.util.spec_from_file_location("gg",ROOT+"/scripts/gate_gold.py"); gg=importlib.util.module_from_spec(spec); spec.loader.exec_module(gg)
res=gg.run(pairs)
def sh(s,k=5):
    t=s.split(); return {tuple(t[i:i+k]) for i in range(max(1,len(t)-k+1))}
keep=[];rep=[]
for p,(b,a) in zip(pairs,res):
    same=[d for d in finals if d.get('lang')==p['lang'] and d.get('cwe')==p['cwe']]
    mx=0.0
    for d in same:
        sm=difflib.SequenceMatcher(None,p['before'],d.get('before','')).ratio()
        A,B=sh(p['before']),sh(d.get('before','')); jc=len(A&B)/max(1,len(A|B))
        mx=max(mx,sm,jc)
    g=b>0 and a==0; nd=mx>=0.85
    rep.append(dict(id=p['id'],rule=p['opengrep_rule'],before_hits=b,after_hits=a,gate_pass=g,max_similarity=round(mx,3),near_dup=nd,before_lines=p['before'].count('\n'),after_lines=p['after'].count('\n')))
    print(rep[-1])
    if g and not nd: keep.append(p)
with open(OUT+'realistic_v04_candidates.jsonl','w') as f:
    for p in keep: f.write(json.dumps(p,ensure_ascii=False)+'\n')
bl=[p['before'].count('\n') for p in keep]; al=[p['after'].count('\n') for p in keep]
from collections import Counter
json.dump(dict(total_authored=len(pairs),gate_pass=sum(r['gate_pass'] for r in rep),gate_fail=[r['id'] for r in rep if not r['gate_pass']],near_dup_drops=[r['id'] for r in rep if r['near_dup']],kept=len(keep),by_lang=Counter(p['lang'] for p in keep),by_cwe=Counter(p['cwe'] for p in keep),
  before_lines=dict(min=min(bl),median=statistics.median(bl),max=max(bl)),after_lines=dict(min=min(al),median=statistics.median(al),max=max(al)),
  gate_tool="scripts/gate_gold.py run() with rules-gold active mapping",near_dup_method="SequenceMatcher + 5-token shingle Jaccard vs all data/*.jsonl and contributions/**/*.jsonl same lang+cwe, threshold 0.85",pairs=rep),open(OUT+'realistic_v04_report.json','w'),indent=1,ensure_ascii=False)
