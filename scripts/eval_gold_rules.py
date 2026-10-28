#!/usr/bin/env python3
"""Avalia cada regra candidata (rules-gold/candidates) isoladamente contra os pares v0.2 que a usam. Saida: rules-gold/eval.json"""
import json,os,sys,subprocess,collections
from concurrent.futures import ThreadPoolExecutor
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0,os.path.join(ROOT,"scripts")); import importlib.util
spec=importlib.util.spec_from_file_location("gq",os.path.join(ROOT,"scripts/gate_queue.py")); gq=importlib.util.module_from_spec(spec); spec.loader.exec_module(gq)
src=sys.argv[1] if len(sys.argv)>1 else os.path.join(ROOT,"data/cylab-commercial-v0.2.jsonl")
P=[json.loads(l) for l in open(src)]; by=collections.defaultdict(list)
for p in P: by[p["opengrep_rule"]].append(p)
cd=os.path.join(ROOT,"rules-gold","candidates")
def ev(rid):
    import tempfile,shutil
    d=tempfile.mkdtemp(); os.makedirs(d+"/rules"); shutil.copy(f"{cd}/{rid}.yaml",f"{d}/rules/{rid}.yaml")

    pairs=by[rid]
    # local gate

    rf=f"{d}/rules/{rid}.yaml"; w=tempfile.mkdtemp()
    for i,p in enumerate(pairs):
        e=gq.EXT[p["lang"]]; open(f"{w}/{i}_b.{e}","w").write(p["before"]); open(f"{w}/{i}_a.{e}","w").write(p["after"])
    o=subprocess.run([gq.OG,"scan","--config",rf,"--json","--quiet","--no-git-ignore","-j","2",w],capture_output=True,text=True)
    try: J=json.loads(o.stdout); cnt=collections.Counter(os.path.basename(r["path"]) for r in J["results"]); errs=[e.get("message","")[:200] for e in J.get("errors",[])]
    except Exception: cnt=collections.Counter(); errs=[o.stderr[-300:]]
    fails=[]
    for i,p in enumerate(pairs):
        e=gq.EXT[p["lang"]]; b,a=cnt[f"{i}_b.{e}"],cnt[f"{i}_a.{e}"]
        if not(b>0 and a==0): fails.append(dict(id=p["id"],before_hits=b,after_hits=a))
    return rid,dict(pairs=len(pairs),passed=len(pairs)-len(fails),fails=fails,errors=errs[:3])
ids=sorted(f[:-5] for f in os.listdir(cd) if f.endswith(".yaml") and f[:-5] in by)
with ThreadPoolExecutor(6) as ex: res=dict(ex.map(ev,ids))
json.dump(res,open(os.path.join(ROOT,"rules-gold","eval.json"),"w"),indent=1)
for k,v in res.items(): print(v["passed"],"/",v["pairs"],k)
