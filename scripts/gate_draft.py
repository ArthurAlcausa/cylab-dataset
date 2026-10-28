#!/usr/bin/env python3
"""Gate using rules-gold/<rule>.yaml when present, else rules/<rule>.yaml. Wraps gate_queue.gate via a temp union rules dir.
Usage: gate_draft.py in.jsonl --report out.json"""
import json,os,sys,tempfile
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__))); import gate_queue as gq
R=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def resolve(rule):
    for d in ("rules-gold","rules"):
        f=os.path.join(R,d,rule+".yaml")
        if os.path.isfile(f): return d,f
    return None,None
if __name__=="__main__":
    pairs=[json.loads(l) for l in open(sys.argv[1])]
    t=tempfile.mkdtemp(prefix="gateroot_"); os.mkdir(t+"/rules"); src={}
    for r in {p["opengrep_rule"] for p in pairs}:
        d,f=resolve(r); src[r]=d
        if f: os.symlink(f,f"{t}/rules/{r}.yaml")
    gq.ROOT=t; res=gq.gate(pairs); rep=[]
    for p,(b,a) in zip(pairs,res):
        rep.append(dict(id=p["id"],lang=p["lang"],rule=p["opengrep_rule"],rule_dir=src[p["opengrep_rule"]],before_hits=b,after_hits=a,passed=b>0 and a==0))
    json.dump(rep,open(sys.argv[sys.argv.index("--report")+1],"w"),indent=1)
    ok=sum(x["passed"] for x in rep); print(f"{ok}/{len(rep)} gate OK")
