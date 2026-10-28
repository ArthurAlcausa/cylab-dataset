#!/usr/bin/env python3
"""Gate igual a gate_queue.py, mas resolve regra por mapping: rules-gold/<id>.yaml se existir em rules-gold/mapping.json (status=taint), senao rules/<id>.yaml.
Uso: gate_gold.py arq.jsonl [--report out.json] [--rules-dir DIR] (DIR forca um diretorio unico, com fallback para rules/)."""
import json,os,sys,importlib.util
H=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(H)
spec=importlib.util.spec_from_file_location("gq",os.path.join(H,"gate_queue.py")); gq=importlib.util.module_from_spec(spec); spec.loader.exec_module(gq)
def run(pairs,rules_dir=None):
    mp={}
    mf=os.path.join(ROOT,"rules-gold","mapping.json")
    if rules_dir is None and os.path.isfile(mf):
        mp={k:v for k,v in json.load(open(mf)).items() if v.get("active")}
    tmp=os.path.join("/tmp","gate_gold_rules"); os.makedirs(tmp,exist_ok=True)
    # build a rules dir view
    import shutil; shutil.rmtree(tmp); os.makedirs(os.path.join(tmp,"rules"))
    for p in set(x["opengrep_rule"] for x in pairs):
        src=os.path.join(ROOT,"rules",p+".yaml")
        if rules_dir and os.path.isfile(os.path.join(rules_dir,p+".yaml")): src=os.path.join(rules_dir,p+".yaml")
        elif p in mp: src=os.path.join(ROOT,mp[p]["path"])
        if os.path.isfile(src): shutil.copy(src,os.path.join(tmp,"rules",p+".yaml"))
    gq.ROOT=tmp
    return gq.gate(pairs)
if __name__=="__main__":
    a=sys.argv; pairs=[json.loads(l) for l in open(a[1])]
    rd=a[a.index("--rules-dir")+1] if "--rules-dir" in a else None
    r=run(pairs,rd); ok=0; rep=[]
    for p,(b,af) in zip(pairs,r):
        g=b>0 and af==0; ok+=g; rep.append(dict(id=p["id"],rule=p["opengrep_rule"],before_hits=b,after_hits=af,passed=g))
        if not g: print("FAIL",p["id"],p["opengrep_rule"],b,af)
    if "--report" in a: json.dump(rep,open(a[a.index("--report")+1],"w"),indent=1)
    print(f"{ok}/{len(pairs)} gate OK"); sys.exit(ok!=len(pairs))
