#!/usr/bin/env python3
"""Gate generico: para cada par de um jsonl, a regra rules/<opengrep_rule>.yaml deve ter >=1 hit no before e 0 no after.
Uso: gate_queue.py arquivo.jsonl [--report out.json]. Agrupa por regra (1 execucao do opengrep por regra)."""
import json, os, subprocess, sys, tempfile, collections
EXT=dict(python="py",javascript="js",typescript="ts",java="java",php="php",csharp="cs",c="c",cpp="cpp",sql="sql",bash="sh")
OG=os.path.expanduser("~/.opengrep/cli/latest/opengrep")
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def gate(pairs):
    by=collections.defaultdict(list)
    for i,p in enumerate(pairs): by[p["opengrep_rule"]].append(i)
    res={}
    for rule,idx in by.items():
        rf=os.path.join(ROOT,"rules",rule+".yaml")
        if not os.path.isfile(rf):
            for i in idx: res[i]=(-1,-1)
            continue
        d=tempfile.mkdtemp(prefix="gate_")
        for i in idx:
            e=EXT[pairs[i]["lang"]]
            open(f"{d}/{i}_b.{e}","w").write(pairs[i]["before"]); open(f"{d}/{i}_a.{e}","w").write(pairs[i]["after"])
        o=subprocess.run([OG,"scan","--config",rf,"--json","--quiet","--no-git-ignore","-j","8",d],capture_output=True,text=True)
        cnt=collections.Counter()
        try:
            for r in json.loads(o.stdout)["results"]: cnt[os.path.basename(r["path"])]+=1
        except Exception: print(o.stderr[-800:],file=sys.stderr); 
        for i in idx:
            e=EXT[pairs[i]["lang"]]; res[i]=(cnt[f"{i}_b.{e}"],cnt[f"{i}_a.{e}"])
    return [res[i] for i in range(len(pairs))]
if __name__=="__main__":
    path=sys.argv[1]; pairs=[json.loads(l) for l in open(path)]
    r=gate(pairs); ok=0; rep=[]
    for p,(b,a) in zip(pairs,r):
        g=b>0 and a==0; ok+=g; rep.append(dict(id=p["id"],rule=p["opengrep_rule"],before_hits=b,after_hits=a,passed=g))
        if not g: print("FAIL",p["id"],p["opengrep_rule"],b,a)
    if "--report" in sys.argv: json.dump(rep,open(sys.argv[sys.argv.index("--report")+1],"w"),indent=1)
    print(f"{ok}/{len(pairs)} gate OK"); sys.exit(ok!=len(pairs))
