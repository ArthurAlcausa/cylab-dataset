import json,subprocess,tempfile,os,sys
EXT=dict(python="py",javascript="js",typescript="tsx",java="java",php="php",csharp="cs",c="c",cpp="cpp",sql="sql",bash="sh")
OG=os.path.expanduser("~/.opengrep/cli/latest/opengrep")
def hits(rule,code,ext):
    d=tempfile.mkdtemp(); fp=os.path.join(d,"t."+ext); open(fp,"w").write(code)
    o=subprocess.run([OG,"scan","--config",rule,"--json","--quiet",fp],capture_output=True,text=True)
    try: return len(json.loads(o.stdout)["results"])
    except Exception: print(o.stderr[-800:]); return -1
ok=0;rows=[json.loads(l) for l in open("data/cylab-v0.1.jsonl")];out=[]
for p in rows:
    r=f"rules/{p['opengrep_rule']}.yaml"; e=EXT[p["lang"]]
    b,a=hits(r,p["before"],e),hits(r,p["after"],e); g=b>0 and a==0; ok+=g
    out.append(dict(id=p["id"],rule=p["opengrep_rule"],before_hits=b,after_hits=a,passed=g))
    print(("PASS" if g else "FAIL"),p["id"],p["opengrep_rule"],b,a)
json.dump(out,open("data/gate-report-v0.1.json","w"),indent=1)
print(f"{ok}/{len(rows)}"); sys.exit(ok!=len(rows))
