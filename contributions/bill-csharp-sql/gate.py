import json,subprocess,tempfile,os,sys
OG=os.path.expanduser("~/.opengrep/cli/latest/opengrep")
IDS=sys.argv[1].split(",") ; RD=sys.argv[2] if len(sys.argv)>2 else "rules"
EXT={"csharp":"cs","sql":"sql"}
pairs=[]
for f in ["data/cylab-commercial-v0.3-gold-DRAFT.jsonl","contributions/markinho-java-php-sql-shell/gold_java_php_csharp_sql.jsonl"]:
  for l in open(f):
    if l.strip():
      r=json.loads(l)
      if r.get("opengrep_rule") in IDS: pairs.append((f[:5],r))
def hits(rule,code,lang):
  d=tempfile.mkdtemp(); p=f"{d}/t.{EXT.get(lang,'txt')}"; open(p,"w").write(code)
  o=subprocess.run([OG,"scan","--config",rule,"--json","--quiet",p],capture_output=True,text=True)
  try: return len(json.loads(o.stdout)["results"])
  except Exception: return -1
res={}
for src,r in pairs:
  rid=r["opengrep_rule"]; rf=f"{RD}/{rid}.yaml"
  if not os.path.exists(rf): rf=f"rules/{rid}.yaml"
  b=hits(rf,r["before"],r["lang"]); a=hits(rf,r["after"],r["lang"])
  ok=b>=1 and a==0
  res.setdefault(rid,[]).append(ok)
  if not ok: print("FAIL",rid,r["id"],src,b,a)
for k,v in sorted(res.items()): print(k,sum(v),"/",len(v))
