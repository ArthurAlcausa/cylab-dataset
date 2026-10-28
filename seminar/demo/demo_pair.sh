#!/usr/bin/env bash
# Uso: seminar/demo/demo_pair.sh <pair_id>   (rodar a partir de /workspace/cylab-dataset)
# Extrai before/after de um par do DRAFT v0.3 e roda Opengrep 1.32 com a regra do par.
set -euo pipefail
ID="${1:-cylab-bill-c-120-0613}"
DS=data/cylab-commercial-v0.3-gold-DRAFT.jsonl
OG="$HOME/.opengrep/cli/latest/opengrep"
OUT=/tmp/cylab-demo/$ID; mkdir -p "$OUT"
python3 - "$ID" "$DS" "$OUT" <<'PY'
import json,sys
pid,ds,out=sys.argv[1:]
ext=dict(python="py",javascript="js",typescript="ts",java="java",php="php",csharp="cs",c="c",cpp="cpp",sql="sql",bash="sh")
for l in open(ds):
    p=json.loads(l)
    if p["id"]==pid:
        e=ext[p["lang"]]
        open(f"{out}/before.{e}","w").write(p["before"]); open(f"{out}/after.{e}","w").write(p["after"])
        open(f"{out}/rule.txt","w").write(p["opengrep_rule"])
        print(f"# {p['id']}  lang={p['lang']}  {p['cwe']}  rule={p['opengrep_rule']}  split={p['split']}")
        print("\n## explanation_pt (alvo de treino)\n"+p["explanation_pt"]); break
else: sys.exit(f"id não encontrado: {pid}")
PY
RULE=$(cat "$OUT/rule.txt")
RF=rules-gold/$RULE.yaml; [ -f "$RF" ] || RF=rules/$RULE.yaml
echo "## regra: $RF"
for f in "$OUT"/before.* "$OUT"/after.*; do
  echo; echo "===== $(basename "$f") ====="; cat "$f"; echo
  n=$("$OG" scan --config "$RF" --json --quiet "$f" 2>/dev/null | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["results"]))')
  echo ">> achados Opengrep: $n"
done
