# Gates
1. **Ferramenta**: Opengrep 1.32.0 instalado pelo script oficial em `~/.opengrep/cli/latest/opengrep`.
2. **Hit/clean** (`scripts/gate.py`): cada par precisa ter mais de 0 achados da sua regra no `before` e 0 achados no `after`. Resultado da v0.1: **38/38 PASS** (veja `data/gate-report-v0.1.json`). Duas regras foram corrigidas durante o gate: `javascript.path-traversal`, para aceitar path.join com N argumentos, e `typescript.xss-dangerously-set`, que passou para pattern-regex com aspas no YAML. Nenhum par foi descartado.
3. **Schema** (`scripts/validate_dataset.py`): campos obrigatórios e não vazios, allowlist de linguagens, formato da CWE e da source, licença, opengrep_rule não nulo e com arquivo de regra, before diferente de after, split válido, pelo menos 4 holdout e nenhuma string proibida. Resultado: OK.

Limitação: as regras são deliberadamente simples (sintáticas) e calibradas para estes pares. Antes de escalar para cerca de 2000 pares, elas devem ser endurecidas com taint mode e testadas contra falsos positivos.
