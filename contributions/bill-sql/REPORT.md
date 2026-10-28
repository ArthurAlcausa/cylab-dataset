# Bill — buffer de realismo SQL (v0.4)

Buffer apenas (split=train); não mesclado. `data/cylab-commercial-v0.3-gold.jsonl` não foi tocado.

## Artefatos
- `realism/gen_sql_realism.py` — gerador (4 preâmbulos por dialeto PG/MySQL/T-SQL/Oracle × 6 domínios comerciais + núcleo vuln/fix por par)
- `realism_buffer.jsonl` — 31 pares, schema gold, license CC-BY-4.0, source `sintetico-cylab https://cwe.mitre.org/data/definitions/<n>.html`
- `realism/sql-<cwe>-NNN.before.sql/.after.sql` — mesmos pares em arquivo
- `gate_report.json` — saída do gate

## Cobertura (14/14 regras cylab.sql.* de rules-gold)
| regra | pares |
|---|---|
| string-concat | 3 |
| hardcoded-db-password | 3 |
| plaintext-password-column | 3 |
| mysql-prepare-concat, plpgsql-execute-concat, tsql-exec-concat, tsql-sql-var-concat, execute-immediate, oracle-execute-immediate, xp-cmdshell, grant-all-public, link-mapping-password, security-definer-no-path, pg-format-unsafe-s | 2 cada |

CWEs: 89 (17), 798 (5), 256 (3), 426 (2), 269 (2), 78 (2).

## Tamanho
Linhas do before: mediana 34, média 34.1, min 25, max 41 (gold v0.3 SQL: 34 pares, média 4.0).

## Gate
- `scripts/gate_gold.py ... --rules-dir rules-gold`: **31/31 OK** (before dispara, after limpo).
- Varredura cruzada: os 31 afters, escaneados contra as 14 regras SQL juntas: 0 achados.
- `validate_dataset.py` falha só porque procura as regras em `rules/` (legado) e exige holdout; esperado para um buffer. Revalidar na mesclagem da v0.4.

## Re-rodar
```
cd /workspace/cylab-dataset
python3 contributions/bill-sql/realism/gen_sql_realism.py
python3 scripts/gate_gold.py contributions/bill-sql/realism_buffer.jsonl --rules-dir rules-gold --report contributions/bill-sql/gate_report.json
```
Observação: os pares compartilham preâmbulos por dialeto/domínio, então rode `gold_near_dup.py` na mesclagem (os núcleos são distintos).
