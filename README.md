# Cylab Dataset

Pares sintéticos originais (vulnerável → corrigido) para treinar e avaliar a correção de vulnerabilidades. Licença: CC-BY-4.0.

## Versões comerciais (gold)
- `data/cylab-commercial-v0.3-gold.jsonl`: 476 pares, selada (SHA256 `f37e1316…`).
- `data/cylab-commercial-v0.4-gold.jsonl`: 576 pares (v0.3-gold + 100 de realismo), 489 train / 87 holdout, 10 linguagens. Gate: `scripts/gate_gold.py --rules-dir rules-gold` 576/576. Metadados em `data/v0.4-gold-cut-meta.json`.
- A v0.1 abaixo continua sendo a semente do pipeline.

- `data/cylab-v0.1.jsonl` tem 38 pares em 8 linguagens e 14 CWEs (33 train, 5 holdout).
- `rules/` tem 34 regras Opengrep/Semgrep, um arquivo por `opengrep_rule`.
- `data/gate-report-v0.1.json` é o resultado do gate do Opengrep para cada par.
- `scripts/build.py` gera os dados e as regras. `scripts/gate.py` roda o gate. `scripts/validate_dataset.py` valida o schema.

## Nota comercial
A meta de dados do produto é **cerca de 2000 pares de qualidade**. A **v0.1 é apenas a semente do pipeline**, criada para exercitar o schema, as regras, os gates e o validador. Ela não foi inflada e não representa o volume de produto.

## Proveniência
Todos os pares foram escritos do zero para a Cylab. Nenhum dado de terceiros ou de lotes anteriores foi lido, importado ou convertido.

## Reproduzir
```
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
python3 scripts/build.py && python3 scripts/gate.py && python3 scripts/validate_dataset.py
```
