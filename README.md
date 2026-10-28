# Cylab Dataset

Pares sintéticos originais (vulnerável → corrigido) para treinar e avaliar a correção de vulnerabilidades. Licença: CC-BY-4.0. Repositório público: https://github.com/ArthurAlcausa/cylab-dataset

## Versão atual: v0.4-gold
- `data/cylab-commercial-v0.4-gold.jsonl`: **576 pares** (v0.3-gold + 100 de realismo), 489 train / 87 holdout, 10 linguagens.
- Gate: `python3 scripts/gate_gold.py --rules-dir rules-gold` → 576/576. Relatório: `data/gate-report-v0.4-gold.json`.
- Metadados: `data/v0.4-gold-cut-meta.json`, `data/v0.4-realism-merge-meta.json`, `data/near-dup-v0.4-realism-draft.json`, `data/gold-near-dup-report.json`.

## Linhagem
- `data/cylab-commercial-v0.2.jsonl` (+ `.sha256`): base do funil citada no seminário.
- `data/cylab-commercial-v0.3-gold.jsonl`: 476 pares, selada (SHA256 `f37e1316…`).

## Estrutura
- `rules-gold/`: regras Opengrep autoritativas do gate gold. `rules/`: regras legadas.
- `scripts/`: gate, validação e build.
- `contributions/`: scripts, regras e relatórios por trilha; `contributions/realism-v04-cross/` guarda a auditoria (HOLDOUT, MERGE/FINAL cut).
- `seminar/`: entrega 1 (PPTX, PDF dos slides, DOC acadêmico md/pdf, roteiro, assets, demo).
- `SCHEMA.md`, `GATES.md`, `CHANGELOG.md`.

## Nota comercial
A meta do produto é **cerca de 2000 pares de qualidade**.

## Proveniência
Todos os pares foram escritos do zero para a Cylab. Nenhum dado de terceiros foi importado ou convertido.

## Reproduzir o gate
```
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
python3 scripts/gate_gold.py --rules-dir rules-gold
```
