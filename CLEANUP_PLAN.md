# Plano de limpeza Cylab (2026-10-28)

## Manter (canônico)
- `data/cylab-commercial-v0.4-gold.jsonl` + `v0.4-gold-cut-meta.json` + `gate-report-v0.4-gold.json`
- `data/cylab-commercial-v0.3-gold.jsonl` + `gold-progress.json` + `gate-report-v0.3-gold-draft-retake.json` + `source-fix-2026-10-28.md`
- `data/cylab-commercial-v0.4-realism-DRAFT.jsonl` + `v0.4-realism-merge-meta.json` (fonte do buffer)
- `data/cylab-commercial-v0.2.jsonl` (+ sha) — histórico do funil
- `data/cylab-v0.1.jsonl` + `gate-report-v0.1.json` — semente
- `rules/` + `rules-gold/`
- `scripts/` canônicos: `gate*.py`, `validate_dataset.py`, `gold_near_dup.py`, `build.py`, `gen_taint_rules.py`, `build_v04_realism_draft.py`
- `seminar/` (slides, DOC, assets, roteiro)
- `contributions/*/…` núcleos gold + buffers realism + `realism-v04-cross/`
- README, SCHEMA, GATES, CHANGELOG, .gitignore

## Remover (lixo / intermediário) — aguardando OK do Arthur
### data/
- `cylab-commercial-v0.3-gold-DRAFT.jsonl`
- `cylab-commercial-v0.3-gold-candidate.jsonl`
- `gate-report-v0.3-candidate*.json` (3 arquivos)
- `gate-report-v0.3-gold-draft.json` (ficar só o `-retake`)
- `gate-report-v0.2-full.json`, `gate-report-bill.json`
- `queue-bill.jsonl`, `queue-sam.jsonl`, `queue-markinho.jsonl`, `queue-sam-dedupe-report.json`
- `scale-progress.json`, `gold-rule-audit.json` (opcional: mover pra `archive/` se quiser auditoria)

### contributions/
- `bill-scale/` (lotes brutos da escala v0.2; já no `v0.2.jsonl`)
- `sam-py-js/sam_batch*.jsonl`, `_raw_v0.1_staging/`, `rules-*-backup/`, `gold_py_js_ts_relaxed.jsonl` (se o núcleo `gold_py_js_ts.jsonl` basta)
- Relatórios SQL taint abandonados em `sam-py-js/` (`gate_report_sql_flow.json`, `gold_sql_taint_*`)
- `bill-csharp-sql/` se for stub morto (12K)

### scripts/
- Geradores one-shot antigos: `bill_generate*.py`, `bill_templates*.py`, `bill_finalize.py`, `build_sam_batch*.py`, `build_v0_1_gold.py` (após confirmar que não são citados no DOC)

## Já limpo nesta rodada
- `__pycache__/`
- `data/queue-sam.jsonl.bak-pre-dedupe`
- pastas de trabalho `/workspace/slides/cylab-*` (fora do git)
