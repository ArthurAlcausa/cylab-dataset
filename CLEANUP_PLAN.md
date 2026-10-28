# Plano de limpeza Cylab (atualizado 2026-10-28)

Alerta (Elon/`f473de5`): não apagar artefatos **citados no DOC** sem `data/archive/` + atualizar o DOC.

## KEEP
- FINALs `v0.3-gold` / `v0.4-gold` + metas/gates
- `v0.2`, `v0.1`, `v0.4-realism-DRAFT` (citados)
- `rules/` + `rules-gold/`
- `seminar/`
- scripts canônicos de gate/validate/near-dup
- Núcleos por frente (`*gold*.jsonl`) + buffers realism por frente + `realism-v04-cross/`

## REMOVE ok
- queues, `.bak`, candidates/DRAFTs supersedidos (não citados)
- batches brutos (`bill-scale`, `sam_batch*`)
- `__pycache__`, JPG híbrida se PNG canônico basta
- backups locais de rules / staging / SQL-taint abandonado (fatia Sam)

## Sam (esta rodada)
- Restaurado: `gold_realism_v0.4_candidates.jsonl` (15 pares da frente)
- Removido: staging, rules-*-backup, sql_taint abandonado, relaxed report, gate_report_gold_candidates
