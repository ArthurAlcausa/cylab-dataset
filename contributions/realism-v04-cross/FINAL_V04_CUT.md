# Corte FINAL v0.4-gold (28/10/2026, 09:08 BRT)

- Saída: `data/cylab-commercial-v0.4-gold.jsonl` com **576 pares** (476 da v0.3-gold + 100 de `data/cylab-commercial-v0.4-realism-DRAFT.jsonl`), sem colisões de id, as 10 chaves gold preservadas.
- Split: 489 train / 87 holdout. Linguagens: cpp 86, python 74, javascript 68, c 67, bash 67, sql 65, java 40, php 39, typescript 37, csharp 33.
- SHA256 v0.4-gold: `ea328aef50b1dba1645af8318ab576a5a206ad41ba065d24cab0dad958b9806c`
- SHA256 v0.3-gold (intocada, conferida antes e depois): `f37e131674bb1c01c444de40b957e1aa546703f0ff819b13b350200e47a25ea3`
- Gate: `scripts/gate_gold.py --rules-dir rules-gold`: **576/576 OK** (`data/gate-report-v0.4-gold.json`).
- `scripts/validate_dataset.py`: OK, 576 pares, 87 holdout.
- Near-dup: 0 descartes já no draft (`cross_near_dup_report.json`), não recalculado.
- O arquivo DRAFT de realismo foi preservado. Metadados em `data/v0.4-gold-cut-meta.json`.
- Próximo passo (opcional): onda de taint. Nada foi enviado ao GitHub.
