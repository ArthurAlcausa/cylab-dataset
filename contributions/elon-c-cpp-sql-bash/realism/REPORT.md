# Elon REALISM buffer (c/cpp/bash) — candidatos v0.4

- Gerados: 36 | gate pass: 36/36 | mantidos: 36
- Drops: 0 
- Linhas do before (mantidos): mediana 39.0, min 26, max 51
- Near-dup: limiar 0.85 (Jaccard 4-gramas normalizados e SequenceMatcher bruto) vs FINAL mesmo lang + interno; max Jaccard vs FINAL = 0.241, max SeqMatch = 0.287, max interno = 0.469
- Colisão de id com FINAL: 0 | FINAL sha256: `f37e131674bb1c01c444de40b957e1aa546703f0ff819b13b350200e47a25ea3`
- split: todos `train` (Bill resplit no v0.4). Regras: todas de `rules-gold/`.

## Por linguagem

- bash: 12
- c: 12
- cpp: 12

## Por lang/CWE

| lang | CWE | n |
|---|---|---|
| bash | CWE-214 | 1 |
| bash | CWE-250 | 1 |
| bash | CWE-295 | 1 |
| bash | CWE-312 | 1 |
| bash | CWE-377 | 1 |
| bash | CWE-494 | 2 |
| bash | CWE-732 | 1 |
| bash | CWE-78 | 2 |
| bash | CWE-798 | 1 |
| bash | CWE-88 | 1 |
| c | CWE-120 | 3 |
| c | CWE-134 | 1 |
| c | CWE-190 | 1 |
| c | CWE-242 | 1 |
| c | CWE-338 | 1 |
| c | CWE-367 | 1 |
| c | CWE-377 | 1 |
| c | CWE-732 | 1 |
| c | CWE-78 | 1 |
| c | CWE-787 | 1 |
| cpp | CWE-120 | 2 |
| cpp | CWE-134 | 2 |
| cpp | CWE-190 | 1 |
| cpp | CWE-22 | 2 |
| cpp | CWE-327 | 1 |
| cpp | CWE-338 | 1 |
| cpp | CWE-416 | 1 |
| cpp | CWE-78 | 1 |
| cpp | CWE-798 | 1 |

## Arquivos (pós-limpeza GIGO 28/10/2026)

- `elon_realism_candidates.jsonl` — lote aceito (36 pares) que entrou no buffer v0.4
- `REPORT.md` — este relatório
- Geradores (`pairs_*.py`, `gen_realism.py`, `finalize.py`) e `gate-report.json` intermediário foram removidos; o conteúdo final permanece neste JSONL.
