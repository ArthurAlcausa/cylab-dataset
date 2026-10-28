# Realism v0.4 — cross-check (holdout/overfitting)

- **Total: 100 pares** — markinho 18 (java/php/csharp), bill 31 (sql), elon 36 (c/cpp/bash), sam 15 (py/js/ts). Split: 97 train / 3 holdout (todos do Sam).
- **Colisões de id:** 0 entre buffers, 0 vs FINAL v0.3-gold.
- **Source/licença:** 100/100 com URL CWE coerente com o campo `cwe` e CC-BY-4.0.
- **Near-dup entre buffers (≥0,85, mesma lang+CWE):** 0 — nenhum par comparável (buffers não compartilham linguagem). Near-dup intra-buffer/vs FINAL fica com os relatórios de cada dono.
- **Linhas (`before`):** geral mediana 34, min 25, máx 51. Por buffer: markinho 34 (30–40), bill 34 (25–41), elon 39 (26–51), sam 33 (29–35).
- **Amostra para revisão humana:** 24 ids, estratificados por buffer/lang/CWE, incluindo os 3 holdout → `sample_ids.json` (campo `owner` para cada dono revisar sua fatia).
- **Checklist:** `contributions/realism-v04-cross/HOLDOUT_OVERFIT_CHECKLIST.md`.
- FINAL v0.3-gold intocado; nada mesclado. Próximo passo: preencher checklist → Bill prepara draft de merge v0.4.
