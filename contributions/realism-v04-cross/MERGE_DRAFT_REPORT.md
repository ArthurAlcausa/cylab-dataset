# v0.4 Realism — MERGE DRAFT REPORT

_Gerado 2026-10-28 (BRT). DRAFT apenas — v0.3-gold selado, nada promovido._

- Draft: `data/cylab-commercial-v0.4-realism-DRAFT.jsonl` — **100 pares**, 10 chaves gold, 0 colisões de id (vs buffers e vs v0.3), 0 lacunas de schema.
- Build reprodutível: `scripts/build_v04_realism_draft.py` (somente leitura nos buffers fonte e no v0.3).

## Contagens

- **by_owner**: `{"markinho": 18, "bill": 31, "elon": 36, "sam": 15}`
- **by_lang**: `{"java": 6, "php": 6, "csharp": 6, "sql": 31, "c": 12, "cpp": 12, "bash": 12, "javascript": 5, "python": 6, "typescript": 4}`
- **by_split**: `{"holdout": 12, "train": 88}`
- **split_by_owner**: `{"markinho": {"holdout": 3, "train": 15}, "bill": {"train": 28, "holdout": 3}, "elon": {"train": 33, "holdout": 3}, "sam": {"holdout": 3, "train": 12}}`
- **by_cwe**: `{"CWE-78": 12, "CWE-22": 8, "CWE-502": 3, "CWE-79": 6, "CWE-918": 3, "CWE-90": 1, "CWE-95": 1, "CWE-601": 1, "CWE-89": 23, "CWE-269": 2, "CWE-798": 7, "CWE-256": 3, "CWE-426": 2, "CWE-120": 5, "CWE-134": 3, "CWE-242": 1, "CWE-377": 2, "CWE-732": 2, "CWE-190": 2, "CWE-338": 2, "CWE-367": 1, "CWE-787": 1, "CWE-327": 1, "CWE-416": 1, "CWE-494": 2, "CWE-214": 1, "CWE-295": 1, "CWE-312": 1, "CWE-250": 1, "CWE-88": 1}`

**Split:** holdouts do Sam mantidos (3). Demais donos: holdout sse `int(sha256(id),16) % 10 == 0` (dentro deste buffer apenas; v0.3 não re-embaralhado) → 12 holdout / 88 train.
Holdout ids: cylab-markinho-java-78-r001, cylab-markinho-java-918-r001, cylab-markinho-java-90-r001, cylab-bill-sqlreal-269-grant-all-public-01, cylab-bill-sqlreal-798-link-mapping-password-01, cylab-bill-sqlreal-426-security-definer-no-path-02, cylab-elon-real-c-78-0001, cylab-elon-real-c-338-0001, cylab-elon-real-c-787-0001, cylab-sam-real-js-22-001, cylab-sam-real-py-78-002, cylab-sam-real-ts-79-001

## Gate

`gate_gold.py --rules-dir rules-gold` → **100/100** (`data/gate-report-v0.4-realism-draft.json`). `validate_dataset.py` também passou (OK: 100 pares, 12 holdout).

## Near-dup (mesma lang+cwe)

- Método Markinho/Bill (SequenceMatcher no `before` + Jaccard 5-token, thr 0.85): intra max 0.857, vs v0.3 max 0.376 (792 comparações).
- Único sinal: `cylab-bill-sqlreal-89-string-concat-02` × `cylab-bill-sqlreal-89-tsql-sql-var-concat-01` (SeqMatcher 0.857, Jaccard-5 0.52; `gold_near_dup.py` Jaccard-4 normalizado 0.914). Regras diferentes, `after` distintos → política keep≤2 mantém ambos.
- `gold_near_dup.py` draft+v0.3 combinado: nenhum par do draft agrupa com v0.3 (os 112 drops do combinado são clusters internos pré-existentes do v0.3, fora de escopo).
- **Drops: 0 → mantidos 100.**

## Checklist

`HOLDOUT_OVERFIT_CHECKLIST.md`: **24/24** preenchido.

## SHA256

- Draft: `ca5e020164f948173e7921270ac9790537379c0211be031ebc5b0216ffb4319e`
- v0.3-gold antes: `f37e131674bb1c01c444de40b957e1aa546703f0ff819b13b350200e47a25ea3`
- v0.3-gold depois: `f37e131674bb1c01c444de40b957e1aa546703f0ff819b13b350200e47a25ea3` (idêntico, prefixo f37e1316 ✔)

## Próximos passos

1. Avaliação humana da amostra de 24 (`sample_ids.json`) + revisão do par SQL quase-dup.
2. Decisão de holdout final (12 hash vs só 3 do Sam).
3. Promoção opcional: novo arquivo `cylab-commercial-v0.4-gold.jsonl` = v0.3 + draft, re-gate, novo SHA; nunca sobrescrever v0.3.
