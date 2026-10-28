# Realism v0.4 batch — notas
- Fontes em realism_src/ (before/after por par); build: `python3 build_realism_v04.py` (re-roda gate + near-dup).
- Correções durante o gate: py-22-001 (safe_join não reconhecido → realpath+commonpath), py-89-002 (allowlist `if x not in S` no before suprimia a regra — padrão pattern-not-inside amplo), ts-89-001 (`pool.query<T>()` genérico não casa `$DB.query`), ts-89-002 (after com template literal ainda batia → queries fixas).
- Observação de regra: os sanitizers `if <... $V not in $S ...>: ... ...` em rules-gold python suprimem qualquer sink APÓS o if, não só dentro dele (possível FN).
- .venv do projeto não existe (/workspace/cylab-dataset/.venv ausente); usado python3 do sistema.
