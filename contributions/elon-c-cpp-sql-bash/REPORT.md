# Elon — ouro C / C++ / Bash (SQL ficou com o Markinho)

## Números
| etapa | c | cpp | bash | total |
|---|---|---|---|---|
| input (v0.2 selado, só leitura) | 194 | 207 | 201 | **602** |
| near-dup thr 0.85 (`gold_near_dup.py`) | 54 | 74 | 54 | **182** (420 descartados, 65 clusters) |
| re-gate com as rules `-gold` | 54 | 74 | 54 | **182/182 PASS** (0 FAIL, 0 descartados) |

- Clusters com 10 ou mais membros no input: 22 (o maior tem 20, em cylab.cpp.std-system). Cada um ficou com 1 ou 2 exemplares (medoide e o membro mais distante). Depois do corte, a rule com mais pares é cylab.cpp.cstr-copy-unbounded, com 15 pares distintos. Nenhuma rule ficou com dezenas de clones.
- Os cortes em 0.80, 0.85, 0.90, 0.95 e 0.99 dão os mesmos 182, porque os clusters são clones exatos de template. Por isso a **faixa relaxada (0.90) está vazia**: `elon_gold_relaxed.jsonl` tem 0 linhas. O núcleo inteiro já serve de base para o merge do Bill.
- `validate_dataset.py`: OK, 182 pares, 16 holdout (split atual herdado da v0.2). Nenhuma ocorrência de vigia/cimbra.
- O SHA-256 da v0.2 continua `aa0f9929…164cd3`, sem alteração.

## Rules endurecidas: 45 (todas com nome novo `cylab.<lang>.<slug>-gold`)
As rules originais em `rules/` **não foram tocadas**. As `-gold` vivem em `rules-gold/` (canônico no repo). Cópia local em `contributions/.../rules/` e o gerador `make_gold_rules.py` foram removidos na limpeza GIGO de 28/10/2026 (eram duplicatas bit-a-bit de `rules-gold/`).
- **C (15) e C++ (16):** 30 viraram patterns estruturados, com metavariáveis, `pattern-not` para literal (printf/fprintf/syslog), `metavariable-regex` (modo 0777/0666, campo len/size, algoritmos fracos do OpenSSL), `pattern-inside`/sequência para TOCTOU access→open e `std::` explícito. Duas continuam em regex ancorada em declaração: cpp.hardcoded-key-literal, porque o parser C++ do Opengrep 1.32 não casa `static const std::string X = "..."`, e cpp.dangling-cstr. Em c.scanf-unbounded-s, o padrão estrutural `scanf(...)` é intersectado com uma regex sobre o formato `%s`.
- **Bash (14):** o suporte estrutural do Opengrep para bash é fraco, então essas rules usam regex restrita a linhas não comentadas (`^(?!\s*#)`, sem `#` antes do match) e com word boundaries. Comentário não dispara mais.

## Limitação taint
Não usamos `mode: taint`. No Opengrep 1.32, taint não produziu hits em C/C++ nos testes, então todo o endurecimento foi feito com padrões estruturais. É preciso revisitar quando houver um Opengrep com taint funcional para C.

## Proposta de holdout/split global (não aplicada)
Script: `holdout_split_proposal.py`. Os pares são agrupados por estrato (lang, rule sem `-gold`) e ordenados por sha256("cylab-holdout-v1:"+id). Vão para holdout floor(15%) de cada estrato, com mínimo de 1 quando o estrato tem 3 ou mais pares; estratos com 2 ou menos ficam todos em train. A ordem é determinística e estável a inclusões.
- Global (`data/cylab-commercial-v0.3-gold-candidate.jsonl`, 722 pares): 134 holdout, 176 estratos → `holdout_split_proposal_global.json`
- Fatia Elon (182 pares): 33 holdout (proposta local; JSON intermediário removido na limpeza GIGO). O `elon_gold.jsonl` mantém o split da v0.2.

## Artefatos (pós-limpeza GIGO 28/10/2026)
`elon_gold.jsonl`, `gold_near_dup_report.json` (thr 0.85), `holdout_split_proposal.py`, `holdout_split_proposal_global.json`, `REPORT.md`, `realism/elon_realism_candidates.jsonl` + `realism/REPORT.md`. Staging/relaxed/generators/cópia de rules foram removidos.
