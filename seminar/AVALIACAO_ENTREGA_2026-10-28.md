# Avaliação do que já foi feito — Projeto Cylab (28/10/2026)

Parecer interno para a 1ª entrega (banca PUC). Baseado nos artefatos do repositório, não em impressões.

## Veredito

**Pronto para a banca como 1ª entrega (dataset ouro + material de apresentação).** O produto final (modelo LoRA + CLI) **ainda não existe** e isso está documentado de forma honesta. A entrega prometida para agora — ouro absoluto + seminário — está fechada e revisada.

## O que está feito (evidência)

| Bloco | Status | Evidência |
|---|---|---|
| Dataset comercial v0.2 (~2k) | Feito / preservado | `data/cylab-commercial-v0.2.jsonl` (2191 pares) |
| Ouro FINAL v0.3 | Feito | `data/cylab-commercial-v0.3-gold.jsonl` — 476 pares; `gold-progress.json` status **FINAL**; SHA-256 `fe2d3846…09ca35` |
| Gate automático | 476/476 | `data/gate-report-v0.3-gold-draft-retake.json` |
| Split | Feito | 401 train / 75 holdout; 10 linguagens; 43 CWEs; 178 regras |
| Núcleos por frente | Feito | Sam 151 (py/js/ts) + Markinho 92 (java/php/C#/sql) + Elon 182 (C/C++/Bash) + 51 complemento |
| Rules-gold / taint | Feito (parcial por lang) | Taint java/php/C#; C/C++ estrutural; Bash regex; SQL regex apertado |
| Near-dup | Feito | Funil 2191→ouro; métodos documentados (Jaccard e SequenceMatcher no núcleo Sam) |
| Roteiro seminário | Feito | `seminar/ROTEIRO_SEMINARIO_PUC.md` + `seminar/demo/` |
| Slides PDF | Feito / aprovado | `seminar/CYLAB_SEMINARIO_PUC_SLIDES.pdf` (13) + `.pptx` — Sam e Markinho aprovaram |
| Doc acadêmico CONIC | Feito / aprovado | `seminar/DOC_ACADEMICO_BANCA.pdf` (+`.md`) — IMRaD, refs ABNT |

## Qualidade (o que está bom)

1. **Critério objetivo de aceite** (before≥1, after=0) torna o ouro auditável — não depende de opinião.
2. **Corte de near-clones** foi a decisão certa: volume 2191 cedeu a 476 distintos; isso é maturidade de dataset, não regressão.
3. **Material da banca alinhado** (roteiro ↔ slides ↔ doc): mesmos números, limitações explícitas, sem métrica inventada de modelo.
4. **Transparência**: taint fraco em C/C++, pares sintéticos curtos e `source` residual estão escritos — a banca valoriza isso.

## Lacunas e riscos (ainda abertos)

1. **Sem modelo treinado** — esperado nesta fase; não demonstrar geração ao vivo.
2. **65 pares com `source` sem URL da CWE** — cosmético (validador falha; gate passa). Vale corrigir antes da banca se houver tempo.
3. **Gate ≠ correção semântica** — risco de overfitting na regra; holdout + revisão humana ainda por vir.
4. **Pares curtos/sintéticos** — mediana ~6 linhas no `before`; generalização a código real é a pergunta aberta.
5. **Demo depende do ambiente** — ensaiar `demo_pair.sh` no notebook da sala; gate completo (~6 min) não rodar ao vivo.

## Nota por frente de trabalho

- **Dataset/ouro:** forte (método + números + gate).
- **Regras:** sólida, com heterogeneidade honesta entre linguagens.
- **Seminário (slides+doc+roteiro):** pronto e revisado.
- **Produto (LoRA/CLI/VS Code):** não iniciado — próxima entrega.

## Conclusão

Para o escopo que Arthur pediu agora (**ouro absoluto + 1ª entrega PUC**), o projeto está **completo e apresentável**. O que falta é operacional (ensaio da demo, opcionalmente metadados `source`) e, depois da banca, o bloco de modelo.
