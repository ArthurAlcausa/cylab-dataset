# Cylab — Roteiro do Seminário (PUC Campinas, banca)

> **Status deste documento:** ROTEIRO, não são os slides finais. Dataset ouro atual: **FINAL v0.4-gold** (`data/cylab-commercial-v0.4-gold.jsonl`, **576 pares** = v0.3-gold 476 + buffer de realismo 100, gate 576/576, 489 train / 87 holdout; metadados em `data/v0.4-gold-cut-meta.json`). Corte anterior: FINAL v0.3-gold (476, gate 476/476). Diagrama de arquitetura para o slide 4: `seminar/assets/cylab-arquitetura.png` (SVG e Mermaid ao lado).
> **Duração-alvo:** 25 min de apresentação + 5 a 10 min de perguntas (cabe entre 20 e 30 min; veja a versão de 20 min no fim).
> **Público:** banca e professores da PUC Campinas.
> **Tom:** acadêmico e direto. Toda afirmação numérica vem de um artefato do repositório (caminho indicado). Nada de métrica de desempenho do modelo, porque **ainda não existe modelo treinado**.

---

## 0. Mensagem central (decorar)

> "A Cylab é um assistente open-source que roda 100% local. Ele lê código, aponta vulnerabilidades, explica o problema em português e propõe um patch. A detecção fica com uma ferramenta determinística (Opengrep). O modelo de linguagem não decide se existe vulnerabilidade: ele explica e corrige. Nesta primeira entrega mostramos a base disso, que é um dataset ouro de pares vulnerável → corrigido, validado automaticamente."

**Fio condutor:** problema → abordagem híbrida → dataset ouro → status atual → próximos passos.

---

## 1. Roteiro minuto a minuto (25 min)

| Tempo | Bloco | Slide(s) |
|---|---|---|
| 00:00–01:30 | Abertura e motivação | 1–2 |
| 01:30–04:30 | Problema | 3 |
| 04:30–08:30 | Abordagem híbrida (SAST + LLM) | 4–5 |
| 08:30–14:30 | Dataset ouro: método e números | 6–9 |
| 14:30–19:00 | Demo ao vivo | 10 |
| 19:00–21:30 | Status atual, limitações e honestidade | 11 |
| 21:30–24:00 | Próximos passos (modelo, CLI, VS Code) | 12 |
| 24:00–25:00 | Fechamento | 13 |
| 25:00–35:00 | Perguntas da banca | 14 (backup) |

### 00:00–01:30 · Abertura (slides 1–2)
- Apresentar o grupo e o projeto: Cylab, PUC Campinas.
- **Fala-chave:** "Hoje não vamos apresentar um produto pronto. Esta é a primeira entrega: mostramos o problema, a arquitetura que escolhemos e a base de dados que construímos para treinar e avaliar o assistente. O restante do produto vem nas próximas entregas."
- Mostrar a agenda em uma linha: problema, abordagem, dataset, demo, status, próximos passos.

### 01:30–04:30 · Problema (slide 3)
- Três dores:
  1. Ferramentas SAST apontam o problema, mas a mensagem é curta, em inglês e não traz a correção para o código do desenvolvedor.
  2. Assistentes de código baseados em LLM na nuvem exigem enviar código-fonte (às vezes proprietário) para terceiros. Muitas empresas e órgãos públicos não podem fazer isso.
  3. Um LLM sozinho alucina: inventa vulnerabilidades que não existem e deixa passar outras. Não dá para auditar isso.
- **Fala-chave:** "A pergunta do projeto é: dá para ter explicação e correção em português, sem que o código saia da máquina, e sem confiar no LLM para decidir o que é vulnerável?"
- Escopo de linguagens: Python, JavaScript/TypeScript, Java, PHP, C#, C, C++, SQL e Shell/Bash.

### 04:30–08:30 · Abordagem híbrida (slides 4–5)
- Pipeline (desenhar como diagrama no slide 4):
  `código → Opengrep (regras Cylab) → achado {regra, CWE, trecho} → LLM local (Ollama) → explicação pt-BR + patch → re-scan Opengrep do patch`
- **Divisão de responsabilidades:**
  - Opengrep **detecta**. É determinístico, auditável e cada achado tem uma regra e uma CWE.
  - O modelo **explica e propõe o patch**. Ele recebe o achado como contexto e não "procura" vulnerabilidade sozinho.
  - O mesmo Opengrep **confere o patch**: o trecho corrigido precisa dar 0 achados da regra.
- **Fala-chave:** "O LLM entra onde ele é bom, que é linguagem e reescrita de código. A decisão sobre o que é vulnerável continua com a ferramenta que dá para auditar."
- Slide 5: por que local e open-source. Privacidade do código, custo zero por consulta, reprodutibilidade, uso em sala de aula e em ambiente sem internet.
- Modelo planejado (citar como **plano**, não como resultado): Qwen2.5-Coder-14B como primeira base e depois Qwen3.8-27B, com fine-tuning LoRA/QLoRA, servido via Ollama, com interface por CLI e extensão VS Code.

### 08:30–14:30 · Dataset ouro (slides 6–9)
**Slide 6: o que é um par.** Mostrar um registro do schema (`SCHEMA.md`): `id, lang, cwe, source, license, opengrep_rule, before, after, explanation_pt, split`.
- **Fala-chave:** "Cada exemplo é um par: o código vulnerável, o código corrigido completo, a regra Opengrep que pega o problema e uma explicação em português que cita a CWE. A licença é CC-BY-4.0 e todos os pares foram escritos do zero para a Cylab."

**Slide 7: o gate automático (critério de aceite).**
- Um par só entra se a sua regra der **> 0 achados no `before`** e **0 achados no `after`** (`GATES.md`, `scripts/gate_draft.py`).
- Também passa pelo validador de schema (`scripts/validate_dataset.py`).
- **Fala-chave:** "Isso transforma 'o patch está certo?' em um teste objetivo. Não é prova de correção semântica, mas garante que a vulnerabilidade marcada some e que o par é consistente com a regra."

**Slide 8: do volume para a qualidade (funil).**
- v0.1: semente com 38 pares, só para exercitar o pipeline.
- v0.2 comercial: **2.191 pares**, 10 linguagens (meta de ~2 mil), sem dados VigIA.
- Problema encontrado na v0.2: muitos pares eram *near-clones* gerados a partir do mesmo template. Exemplo da fatia C/C++/Bash: entraram 602 pares e, após deduplicação por similaridade (limiar 0,85), ficaram 182 (`contributions/elon-c-cpp-sql-bash/REPORT.md`).
- **Fala-chave:** "Volume não é qualidade. Um dataset com 20 variações do mesmo `system()` ensina o modelo a decorar o template, não a entender a falha. Por isso cortamos clones antes de chamar qualquer coisa de ouro."

**Slide 9: Ouro FINAL v0.4-gold: números.** Fonte: `data/cylab-commercial-v0.4-gold.jsonl` + `data/v0.4-gold-cut-meta.json` (v0.4) e `data/gold-progress.json` (`gold_final`, v0.3).
- **Atual: 576 pares**, gate **576/576** (`scripts/gate_gold.py --rules-dir rules-gold`), split 489 train / 87 holdout. São os 476 da v0.3 sem alteração + **100 pares de realismo** (funções de 26 a 52 linhas, mediana 35; 0 near-dup contra a v0.3).
- Corte anterior v0.3-gold: **476 pares**, gate **476/476**.
- Origem: Sam 151 (Python/JS/TS) + Markinho 92 (Java/PHP/C#/SQL) + Elon 182 (C/C++/Bash) + 51 do conjunto candidato global que não eram near-dup.
- Split: 401 train / 75 holdout.
- 10 linguagens presentes (nenhuma faltando).
- Regras endurecidas: 314 dos 476 pares são verificados por regras `-gold` endurecidas e 162 ainda pelas regras originais.
- **Fala-chave:** "O número é menor que o da v0.2 de propósito. Preferimos 476 pares distintos e verificados a 2 mil com repetição."
- **Dizer explicitamente:** "O status oficial é **FINAL v0.4-gold** (576 pares); a v0.3-gold (476) é o corte anterior e está contida nela."

### 14:30–19:00 · Demo ao vivo (slide 10)
Roteiro da demo (comandos na seção 3):
1. (30 s) Mostrar o FINAL v0.4-gold: 576 pares, gate 576/576 (`data/v0.4-gold-cut-meta.json`); a v0.3 (476) segue registrada em `gold-progress.json` → `gold_final`.
2. (90 s) **Par C, CWE-120** (`cylab-bill-c-120-0613`, holdout): `strcpy` sem limite. Opengrep encontra **2 achados no before e 0 no after**. Ler a `explanation_pt` em voz alta.
3. (90 s) **Par Python, CWE-89** (`cylab-bill-python-89-0002`, regra `cylab.python.sqli-fstring-execute`): SQL montado com f-string/`.format()`. O before dá 1 achado e o after, com parâmetro vinculado, dá 0.
4. (30 s) Abrir uma regra `-gold` de C (`rules-gold/cylab.c.strcpy-strcat-gold.yaml`) e mostrar que é um padrão estrutural, não uma busca de texto.
5. (30 s) Mostrar o relatório de gate já gerado (`data/gate-report-v0.3-gold-draft-retake.json`). **Não rodar o gate completo ao vivo**: ele leva cerca de 6 min no box.
- **Fala-chave:** "O que vocês veem é exatamente o que o assistente vai fazer em produção: o Opengrep acha, a explicação diz o porquê e o patch faz o achado sumir. Hoje a explicação e o patch vêm do dataset. Na próxima etapa, quem vai gerá-los é o modelo treinado com esses pares."
- **Não** mostrar o modelo gerando patch: ele ainda não foi treinado e não há Ollama instalado no box (TBD).

### 19:00–21:30 · Status atual e honestidade (slide 11)
Falar com transparência. A banca valoriza isso.
- **FINAL v0.4-gold (atual):** `data/cylab-commercial-v0.4-gold.jsonl` (576/576, SHA em `data/v0.4-gold-cut-meta.json`). **FINAL v0.3 (anterior):** `data/cylab-commercial-v0.3-gold.jsonl` (476/476, SHA em `gold-progress.json`). Metadados `source` (65) **já normalizados** em 28/10/2026 (`data/source-fix-2026-10-28.md`); validador OK.
- **Limites do taint:**
  - Java/PHP/C#: 32 rules active taint em `rules-gold/` (crypto/secret/header/xxe/libxml ficaram regex de propósito).
  - SQL: 14 rules em `rules-gold/` com regex apertado (Opengrep sem taint SQL).
  - Em C/C++, o taint do Opengrep 1.32 não produziu achados nos nossos testes. Por isso as regras `-gold` de C/C++ são **estruturais** (metavariáveis, `pattern-not`, `pattern-inside`), não de fluxo de dados.
  - Em Bash, o suporte estrutural é fraco, então as regras usam regex restrita (ignorando comentários).
- **Near-clone:** a deduplicação reduz a repetição, mas os pares continuam sintéticos e, na maioria, curtos (funções de 3 a 10 linhas; o buffer v0.4 traz 100 pares de 26 a 52 linhas, ainda arquivo único). Isso não representa código real de produção.
- **Gate ≠ correção semântica:** "0 achados no after" prova que a regra não dispara mais, não que o patch esteja funcionalmente correto em todo contexto.
- **Metadados:** os 65 `source` sem URL da CWE foram normalizados; `validate_dataset.py` passa (OK: 476 na v0.3; OK: 576 pares, 87 holdout na v0.4).
- **Fala-chave:** "Nada aqui é métrica de modelo. O que medimos até agora é a consistência do dataset contra as regras."

### 21:30–24:00 · Próximos passos (slide 12)
1. ~~Congelar o v0.3 FINAL~~ **feito**. ~~Corrigir metadados `source` (65)~~ **feito** (28/10/2026).
2. Fine-tuning LoRA/QLoRA no Qwen2.5-Coder-14B, depois Qwen3.8-27B.
3. Avaliação no holdout (87 pares na v0.4: 75 da v0.3 + 12 do buffer de realismo), com critério principal objetivo: **o patch gerado pelo modelo passa no gate?** (> 0 achados no before, 0 no after). Somar revisão humana das explicações.
4. Empacotamento: Ollama + CLI + extensão VS Code, tudo local.
5. Ampliar com código mais realista (funções maiores: 1ª onda **feita** na v0.4; falta múltiplos arquivos) e rever o taint de C quando houver suporte no Opengrep.
- **Fala-chave:** "A próxima entrega responde à pergunta que hoje deixamos em aberto: um modelo local, treinado nesses pares, gera patches que passam no gate?"

### 24:00–25:00 · Fechamento (slide 13)
- Três frases:
  1. Detecção determinística + LLM só para explicar e corrigir.
  2. Dataset ouro com critério de aceite automático: 576/576 no gate, FINAL v0.4-gold (v0.3 = 476 é o corte anterior).
  3. Tudo local e open-source.
- "Obrigado. Ficamos à disposição para perguntas."

---

## 2. Estrutura sugerida de slides (títulos)

1. Cylab: assistente local de segurança de código (PUC Campinas)
2. Agenda e o que é esta primeira entrega
3. O problema: SAST sem explicação, LLM na nuvem, LLM que alucina
4. Arquitetura híbrida: Opengrep detecta, LLM explica e corrige, Opengrep confere
5. Por que 100% local e open-source (e o modelo planejado)
6. Anatomia de um par do dataset (schema)
7. O gate: > 0 achados no before, 0 no after
8. De 2.191 para ouro: o problema dos near-clones
9. Ouro FINAL v0.4-gold: 576 pares (476 + 100 de realismo), 10 linguagens, gate 576/576
10. Demo: um par C e um par Python no Opengrep
11. Status e limitações: FINAL v0.4-gold; metadados normalizados; near-clone; gate ≠ semântica
12. Próximos passos: FINAL → LoRA/QLoRA → avaliação no holdout → CLI/VS Code
13. Conclusão
14. (Backup) Detalhes: regras `-gold` em C/C++, política de holdout, deduplicação

---

## 3. Checklist de demo

Todos os comandos rodam a partir de `/workspace/cylab-dataset` (no box) e foram testados em 27/10/2026.

### Antes da apresentação
- [ ] Opengrep 1.32.0 presente: `~/.opengrep/cli/latest/opengrep --version` → `1.32.0` ✅ (testado)
- [ ] Ensaiar os dois pares (cada um leva de 3 a 4 s):
  - [ ] `seminar/demo/demo_pair.sh cylab-bill-c-120-0613` → before **2** achados, after **0** ✅ (testado)
  - [ ] `seminar/demo/demo_pair.sh cylab-bill-python-89-0002` → before **1**, after **0** ✅ (testado)
- [ ] Par reserva, caso a banca peça outro: `cylab-bill-c-78-0642` (CWE-78, `system()`) ou `cylab-bill-c-134-0638` (CWE-134, format string). **TBD:** ensaiar antes.
- [ ] Deixar abertos em abas:
  - `data/v0.4-gold-cut-meta.json` (FINAL v0.4-gold, sha256, 576/576)
  - `data/gold-progress.json` → chave `gold_final` (status FINAL, sha256, 476)
  - `data/gate-report-v0.3-gold-draft-retake.json` (re-gate 476/476)
  - `rules-gold/cylab.c.strcpy-strcat-gold.yaml`
  - `contributions/elon-c-cpp-sql-bash/REPORT.md` (funil 602 → 182, limitação do taint)
- [ ] Fonte do terminal grande (≥ 18 pt) e tema claro.
- [ ] **Plano B sem rede ou se o box falhar:** gravar a demo em vídeo e tirar prints da saída dos dois pares. **TBD — check obrigatório antes da banca**
- [ ] Levar a demo em notebook local com Opengrep instalado. **TBD:** o box é remoto, é preciso confirmar o acesso na sala.

### Durante a demo
```bash
cd /workspace/cylab-dataset
python3 -c "import json;print(json.load(open('data/gold-progress.json'))['gold_final'])"   # status FINAL, 476
seminar/demo/demo_pair.sh cylab-bill-c-120-0613                       # C / CWE-120
seminar/demo/demo_pair.sh cylab-bill-python-89-0002                   # Python / CWE-89
cat rules-gold/cylab.c.strcpy-strcat-gold.yaml                        # regra estrutural
```

### NÃO fazer ao vivo
- `python3 scripts/gate_draft.py data/cylab-commercial-v0.3-gold.jsonl --report /tmp/g.json` leva **cerca de 6 min** (476/476 OK, testado). Mostrar só o relatório.
- `python3 scripts/validate_dataset.py data/cylab-commercial-v0.4-gold.jsonl` → **OK: 576 pares, 87 holdout** (v0.3: OK: 476 pares, 75 holdout, após source-fix 28/10/2026). Pode mostrar se a banca perguntar.
- Modelo / Ollama / CLI / VS Code: **TBD**. Não há Ollama instalado no box e não existe modelo treinado. Mostrar só como diagrama.

---

## 4. Perguntas previstas da banca (e respostas curtas)

1. **"Qual a acurácia do modelo?"** Ainda não existe modelo treinado. Esta entrega é o dataset e a arquitetura. A métrica planejada é a taxa de patches que passam no gate, medida no holdout de 87 pares (v0.4).
2. **"Por que não usar só o LLM?"** Porque o LLM alucina achados e não dá para auditar. Com o Opengrep cada achado tem regra e CWE rastreáveis, e o LLM só trabalha a partir disso.
3. **"Por que não usar só o Opengrep?"** Ele detecta, mas não explica em pt-BR nem adapta a correção ao código. É essa lacuna que o modelo cobre.
4. **"O gate prova que o patch é correto?"** Não. Prova que a regra deixou de disparar. A correção funcional precisa de revisão humana e, no futuro, de testes. Isso está nas limitações.
5. **"O modelo não vai só aprender a satisfazer a regra?"** É um risco real (overfitting na regra). Por isso deduplicamos near-clones, separamos o holdout por estrato e planejamos revisão humana e código mais realista.
6. **"Dados sintéticos generalizam para código real?"** É a principal limitação. Os pares são curtos e originais (sem dados de terceiros). A próxima fase precisa de exemplos maiores e realistas.
7. **"Por que o ouro tem 576 e não 2 mil?"** Porque cortamos clones de template (v0.3 = 476) e só depois somamos 100 pares maiores e distintos. Na fatia C/C++/Bash, por exemplo, 602 viraram 182. Qualidade e diversidade vêm antes do volume.
8. **"Por que não taint em C/C++?"** Nos testes, o taint do Opengrep 1.32 não gerou achados em C/C++. Usamos padrões estruturais e vamos revisitar quando a ferramenta suportar.
9. **"O dataset é FINAL?"** Sim, v0.4-gold (576), que contém integralmente o corte anterior v0.3-gold (476). Metadados `source` normalizados; validador OK.
10. **"Como evitam vazamento entre train e holdout?"** O split é determinístico por hash dentro de cada estrato (linguagem + regra), e a deduplicação é feita antes. Ver `holdout_split_proposal.py` e a `holdout_policy` no manifesto.
11. **"Qual hardware para rodar local?"** **TBD:** medir depois do fine-tuning. Não citar números agora.
12. **"Licença e proveniência?"** Pares escritos do zero para a Cylab, licença CC-BY-4.0, sem dados de terceiros e sem dados VigIA.

---

## 5. Riscos e como tratar

| Risco | Mitigação na fala |
|---|---|
| A banca entender que o modelo já existe | Repetir "planejado" e "próxima entrega", sem nenhum número de modelo |
| Confundir status do dataset | Dizer **FINAL v0.4-gold** (576; v0.3 = 476 é o corte anterior) no slide 9; `source` já normalizado |
| Superestimar o gate | Dizer explicitamente "gate ≠ correção semântica" |
| Pergunta sobre taint em C | Resposta 8; é uma limitação da ferramenta, documentada |
| Near-clone residual | Admitir: os pares são curtos e sintéticos; o plano é aumentar o realismo |
| Demo falhar (rede/box) | Vídeo e prints de backup (TBD) |
| Validador | Já passa (source-fix); pode mostrar se pedirem |
| Nome do checkpoint "Qwen3.8-27B" | **TBD:** confirmar o nome e a versão exata do modelo antes de pôr no slide |

---

## 6. Versão curta (20 min)
Cortar: slide 5 para 1 min, slides 6–8 para 4 min, demo para 3 min (só o par C), próximos passos para 1,5 min. Mais 5 min de perguntas.
