# Checklist de overfitting — holdout realism v0.4

Amostra: 24 pares de 100 (estratificada por buffer/lang/CWE). Fonte: `sample_ids.json`. Não altera FINAL v0.3-gold.

Critérios por item:
- (a) O `after` corrige o bug real ou só silencia a regra?
- (b) Rename/ofuscação trivial do `before` ainda passaria pela regra (falso negativo)?
- (c) Sentido funcional do código (1–5).

## Fatia markinho (6)

### `cylab-markinho-java-22-r001` — java / CWE-22 / split=train / regra `cylab.java.file-from-parameter`
- [x] (a) corrige de fato / só silencia: corrige de fato — allowlist `^[A-Za-z0-9_-]{1,64}\.pdf$` + normalize/startsWith(base); não só silencia
- [x] (b) rename/ofuscação passaria? (s/n): s — regra exige `request.getParameter` inline em `new File(`; o before usa `req` e var intermediária `nome`, então o próprio before NÃO casa (validado por regex)
- [x] (c) sentido funcional 1–5: 5
- Revisor: Markinho (2026-10-28)  Obs.: Fix sólido; regra regex frágil (nome `req`/variável intermediária escapam). Par não serve como positivo da regra atual.

### `cylab-markinho-java-502-r001` — java / CWE-502 / split=train / regra `cylab.java.objectinputstream`
- [x] (a) corrige de fato / só silencia: corrige de fato — troca ObjectInputStream por Jackson tipado Map<String,String> + limite de tamanho
- [x] (b) rename/ofuscação passaria? (s/n): s — regex `new ObjectInputStream(` pega o before, mas wrapper/subclasse (`new SafeOIS(`), reflexão ou XMLDecoder escapariam; rename de variável não afeta
- [x] (c) sentido funcional 1–5: 5
- Revisor: Markinho (2026-10-28)  Obs.: Before casa, after não. Fix real e idiomático.

### `cylab-markinho-java-78-r001` — java / CWE-78 / split=train / regra `cylab.java.runtime-exec-concat`
- [x] (a) corrige de fato / só silencia: corrige de fato — allowlist de host + ProcessBuilder com lista de args (sem shell)
- [x] (b) rename/ofuscação passaria? (s/n): s — taint só considera parâmetro String de método como source; `host` vem de `req.getParameter` em var local em doGet(req,resp), provavelmente o before nem dispara; extrair para método `ping(String h)` faria disparar, inline não
- [x] (c) sentido funcional 1–5: 4
- Revisor: Markinho (2026-10-28)  Obs.: Fix real. Nota: `-` permitido no regex ainda permite host iniciando com `-` (injeção de argumento no ping); ideal exigir 1º char alfanumérico ou `--`. Não validei com opengrep (não instalado).

### `cylab-markinho-java-79-r001` — java / CWE-79 / split=train / regra `cylab.java.servlet-writer-param`
- [x] (a) corrige de fato / só silencia: corrige de fato — Encode.forHtml(termo) no ponto de saída (contexto HTML de corpo correto)
- [x] (b) rename/ofuscação passaria? (s/n): s — regra exige `request.getParameter` dentro do print; before usa `req` + var `termo`, então o before NÃO casa (validado por regex)
- [x] (c) sentido funcional 1–5: 5
- Revisor: Markinho (2026-10-28)  Obs.: Fix mínimo e correto; regra não cobre o padrão realista (var intermediária).

### `cylab-markinho-java-90-r001` — java / CWE-90 / split=train / regra `cylab.java.ldap-filter-concat`
- [x] (a) corrige de fato / só silencia: corrige de fato — filtro parametrizado `{0}` com args via DirContext.search (JNDI escapa)
- [x] (b) rename/ofuscação passaria? (s/n): s — regex depende de `uid=" +` literal; String.format/StringBuilder/concat em var separada ou atributo fora da lista (ex. `sn=`) escapariam
- [x] (c) sentido funcional 1–5: 5
- Revisor: Markinho (2026-10-28)  Obs.: Before casa, after não. Fix canônico.

### `cylab-markinho-java-918-r001` — java / CWE-918 / split=train / regra `cylab.java.url-from-parameter`
- [x] (a) corrige de fato / só silencia: corrige de fato (parcial) — exige https + allowlist de host antes de abrir; não só silencia
- [x] (b) rename/ofuscação passaria? (s/n): s — regra exige `new URL(request.getParameter` inline; before usa var `endereco` e `req`, então o before NÃO casa (validado por regex)
- [x] (c) sentido funcional 1–5: 4
- Revisor: Markinho (2026-10-28)  Obs.: Allowlist exata de host é boa; restam redirects (openStream segue redirect só mesmo protocolo, https→https externo possível) e o setContentType fixo image/png. Regra não pega o before.

## Fatia bill (6) — preenchida Bill 2026-10-28

### `cylab-bill-sqlreal-256-plaintext-password-column-01` — sql / CWE-256 / split=train / regra `cylab.sql.plaintext-password-column`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (coluna `hash_portal` + `crypt()`/pgcrypto; não é só rename)
- [x] (b) rename/ofuscação passaria? (s/n): **s** (regex ancorada em `senha|password|pwd|passwd` + VARCHAR — rename p/ `credencial_portal` etc. vira FN)
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Bill**  Obs.: fraqueza conhecida da rule regex; o par em si tem fix real. Tabela `chamados` de contexto ok.

### `cylab-bill-sqlreal-269-grant-all-public-02` — sql / CWE-269 / split=train / regra `cylab.sql.grant-all-public`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (host `10.20.%` + privilégios mínimos SELECT/INSERT/UPDATE/EXECUTE)
- [x] (b) rename/ofuscação passaria? (s/n): **n** (padrão `GRANT ALL … TO …@'%'` sobrevive a rename de user/tabela)
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Bill**  Obs.: schema `financeiro` referenciado no GRANT sem CREATE DATABASE — aceitável p/ snippet de provisionamento.

### `cylab-bill-sqlreal-426-security-definer-no-path-01` — sql / CWE-426 / split=train / regra `cylab.sql.security-definer-no-path`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (`SET search_path = vendas, pg_temp` + objetos qualificados)
- [x] (b) rename/ofuscação passaria? (s/n): **n** (dispara em `SECURITY DEFINER` sem `SET search_path`)
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Bill**  Obs.: `pedidos_aprovacao` referida sem DDL no snippet — gap menor de completude, não de segurança.

### `cylab-bill-sqlreal-78-xp-cmdshell-02` — sql / CWE-78 / split=train / regra `cylab.sql.xp-cmdshell`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (`xp_cmdshell` = 0; lista via tabela `ArquivosRecebidos`, sem shell)
- [x] (b) rename/ofuscação passaria? (s/n): **n** (literal `'xp_cmdshell', 1` / `EXEC xp_cmdshell` — rename de proc não evade)
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Bill**  Obs.: DDL de `ArquivosRecebidos` omitido de propósito (serviço de ingestão); ok p/ realismo.

### `cylab-bill-sqlreal-798-hardcoded-db-password-03` — sql / CWE-798 / split=train / regra `cylab.sql.hardcoded-db-password`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (`IDENTIFIED EXTERNALLY` / `GLOBALLY AS …`, sem segredo no DDL)
- [x] (b) rename/ofuscação passaria? (s/n): **n** p/ aspas simples; **parcial** — rule só casa `'…'`, então `IDENTIFIED BY "pwd"` (aspas duplas Oracle) já evade no before (1 dos 2 users usa `"`)
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Bill**  Obs.: before ainda dispara via `LogRO!2026` em aspas simples. Gap da rule p/ aspas duplas — anotar p/ taint/wave futura, não bloqueia o par.

### `cylab-bill-sqlreal-89-tsql-exec-concat-01` — sql / CWE-89 / split=train / regra `cylab.sql.tsql-exec-concat`
- [x] (a) corrige de fato / só silencia: **corrige de fato** (allowlist de colunas + `QUOTENAME` + `sp_executesql`)
- [x] (b) rename/ofuscação passaria? (s/n): **n** (padrão `EXEC (N'…' + @param)`; rename de @Ordenacao ainda casa)
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Bill**  Obs.: after não casa a rule (não usa `EXEC (N'+@)`). `@Status` não usado no SELECT — ruído menor.

## Fatia elon (6)

### `cylab-elon-real-bash-494-0002` — bash / CWE-494 / split=train / regra `cylab.bash.source-remote-script-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Elon**  Obs.: after troca `source <(curl …)` por lib local com checagem de dono/não-symlink. Rename de vars não foge do regex; ofuscação tipo `eval "$(curl…)"` seria outro sink (fora da regra).

### `cylab-elon-real-bash-78-0002` — bash / CWE-78 / split=train / regra `cylab.bash.sh-c-interpolated-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Elon**  Obs.: remove `sh -c` com interpolação; valida charset e chama `tar`/`sha256sum` com args quotados. Rename trivial não evade o regex `sh -c "…$"`.

### `cylab-elon-real-c-120-0003` — c / CWE-120 / split=train / regra `cylab.c.scanf-unbounded-s-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Elon**  Obs.: `%s` → `%23s`/`%31s` com espaço pro `\0`. Rename de buffers não muda o formato; API alternativa (`gets`) seria outra regra.

### `cylab-elon-real-cpp-120-0001` — cpp / CWE-120 / split=train / regra `cylab.cpp.cstr-copy-unbounded-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Elon**  Obs.: `strcpy`/`strcat` → `snprintf` com `sizeof`. Rename de vars não evade; wrapper customizado sim (risco residual de regra estrutural).

### `cylab-elon-real-cpp-134-0001` — cpp / CWE-134 / split=train / regra `cylab.cpp.printf-cstr-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **4**
- Revisor: **Elon**  Obs.: `printf(cstr)` → `printf("%s", cstr)`. Path do arquivo de tradução ainda vem de argv (outra superfície); o format-string em si está corrigido.

### `cylab-elon-real-cpp-22-0001` — cpp / CWE-22 / split=train / regra `cylab.cpp.ofstream-concat-path-gold`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Elon**  Obs.: rejeita path com separadores via `filename()` + igualdade com o nome original; grava sob `kUploadDir`. Concat `dir+name` some do after.

## Fatia sam (6)

### `cylab-sam-real-js-22-001` — javascript / CWE-22 / split=holdout / regra `cylab.javascript.path-traversal`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: after faz `path.resolve` + `startsWith(base + sep)`; Express realista (tenant/PDF). Holdout OK.

### `cylab-sam-real-js-89-001` — javascript / CWE-89 / split=train / regra `cylab.javascript.sql-injection`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: `pool.execute` com `?` + validação numérica de `max`; concat no before é o bug real.

### `cylab-sam-real-py-78-002` — python / CWE-78 / split=holdout / regra `cylab.python.command-injection`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: sai de `os.system` → `subprocess` argv + regex allowlist + gzip em Python. Holdout OK.

### `cylab-sam-real-py-89-001` — python / CWE-89 / split=train / regra `cylab.python.sql-injection`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: placeholders `?` + `<int:cliente_id>` na rota Flask; não é só silenciar f-string.

### `cylab-sam-real-ts-79-001` — typescript / CWE-79 / split=holdout / regra `cylab.typescript.innerhtml-assign`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: `createElement`/`textContent`/`replaceChildren` no lugar de `innerHTML`. Holdout OK.

### `cylab-sam-real-ts-89-002` — typescript / CWE-89 / split=train / regra `cylab.typescript.sql-injection`
- [x] (a) corrige de fato / só silencia: **corrige de fato**
- [x] (b) rename/ofuscação passaria? (s/n): **n**
- [x] (c) sentido funcional 1–5: **5**
- Revisor: **Sam**  Obs.: queries fixas TypeORM com `$1/$2/$3`; ramo com/sem `acao` sem concatenar filtro.
