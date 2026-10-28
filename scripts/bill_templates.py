# Templates originais para geracao sintetica (Cylab, CC-BY-4.0). Placeholders: @T@ tabela, @C@ campo, @S@ singular, @SC@ Singular, @CC@ Campo
E=[("usuarios","email","usuario"),("pedidos","status","pedido"),("produtos","sku","produto"),("clientes","cpf","cliente"),
("faturas","numero","fatura"),("contratos","codigo","contrato"),("chamados","protocolo","chamado"),("alunos","matricula","aluno"),
("pacientes","prontuario","paciente"),("veiculos","placa","veiculo"),("funcionarios","cracha","funcionario"),("fornecedores","cnpj","fornecedor"),
("reservas","localizador","reserva"),("cursos","slug","curso"),("eventos","titulo","evento"),("lojas","cidade","loja"),
("pagamentos","transacao","pagamento"),("entregas","rastreio","entrega"),("contas","agencia","conta"),("projetos","nome","projeto")]
T=[]
def t(lang,cwe,slug,regex,exp,*styles,rl=None): T.append(dict(lang=lang,cwe=cwe,slug=slug,regex=regex,exp=exp,styles=styles,rl=rl or lang))
# ---------------- PYTHON
t("python","89","sqli-fstring-execute",r"""execute\(\s*(f["']|"[^"]*"\s*(%|\.format)|'[^']*'\s*(%|\.format))""",
"A query monta SQL com interpolação de string usando o valor de @C@ vindo do chamador, o que permite injeção de SQL (CWE-89). A correção passa o valor como parâmetro vinculado, e o driver o trata sempre como dado.",
("""def buscar_@S@(cur, @C@):\n    cur.execute(f"SELECT * FROM @T@ WHERE @C@ = '{@C@}'")\n    return cur.fetchone()\n""",
 """def buscar_@S@(cur, @C@):\n    cur.execute("SELECT * FROM @T@ WHERE @C@ = %s", (@C@,))\n    return cur.fetchone()\n"""),
("""def contar_@T@(conn, filtro):\n    sql = "SELECT COUNT(*) FROM @T@ WHERE @C@ LIKE '{}%'"\n    cur = conn.cursor()\n    cur.execute(sql.format(filtro))\n    return cur.fetchone()[0]\n""".replace('cur.execute(sql.format(filtro))','cur.execute("SELECT COUNT(*) FROM @T@ WHERE @C@ LIKE \'{}%\'".format(filtro))'),
 """def contar_@T@(conn, filtro):\n    cur = conn.cursor()\n    cur.execute("SELECT COUNT(*) FROM @T@ WHERE @C@ LIKE ?", (filtro + "%",))\n    return cur.fetchone()[0]\n"""),
("""def apagar_@S@(db, ident):\n    db.execute("DELETE FROM @T@ WHERE id = %s" % ident)\n    db.commit()\n""",
 """def apagar_@S@(db, ident):\n    db.execute("DELETE FROM @T@ WHERE id = ?", (int(ident),))\n    db.commit()\n"""))
t("python","78","subprocess-shell-true",r"""shell\s*=\s*True""",
"O comando é executado via shell com o valor @C@ concatenado, permitindo que metacaracteres como ; ou $( ) injetem comandos (CWE-78). A correção passa uma lista de argumentos sem shell=True, então o valor nunca é interpretado pelo shell.",
("""import subprocess\n\ndef exportar_@T@(@C@):\n    subprocess.run(f"tar czf /backup/@T@.tgz /dados/{@C@}", shell=True, check=True)\n""",
 """import subprocess\n\ndef exportar_@T@(@C@):\n    subprocess.run(["tar", "czf", "/backup/@T@.tgz", "--", f"/dados/{@C@}"], check=True)\n"""),
("""import subprocess\n\ndef log_@S@(arquivo):\n    saida = subprocess.check_output("grep @C@ " + arquivo, shell=True)\n    return saida.decode()\n""",
 """import subprocess\n\ndef log_@S@(arquivo):\n    saida = subprocess.check_output(["grep", "@C@", "--", arquivo])\n    return saida.decode()\n"""))
t("python","22","open-join-user",r"""open\(\s*os\.path\.join\(""",
"O nome do arquivo de @S@ vem do usuário e é unido ao diretório base sem validação; sequências como ../ escapam da pasta (CWE-22). A correção resolve o caminho real e confere que ele continua dentro do diretório permitido.",
("""import os\nBASE = "/srv/@T@"\n\ndef ler_anexo(nome):\n    with open(os.path.join(BASE, nome), "rb") as f:\n        return f.read()\n""",
 """import os\nBASE = os.path.realpath("/srv/@T@")\n\ndef ler_anexo(nome):\n    alvo = os.path.realpath(os.path.join(BASE, nome))\n    if os.path.commonpath([alvo, BASE]) != BASE:\n        raise PermissionError("caminho fora da base")\n    with open(alvo, "rb") as f:\n        return f.read()\n"""),
("""import os\nfrom flask import request\n\ndef baixar_@S@():\n    nome = request.args["arquivo"]\n    return open(os.path.join("relatorios/@T@", nome)).read()\n""",
 """import os\nfrom flask import request, abort\nfrom werkzeug.utils import secure_filename\n\ndef baixar_@S@():\n    nome = secure_filename(request.args["arquivo"])\n    if not nome:\n        abort(400)\n    caminho = os.path.join("relatorios/@T@", nome)\n    with open(caminho) as f:\n        return f.read()\n"""))
t("python","918","requests-from-request",r"""requests\.\w+\(\s*request\.(args|form|json|values)""",
"A URL requisitada pelo servidor vem direto do parâmetro do cliente, permitindo SSRF para serviços internos ou metadados de nuvem (CWE-918). A correção fixa o host base e usa apenas o identificador de @S@ escapado no caminho.",
("""import requests\nfrom flask import request\n\ndef proxy_@S@():\n    r = requests.get(request.args["url"], timeout=5)\n    return r.text\n""",
 """import requests\nfrom urllib.parse import quote\nfrom flask import request\nAPI = "https://api.interna.exemplo/@T@"\n\ndef proxy_@S@():\n    ident = quote(request.args["id"], safe="")\n    r = requests.get(f"{API}/{ident}", timeout=5)\n    return r.text\n"""),
("""import requests\nfrom flask import request\n\ndef webhook_@S@():\n    requests.post(request.json["callback"], json={"@C@": "ok"}, timeout=3)\n    return "", 204\n""",
 """import requests\nfrom urllib.parse import urlparse\nfrom flask import request, abort\nPERMITIDOS = {"hooks.parceiro.exemplo"}\n\ndef webhook_@S@():\n    destino = request.json["callback"]\n    u = urlparse(destino)\n    if u.scheme != "https" or u.hostname not in PERMITIDOS:\n        abort(400)\n    requests.post(destino, json={"@C@": "ok"}, timeout=3)\n    return "", 204\n"""))
t("python","502","unsafe-yaml-pickle",r"""pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)""",
"Desserializar dados de @S@ não confiáveis com pickle ou yaml.load permite construir objetos arbitrários e executar código (CWE-502). A correção usa um formato de dados puro (json ou yaml.safe_load).",
("""import pickle\n\ndef carregar_@S@(blob: bytes):\n    return pickle.loads(blob)\n""",
 """import json\n\ndef carregar_@S@(blob: bytes):\n    return json.loads(blob.decode("utf-8"))\n"""),
("""import yaml\n\ndef config_@T@(texto):\n    dados = yaml.load(texto)\n    return dados.get("@C@")\n""",
 """import yaml\n\ndef config_@T@(texto):\n    dados = yaml.safe_load(texto)\n    return dados.get("@C@")\n"""))
# ---------------- JAVASCRIPT
t("javascript","89","sql-template-literal",r"""\.query\(\s*`[^`]*\$\{""",
"O SQL é montado com template literal contendo @C@ vindo da requisição, permitindo injeção de SQL (CWE-89). A correção usa placeholders e passa os valores em array separado.",
("""app.get('/@T@', async (req, res) => {\n  const rows = await db.query(`SELECT * FROM @T@ WHERE @C@ = '${req.query.@C@}'`);\n  res.json(rows);\n});\n""",
 """app.get('/@T@', async (req, res) => {\n  const rows = await db.query('SELECT * FROM @T@ WHERE @C@ = ?', [req.query.@C@]);\n  res.json(rows);\n});\n"""),
("""async function remover@SC@(pool, id) {\n  return pool.query(`DELETE FROM @T@ WHERE id = ${id}`);\n}\nmodule.exports = { remover@SC@ };\n""",
 """async function remover@SC@(pool, id) {\n  return pool.query('DELETE FROM @T@ WHERE id = $1', [id]);\n}\nmodule.exports = { remover@SC@ };\n"""))
t("javascript","78","exec-template",r"""exec(Sync)?\(\s*`[^`]*\$\{""",
"O comando de shell recebe @C@ interpolado, então caracteres como ; ou | permitem injeção de comandos (CWE-78). A correção usa execFile com argumentos em array, sem shell.",
("""const { exec } = require('child_process');\n\nfunction comprimir@SC@(nome, cb) {\n  exec(`zip -r /tmp/${nome}.zip ./@T@/${nome}`, cb);\n}\n""",
 """const { execFile } = require('child_process');\n\nfunction comprimir@SC@(nome, cb) {\n  execFile('zip', ['-r', `/tmp/${nome}.zip`, `./@T@/${nome}`], cb);\n}\n"""),
("""const { execSync } = require('child_process');\n\nfunction contarLinhas@SC@(arquivo) {\n  return execSync(`wc -l ${arquivo}`).toString();\n}\n""",
 """const { execFileSync } = require('child_process');\n\nfunction contarLinhas@SC@(arquivo) {\n  return execFileSync('wc', ['-l', '--', arquivo]).toString();\n}\n"""))
t("javascript","79","res-send-reflect",r"""\bres(\.status\(\d+\))?\.send\(\s*`[^`]*\$\{req\.(query|params|body)""",
"O parâmetro @C@ é refletido no HTML sem escape, permitindo XSS refletido (CWE-79). A correção escapa o valor com uma função de encoding HTML antes de inseri-lo.",
("""app.get('/@T@/busca', (req, res) => {\n  res.send(`<h1>Resultados para ${req.query.@C@}</h1>`);\n});\n""",
 """const escapeHtml = require('escape-html');\n\napp.get('/@T@/busca', (req, res) => {\n  res.send(`<h1>Resultados para ${escapeHtml(req.query.@C@)}</h1>`);\n});\n"""),
("""router.get('/@S@/:id', (req, res) => {\n  res.status(404).send(`<p>@SC@ ${req.params.id} nao encontrado</p>`);\n});\n""",
 """const escapeHtml = require('escape-html');\n\nrouter.get('/@S@/:id', (req, res) => {\n  res.status(404).send(`<p>@SC@ ${escapeHtml(req.params.id)} nao encontrado</p>`);\n});\n"""))
t("javascript","601","redirect-user",r"""res\.redirect\(\s*(\d+\s*,\s*)?req\.(query|body|params)""",
"O destino do redirecionamento após a ação em @T@ vem do cliente, permitindo open redirect para sites de phishing (CWE-601). A correção aceita apenas caminhos relativos internos.",
("""app.post('/@T@/salvar', (req, res) => {\n  salvar@SC@(req.body);\n  res.redirect(req.query.next);\n});\n""",
 """function destinoSeguro(n) {\n  return typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') ? n : '/@T@';\n}\n\napp.post('/@T@/salvar', (req, res) => {\n  salvar@SC@(req.body);\n  res.redirect(destinoSeguro(req.query.next));\n});\n"""),
("""app.get('/login/@S@', (req, res) => {\n  res.redirect(302, req.query.retorno);\n});\n""",
 """const PERMITIDOS = new Set(['/@T@', '/painel']);\n\napp.get('/login/@S@', (req, res) => {\n  const alvo = PERMITIDOS.has(req.query.retorno) ? req.query.retorno : '/painel';\n  res.redirect(302, alvo);\n});\n"""))
t("javascript","328","weak-hash-createhash",r"""createHash\(\s*['"](md5|sha1)['"]""",
"Senha ou segredo de @S@ é derivado com MD5/SHA-1, hashes rápidos e quebráveis por força bruta (CWE-328). A correção usa scrypt com salt aleatório.",
("""const crypto = require('crypto');\n\nfunction hashSenha@SC@(senha) {\n  return crypto.createHash('md5').update(senha).digest('hex');\n}\n""",
 """const crypto = require('crypto');\n\nfunction hashSenha@SC@(senha) {\n  const salt = crypto.randomBytes(16);\n  const dk = crypto.scryptSync(senha, salt, 64);\n  return salt.toString('hex') + ':' + dk.toString('hex');\n}\n"""),
("""const crypto = require('crypto');\n\nexports.tokenReset@SC@ = (@C@) =>\n  crypto.createHash('sha1').update(@C@ + Date.now()).digest('hex');\n""",
 """const crypto = require('crypto');\n\nexports.tokenReset@SC@ = (@C@) =>\n  crypto.randomBytes(32).toString('hex');\n"""))
# ---------------- TYPESCRIPT
t("typescript","942","cors-wildcard-credentials",r"""origin:\s*['"]\*['"]|origin:\s*true""",
"A API de @T@ aceita qualquer origem com credenciais, permitindo que sites maliciosos leiam respostas autenticadas (CWE-942). A correção restringe a uma lista explícita de origens confiáveis.",
("""import cors from 'cors';\n\napp.use('/api/@T@', cors({ origin: '*', credentials: true }));\n""",
 """import cors from 'cors';\n\nconst ORIGENS: string[] = ['https://app.exemplo.com.br'];\napp.use('/api/@T@', cors({ origin: ORIGENS, credentials: true }));\n"""),
("""import cors from 'cors';\n\nexport function configurar@SC@(app: any): void {\n  app.use(cors({ origin: true, credentials: true }));\n}\n""",
 """import cors from 'cors';\n\nexport function configurar@SC@(app: any): void {\n  app.use(cors({ origin: ['https://painel.exemplo.com.br'], credentials: true }));\n}\n"""))
t("typescript","798","hardcoded-credential",r"""(SECRET|API_KEY|TOKEN|PASSWORD|SENHA)\w*\s*(:\s*string\s*)?=\s*['"][^'"]{8,}['"]""",
"Uma credencial do serviço de @T@ está fixa no código-fonte e vaza via repositório ou bundle (CWE-798). A correção lê o valor de variável de ambiente e falha se estiver ausente.",
("""import jwt from 'jsonwebtoken';\n\nconst JWT_SECRET: string = 'cylab-@S@-segredo-2024';\n\nexport const assinar@SC@ = (id: string) => jwt.sign({ id }, JWT_SECRET);\n""",
 """import jwt from 'jsonwebtoken';\n\nconst JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) throw new Error('JWT_SECRET ausente');\n\nexport const assinar@SC@ = (id: string) => jwt.sign({ id }, JWT_SECRET);\n"""),
("""export class Cliente@SC@Api {\n  private readonly API_KEY = 'sk_live_@C@_9f8e7d6c5b4a';\n  headers() { return { Authorization: `Bearer ${this.API_KEY}` }; }\n}\n""",
 """export class Cliente@SC@Api {\n  private readonly apiKey = process.env.@CU@_API_KEY ?? '';\n  headers() { return { Authorization: `Bearer ${this.apiKey}` }; }\n}\n"""))
t("typescript","338","math-random-token",r"""Math\.random\(\)""",
"O token de @S@ é gerado com Math.random, que não é criptograficamente seguro e pode ser previsto (CWE-338). A correção usa crypto.randomBytes/randomUUID.",
("""export function gerarToken@SC@(): string {\n  return Math.random().toString(36).slice(2) + Date.now().toString(36);\n}\n""",
 """import { randomBytes } from 'crypto';\n\nexport function gerarToken@SC@(): string {\n  return randomBytes(24).toString('base64url');\n}\n"""),
("""export const codigoVerificacao@SC@ = (): number =>\n  Math.floor(100000 + Math.random() * 900000);\n""",
 """import { randomInt } from 'crypto';\n\nexport const codigoVerificacao@SC@ = (): number => randomInt(100000, 1000000);\n"""))
t("typescript","79","innerhtml-assign",r"""\.innerHTML\s*[+]?=""",
"O campo @C@ do @S@ é inserido via innerHTML, então HTML/JS controlado pelo usuário é executado no navegador (XSS, CWE-79). A correção usa textContent, que trata o valor como texto.",
("""export function render@SC@(el: HTMLElement, @C@: string): void {\n  el.innerHTML = `<strong>${@C@}</strong>`;\n}\n""",
 """export function render@SC@(el: HTMLElement, @C@: string): void {\n  const s = document.createElement('strong');\n  s.textContent = @C@;\n  el.replaceChildren(s);\n}\n"""),
("""export function adicionarComentario@SC@(lista: HTMLUListElement, texto: string): void {\n  lista.innerHTML += '<li>' + texto + '</li>';\n}\n""",
 """export function adicionarComentario@SC@(lista: HTMLUListElement, texto: string): void {\n  const li = document.createElement('li');\n  li.textContent = texto;\n  lista.appendChild(li);\n}\n"""))
t("typescript","89","sql-template-query",r"""\.query\(\s*`[^`]*\$\{""",
"A consulta de @T@ interpola parâmetro do usuário no SQL, viabilizando injeção (CWE-89). A correção usa parâmetros posicionais do driver.",
("""import { Pool } from 'pg';\n\nexport async function listar@SC@(pool: Pool, @C@: string) {\n  const r = await pool.query(`SELECT * FROM @T@ WHERE @C@ = '${@C@}' ORDER BY id`);\n  return r.rows;\n}\n""",
 """import { Pool } from 'pg';\n\nexport async function listar@SC@(pool: Pool, @C@: string) {\n  const r = await pool.query('SELECT * FROM @T@ WHERE @C@ = $1 ORDER BY id', [@C@]);\n  return r.rows;\n}\n"""),
("""import { DataSource } from 'typeorm';\n\nexport const ordenar@SC@ = (ds: DataSource, coluna: string) =>\n  ds.query(`SELECT id, @C@ FROM @T@ ORDER BY ${coluna}`);\n""",
 """import { DataSource } from 'typeorm';\n\nconst COLUNAS = new Set(['id', '@C@']);\n\nexport const ordenar@SC@ = (ds: DataSource, coluna: string) => {\n  const c = COLUNAS.has(coluna) ? coluna : 'id';\n  return ds.query('SELECT id, @C@ FROM @T@ ORDER BY ' + c);\n};\n"""))
# ---------------- JAVA
t("java","89","statement-concat",r"""execute(Query|Update)?\(\s*"[^"]*"\s*\+""",
"O SQL concatena @C@ recebido como parâmetro e executa via Statement, permitindo injeção de SQL (CWE-89). A correção usa PreparedStatement com parâmetro vinculado.",
("""import java.sql.*;\n\npublic class @SC@Repo {\n  public ResultSet porCampo(Connection c, String @C@) throws SQLException {\n    Statement st = c.createStatement();\n    return st.executeQuery("SELECT * FROM @T@ WHERE @C@ = '" + @C@ + "'");\n  }\n}\n""",
 """import java.sql.*;\n\npublic class @SC@Repo {\n  public ResultSet porCampo(Connection c, String @C@) throws SQLException {\n    PreparedStatement ps = c.prepareStatement("SELECT * FROM @T@ WHERE @C@ = ?");\n    ps.setString(1, @C@);\n    return ps.executeQuery();\n  }\n}\n"""),
("""import java.sql.*;\n\nclass Arquiva@SC@ {\n  int arquivar(Connection c, String id) throws SQLException {\n    return c.createStatement().executeUpdate("UPDATE @T@ SET arquivado = 1 WHERE id = " + id);\n  }\n}\n""",
 """import java.sql.*;\n\nclass Arquiva@SC@ {\n  int arquivar(Connection c, String id) throws SQLException {\n    try (PreparedStatement ps = c.prepareStatement("UPDATE @T@ SET arquivado = 1 WHERE id = ?")) {\n      ps.setLong(1, Long.parseLong(id));\n      return ps.executeUpdate();\n    }\n  }\n}\n"""))
t("java","78","runtime-exec-concat",r"""\.exec\(\s*("[^"]*"\s*\+|new String\[\]\s*\{\s*"(/bin/)?(ba)?sh")""",
"O comando de sistema é montado concatenando @C@ e executado por Runtime.exec (ou via sh -c), abrindo injeção de comandos (CWE-78). A correção usa ProcessBuilder com cada argumento separado e sem shell.",
("""public class Relatorio@SC@ {\n  public Process gerar(String @C@) throws java.io.IOException {\n    return Runtime.getRuntime().exec("/opt/bin/relatorio --@C@ " + @C@);\n  }\n}\n""",
 """public class Relatorio@SC@ {\n  public Process gerar(String @C@) throws java.io.IOException {\n    return new ProcessBuilder("/opt/bin/relatorio", "--@C@", @C@).start();\n  }\n}\n"""),
("""public class Backup@SC@ {\n  void copiar(String destino) throws Exception {\n    Runtime.getRuntime().exec(new String[]{"sh", "-c", "cp -r /dados/@T@ " + destino}).waitFor();\n  }\n}\n""",
 """public class Backup@SC@ {\n  void copiar(String destino) throws Exception {\n    new ProcessBuilder("cp", "-r", "/dados/@T@", "--", destino).start().waitFor();\n  }\n}\n"""))
t("java","611","xxe-documentbuilder",r"""DocumentBuilderFactory\.newInstance\(\)\s*;(?![\s\S]*disallow-doctype-decl)""",
"O XML de @T@ é processado com DocumentBuilderFactory padrão, que resolve DTD e entidades externas (XXE, CWE-611), permitindo ler arquivos locais ou SSRF. A correção desabilita DOCTYPE e entidades externas antes de criar o parser.",
("""import javax.xml.parsers.*;\nimport org.w3c.dom.Document;\n\npublic class Importa@SC@ {\n  public Document ler(java.io.InputStream in) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    return f.newDocumentBuilder().parse(in);\n  }\n}\n""",
 """import javax.xml.parsers.*;\nimport org.w3c.dom.Document;\n\npublic class Importa@SC@ {\n  public Document ler(java.io.InputStream in) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n    f.setXIncludeAware(false);\n    f.setExpandEntityReferences(false);\n    return f.newDocumentBuilder().parse(in);\n  }\n}\n"""))
t("java","328","messagedigest-weak",r"""MessageDigest\.getInstance\(\s*"(MD5|SHA-?1|MD2)"\s*\)""",
"A senha/token de @S@ é protegida com MD5 ou SHA-1, algoritmos rápidos e com colisões conhecidas (CWE-328). A correção usa PBKDF2 com salt aleatório e muitas iterações.",
("""import java.security.MessageDigest;\n\npublic class Senha@SC@ {\n  public static byte[] hash(String senha) throws Exception {\n    return MessageDigest.getInstance("MD5").digest(senha.getBytes("UTF-8"));\n  }\n}\n""",
 """import javax.crypto.SecretKeyFactory;\nimport javax.crypto.spec.PBEKeySpec;\n\npublic class Senha@SC@ {\n  public static byte[] hash(char[] senha, byte[] salt) throws Exception {\n    PBEKeySpec spec = new PBEKeySpec(senha, salt, 310000, 256);\n    return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();\n  }\n}\n"""),
("""import java.security.MessageDigest;\n\nclass Assinatura@SC@ {\n  byte[] digest(byte[] dados) throws Exception {\n    MessageDigest md = MessageDigest.getInstance("SHA-1");\n    return md.digest(dados);\n  }\n}\n""",
 """import java.security.MessageDigest;\n\nclass Assinatura@SC@ {\n  byte[] digest(byte[] dados) throws Exception {\n    MessageDigest md = MessageDigest.getInstance("SHA-256");\n    return md.digest(dados);\n  }\n}\n"""))
t("java","502","objectinputstream",r"""new\s+ObjectInputStream\s*\(""",
"Ler objetos de @S@ com ObjectInputStream a partir de dados externos permite gadget chains e execução remota (CWE-502). A correção troca por desserialização JSON tipada.",
("""import java.io.*;\n\npublic class Sessao@SC@ {\n  public Object restaurar(InputStream in) throws Exception {\n    try (ObjectInputStream ois = new ObjectInputStream(in)) {\n      return ois.readObject();\n    }\n  }\n}\n""",
 """import java.io.*;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n\npublic class Sessao@SC@ {\n  private static final ObjectMapper M = new ObjectMapper();\n  public @SC@Dto restaurar(InputStream in) throws IOException {\n    return M.readValue(in, @SC@Dto.class);\n  }\n}\n"""))
# ---------------- PHP
t("php","89","query-interpolated",r"""(->query|mysqli_query|pg_query)\([^;]*"[^"]*\$\w+""",
"A consulta de @T@ interpola variável vinda da requisição dentro da string SQL, permitindo injeção (CWE-89). A correção usa prepared statement com bind de parâmetro.",
("""<?php\n$@C@ = $_GET['@C@'];\n$res = $pdo->query("SELECT * FROM @T@ WHERE @C@ = '$@C@'");\nforeach ($res as $linha) { echo htmlspecialchars($linha['id']); }\n""",
 """<?php\n$@C@ = $_GET['@C@'] ?? '';\n$st = $pdo->prepare('SELECT * FROM @T@ WHERE @C@ = ?');\n$st->execute([$@C@]);\nforeach ($st as $linha) { echo htmlspecialchars($linha['id']); }\n"""),
("""<?php\nfunction excluir_@S@(mysqli $db, $id) {\n    return mysqli_query($db, "DELETE FROM @T@ WHERE id = $id");\n}\n""",
 """<?php\nfunction excluir_@S@(mysqli $db, $id) {\n    $st = mysqli_prepare($db, 'DELETE FROM @T@ WHERE id = ?');\n    $id = (int) $id;\n    mysqli_stmt_bind_param($st, 'i', $id);\n    return mysqli_stmt_execute($st);\n}\n"""))
t("php","78","shell-concat",r"""(shell_exec|system|exec|passthru|popen)\(\s*['"][^'"]*['"]\s*\.\s*\$""",
"O valor @C@ é concatenado a um comando de shell, permitindo injeção de comandos (CWE-78). A correção escapa o argumento com escapeshellarg e valida o formato.",
("""<?php\n$arquivo = $_POST['arquivo'];\n$saida = shell_exec('file -b /uploads/@T@/' . $arquivo);\necho htmlspecialchars($saida);\n""",
 """<?php\n$arquivo = basename($_POST['arquivo'] ?? '');\n$saida = shell_exec('file -b ' . escapeshellarg('/uploads/@T@/' . $arquivo));\necho htmlspecialchars((string) $saida);\n"""),
("""<?php\nfunction pingar_@S@($host) {\n    system("ping -c 2 " . $host);\n}\n""",
 """<?php\nfunction pingar_@S@($host) {\n    if (!filter_var($host, FILTER_VALIDATE_IP)) { return; }\n    system('ping -c 2 ' . escapeshellarg($host));\n}\n"""))
t("php","79","echo-superglobal",r"""(echo|print)\s+(\$_(GET|POST|REQUEST|COOKIE)\[|["'][^"']*["']\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)\[)""",
"O parâmetro @C@ da requisição é ecoado no HTML sem escape, gerando XSS refletido (CWE-79). A correção aplica htmlspecialchars com ENT_QUOTES antes de exibir.",
("""<?php\necho "<p>Busca por @T@: " . $_GET['@C@'] . "</p>";\n""",
 """<?php\n$termo = htmlspecialchars($_GET['@C@'] ?? '', ENT_QUOTES, 'UTF-8');\necho "<p>Busca por @T@: " . $termo . "</p>";\n"""),
("""<?php\n// formulario de @S@\nprint $_POST['@C@'];\n""",
 """<?php\n// formulario de @S@\n$v = htmlspecialchars($_POST['@C@'] ?? '', ENT_QUOTES, 'UTF-8');\nprint $v;\n"""))
t("php","22","file-superglobal",r"""(include|require|file_get_contents|readfile|fopen)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST)""",
"O nome de arquivo de @S@ vem direto da requisição e é usado em leitura/inclusão de arquivo, permitindo path traversal ou inclusão local (CWE-22). A correção usa basename e confere o caminho real dentro da pasta permitida.",
("""<?php\nreadfile('/var/@T@/docs/' . $_GET['doc']);\n""",
 """<?php\n$base = realpath('/var/@T@/docs');\n$alvo = realpath($base . '/' . basename($_GET['doc'] ?? ''));\nif ($alvo === false || strpos($alvo, $base . DIRECTORY_SEPARATOR) !== 0) { http_response_code(404); exit; }\nreadfile($alvo);\n"""),
("""<?php\ninclude 'paginas/@T@/' . $_GET['aba'] . '.php';\n""",
 """<?php\n$abas = ['resumo', 'historico', '@C@'];\n$aba = in_array($_GET['aba'] ?? '', $abas, true) ? $_GET['aba'] : 'resumo';\ninclude 'paginas/@T@/' . $aba . '.php';\n"""))
t("php","601","header-location-user",r"""header\(\s*["']Location:\s*["']\s*\.\s*\$_(GET|POST|REQUEST)""",
"O cabeçalho Location usa URL vinda do usuário após a operação em @T@, permitindo open redirect (CWE-601). A correção só aceita caminhos relativos internos.",
("""<?php\nsalvar_@S@($_POST);\nheader('Location: ' . $_GET['volta']);\nexit;\n""",
 """<?php\nsalvar_@S@($_POST);\n$volta = $_GET['volta'] ?? '/@T@';\nif (!preg_match('#^/(?!/)#', $volta)) { $volta = '/@T@'; }\nheader('Location: ' . $volta);\nexit;\n"""))
# ---------------- CSHARP
t("csharp","89","sqlcommand-concat",r"""SqlCommand\(\s*(\$"[^"]*\{|"[^"]*"\s*\+)""",
"O comando SQL de @T@ concatena/interpola @C@ do usuário, permitindo injeção de SQL (CWE-89). A correção usa SqlParameter.",
("""using System.Data.SqlClient;\n\npublic class @SC@Dao {\n    public SqlDataReader Buscar(SqlConnection c, string @C@) {\n        var cmd = new SqlCommand("SELECT * FROM @T@ WHERE @C@ = '" + @C@ + "'", c);\n        return cmd.ExecuteReader();\n    }\n}\n""",
 """using System.Data.SqlClient;\n\npublic class @SC@Dao {\n    public SqlDataReader Buscar(SqlConnection c, string @C@) {\n        var cmd = new SqlCommand("SELECT * FROM @T@ WHERE @C@ = @v", c);\n        cmd.Parameters.AddWithValue("@v", @C@);\n        return cmd.ExecuteReader();\n    }\n}\n"""),
("""using Microsoft.Data.SqlClient;\n\nclass Limpa@SC@ {\n    int Executar(SqlConnection c, string id) {\n        using var cmd = new SqlCommand($"DELETE FROM @T@ WHERE Id = {id}", c);\n        return cmd.ExecuteNonQuery();\n    }\n}\n""",
 """using Microsoft.Data.SqlClient;\n\nclass Limpa@SC@ {\n    int Executar(SqlConnection c, int id) {\n        using var cmd = new SqlCommand("DELETE FROM @T@ WHERE Id = @id", c);\n        cmd.Parameters.AddWithValue("@id", id);\n        return cmd.ExecuteNonQuery();\n    }\n}\n"""))
t("csharp","78","process-start-shell",r"""Process\.Start\(\s*"(cmd(\.exe)?|/bin/(ba)?sh|bash|powershell(\.exe)?)"\s*,""",
"O processo é iniciado via shell (cmd/sh) com @C@ concatenado nos argumentos, permitindo injeção de comandos (CWE-78). A correção chama o executável diretamente usando ArgumentList.",
("""using System.Diagnostics;\n\npublic static class Exporta@SC@ {\n    public static void Rodar(string @C@) {\n        Process.Start("cmd.exe", "/c exportador.exe --@C@ " + @C@);\n    }\n}\n""",
 """using System.Diagnostics;\n\npublic static class Exporta@SC@ {\n    public static void Rodar(string @C@) {\n        var psi = new ProcessStartInfo("exportador.exe");\n        psi.ArgumentList.Add("--@C@");\n        psi.ArgumentList.Add(@C@);\n        Process.Start(psi);\n    }\n}\n"""),
("""using System.Diagnostics;\n\nclass Compacta@SC@ {\n    void Zip(string pasta) {\n        Process.Start("/bin/sh", $"-c \\"tar czf /tmp/@T@.tgz {pasta}\\"");\n    }\n}\n""",
 """using System.Diagnostics;\n\nclass Compacta@SC@ {\n    void Zip(string pasta) {\n        var psi = new ProcessStartInfo("tar");\n        foreach (var a in new[] { "czf", "/tmp/@T@.tgz", "--", pasta }) psi.ArgumentList.Add(a);\n        Process.Start(psi);\n    }\n}\n"""))
t("csharp","502","binaryformatter",r"""new\s+(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\s*\(""",
"BinaryFormatter (e similares) desserializa tipos arbitrários dos dados de @S@, permitindo execução remota (CWE-502). A correção usa System.Text.Json com tipo fixo.",
("""using System.IO;\nusing System.Runtime.Serialization.Formatters.Binary;\n\npublic class Cache@SC@ {\n    public object Ler(Stream s) {\n        var bf = new BinaryFormatter();\n        return bf.Deserialize(s);\n    }\n}\n""",
 """using System.IO;\nusing System.Text.Json;\n\npublic class Cache@SC@ {\n    public @SC@Dto? Ler(Stream s) {\n        return JsonSerializer.Deserialize<@SC@Dto>(s);\n    }\n}\n"""))
t("csharp","328","weak-hash-create",r"""\b(MD5|SHA1)\.(Create\(|HashData\()|new\s+(MD5|SHA1)CryptoServiceProvider""",
"A senha de @S@ é armazenada com MD5/SHA-1, hash rápido e inadequado para senhas (CWE-328). A correção usa PBKDF2 (Rfc2898DeriveBytes.Pbkdf2) com salt e SHA-256.",
("""using System.Security.Cryptography;\nusing System.Text;\n\npublic static class Hash@SC@ {\n    public static byte[] Senha(string s) {\n        using var md5 = MD5.Create();\n        return md5.ComputeHash(Encoding.UTF8.GetBytes(s));\n    }\n}\n""",
 """using System.Security.Cryptography;\n\npublic static class Hash@SC@ {\n    public static byte[] Senha(string s, byte[] salt) {\n        return Rfc2898DeriveBytes.Pbkdf2(s, salt, 310000, HashAlgorithmName.SHA256, 32);\n    }\n}\n"""),
("""using System.Security.Cryptography;\nusing System.Text;\n\nclass Token@SC@ {\n    byte[] Gerar(string @C@) => SHA1.HashData(Encoding.UTF8.GetBytes(@C@));\n}\n""",
 """using System.Security.Cryptography;\n\nclass Token@SC@ {\n    byte[] Gerar(string @C@) => RandomNumberGenerator.GetBytes(32);\n}\n"""))
t("csharp","22","path-combine-file",r"""File\.\w+\(\s*Path\.Combine\(""",
"O nome de arquivo de @S@ vindo do usuário é combinado com a raiz sem validação; ../ ou caminho absoluto escapam do diretório (CWE-22). A correção normaliza com GetFullPath e exige que fique dentro da raiz.",
("""using System.IO;\n\npublic class Anexo@SC@ {\n    const string Raiz = "/srv/@T@";\n    public byte[] Ler(string nome) => File.ReadAllBytes(Path.Combine(Raiz, nome));\n}\n""",
 """using System;\nusing System.IO;\n\npublic class Anexo@SC@ {\n    static readonly string Raiz = Path.GetFullPath("/srv/@T@/");\n    public byte[] Ler(string nome) {\n        var alvo = Path.GetFullPath(Path.Combine(Raiz, nome));\n        if (!alvo.StartsWith(Raiz, StringComparison.Ordinal)) throw new UnauthorizedAccessException();\n        return File.ReadAllBytes(alvo);\n    }\n}\n"""),
("""using System.IO;\n\nclass Remove@SC@ {\n    void Apagar(string pasta, string arq) {\n        File.Delete(Path.Combine(pasta, arq));\n    }\n}\n""",
 """using System;\nusing System.IO;\n\nclass Remove@SC@ {\n    void Apagar(string pasta, string arq) {\n        var raiz = Path.GetFullPath(pasta) + Path.DirectorySeparatorChar;\n        var alvo = Path.GetFullPath(Path.Combine(raiz, Path.GetFileName(arq)));\n        if (!alvo.StartsWith(raiz, StringComparison.Ordinal)) throw new UnauthorizedAccessException();\n        File.Delete(alvo);\n    }\n}\n"""))
# ---------------- C
t("c","120","strcpy-strcat",r"""\b(strcpy|strcat)\s*\(""",
"strcpy/strcat copiam o @C@ de @S@ sem checar o tamanho do buffer de destino, causando estouro de buffer (CWE-120). A correção usa snprintf limitado ao tamanho do destino.",
("""#include <string.h>\n\nvoid copiar_@C@(char *dst_@S@, const char *entrada) {\n    char tmp[32];\n    strcpy(tmp, entrada);\n    strcpy(dst_@S@, tmp);\n}\n""",
 """#include <stdio.h>\n#include <string.h>\n\nvoid copiar_@C@(char *dst_@S@, size_t n, const char *entrada) {\n    char tmp[32];\n    snprintf(tmp, sizeof tmp, "%s", entrada);\n    snprintf(dst_@S@, n, "%s", tmp);\n}\n"""),
("""#include <string.h>\n\nvoid caminho_@S@(char out[64], const char *nome) {\n    out[0] = '\\0';\n    strcat(out, "/var/@T@/");\n    strcat(out, nome);\n}\n""",
 """#include <stdio.h>\n\nint caminho_@S@(char out[64], const char *nome) {\n    int n = snprintf(out, 64, "/var/@T@/%s", nome);\n    return (n < 0 || n >= 64) ? -1 : 0;\n}\n"""))
t("c","134","printf-nonliteral",r"""\b(printf\(\s*[a-z_]\w*(->\w+|\[\w*\])?\s*\)|fprintf\(\s*\w+\s*,\s*[a-z_]\w*(->\w+)?\s*\)|syslog\(\s*\w+\s*,\s*[a-z_]\w*(->\w+)?\s*\))""",
"O texto de @S@ controlado externamente é passado como string de formato; especificadores como %n ou %x permitem ler/escrever memória (CWE-134). A correção usa formato literal \"%s\".",
("""#include <stdio.h>\n\nvoid mostrar_@C@(const char *@C@) {\n    printf(@C@);\n}\n""",
 """#include <stdio.h>\n\nvoid mostrar_@C@(const char *@C@) {\n    printf("%s", @C@);\n}\n"""),
("""#include <syslog.h>\n\nvoid auditar_@S@(const char *msg) {\n    syslog(LOG_INFO, msg);\n}\n""",
 """#include <syslog.h>\n\nvoid auditar_@S@(const char *msg) {\n    syslog(LOG_INFO, "%s", msg);\n}\n"""),
("""#include <stdio.h>\n\nvoid erro_@S@(FILE *log, const char *detalhe) {\n    fprintf(log, detalhe);\n}\n""",
 """#include <stdio.h>\n\nvoid erro_@S@(FILE *log, const char *detalhe) {\n    fprintf(log, "%s\\n", detalhe);\n}\n"""))
t("c","78","system-popen",r"""\b(system|popen)\s*\(""",
"O comando é montado com @C@ externo e passado para system/popen, que invocam /bin/sh e permitem injeção de comandos (CWE-78). A correção usa fork + execv com argumentos separados.",
("""#include <stdio.h>\n#include <stdlib.h>\n\nint backup_@S@(const char *@C@) {\n    char cmd[256];\n    snprintf(cmd, sizeof cmd, "cp /dados/@T@/%s /backup/", @C@);\n    return system(cmd);\n}\n""",
 """#include <sys/wait.h>\n#include <unistd.h>\n#include <stdio.h>\n\nint backup_@S@(const char *@C@) {\n    char src[256];\n    snprintf(src, sizeof src, "/dados/@T@/%s", @C@);\n    pid_t p = fork();\n    if (p == 0) { execl("/bin/cp", "cp", "--", src, "/backup/", (char *)NULL); _exit(127); }\n    int st; waitpid(p, &st, 0);\n    return st;\n}\n"""))
t("c","242","gets-call",r"""\bgets\s*\(""",
"gets() lê o @C@ sem limite de tamanho e sempre permite estouro do buffer (CWE-242/120). A correção usa fgets com o tamanho do buffer e remove a quebra de linha.",
("""#include <stdio.h>\n\nint ler_@C@(void) {\n    char @C@[40];\n    gets(@C@);\n    return puts(@C@);\n}\n""",
 """#include <stdio.h>\n#include <string.h>\n\nint ler_@C@(void) {\n    char @C@[40];\n    if (!fgets(@C@, sizeof @C@, stdin)) return -1;\n    @C@[strcspn(@C@, "\\n")] = '\\0';\n    return puts(@C@);\n}\n"""))
t("c","190","malloc-mul-overflow",r"""malloc\(\s*\w+\s*\*\s*sizeof""",
"A alocação de n @T@ multiplica contagem externa por sizeof sem checar overflow; o produto pode estourar e alocar menos que o necessário (CWE-190). A correção usa calloc, que verifica a multiplicação.",
("""#include <stdlib.h>\n\ntypedef struct { int id; char @C@[24]; } @S@_t;\n\n@S@_t *alocar_@T@(size_t n) {\n    return malloc(n * sizeof(@S@_t));\n}\n""",
 """#include <stdlib.h>\n\ntypedef struct { int id; char @C@[24]; } @S@_t;\n\n@S@_t *alocar_@T@(size_t n) {\n    return calloc(n, sizeof(@S@_t));\n}\n"""))
# ---------------- CPP
t("cpp","120","cstr-copy-unbounded",r"""\b(std::)?(strcpy|sprintf|strcat)\s*\(""",
"Copiar o @C@ de @S@ para um array fixo com strcpy/sprintf não limita o tamanho e pode estourar a pilha (CWE-120). A correção usa std::string, que gerencia a memória.",
("""#include <cstring>\n#include <string>\n\nstruct @SC@ { char @C@[32]; };\n\nvoid definir(@SC@ &x, const std::string &v) {\n    std::strcpy(x.@C@, v.c_str());\n}\n""",
 """#include <string>\n\nstruct @SC@ { std::string @C@; };\n\nvoid definir(@SC@ &x, const std::string &v) {\n    x.@C@ = v;\n}\n"""),
("""#include <cstdio>\n#include <string>\n\nstd::string rotulo_@S@(const std::string &@C@, int id) {\n    char buf[48];\n    std::sprintf(buf, "@S@-%d-%s", id, @C@.c_str());\n    return buf;\n}\n""",
 """#include <string>\n\nstd::string rotulo_@S@(const std::string &@C@, int id) {\n    return "@S@-" + std::to_string(id) + "-" + @C@;\n}\n"""))
t("cpp","78","std-system",r"""\b(std::)?(system|popen)\s*\(""",
"A string de comando inclui @C@ externo e é executada por std::system, que passa pelo shell e permite injeção (CWE-78). A correção executa o binário diretamente com execv e vetor de argumentos.",
("""#include <cstdlib>\n#include <string>\n\nint converter_@S@(const std::string &arquivo) {\n    std::string cmd = "convert /in/@T@/" + arquivo + " /out/@T@.pdf";\n    return std::system(cmd.c_str());\n}\n""",
 """#include <string>\n#include <sys/wait.h>\n#include <unistd.h>\n\nint converter_@S@(const std::string &arquivo) {\n    std::string src = "/in/@T@/" + arquivo;\n    pid_t p = fork();\n    if (p == 0) {\n        const char *argv[] = {"convert", src.c_str(), "/out/@T@.pdf", nullptr};\n        execv("/usr/bin/convert", const_cast<char *const *>(argv));\n        _exit(127);\n    }\n    int st = 0; waitpid(p, &st, 0);\n    return st;\n}\n"""))
t("cpp","134","printf-cstr",r"""\b(std::)?(printf\(\s*\w+(\.c_str\(\))?\s*\)|fprintf\(\s*\w+\s*,\s*\w+(\.c_str\(\))?\s*\))""",
"A mensagem de @S@ vinda de fora é usada como string de formato em printf, permitindo leitura/escrita de memória com %x/%n (CWE-134). A correção usa formato fixo ou std::cout.",
("""#include <cstdio>\n#include <string>\n\nvoid log_@S@(const std::string &msg) {\n    std::printf(msg.c_str());\n}\n""",
 """#include <cstdio>\n#include <string>\n\nvoid log_@S@(const std::string &msg) {\n    std::printf("%s\\n", msg.c_str());\n}\n"""),
("""#include <cstdio>\n#include <string>\n\nvoid erro_@S@(const std::string &@C@) {\n    fprintf(stderr, @C@.c_str());\n}\n""",
 """#include <iostream>\n#include <string>\n\nvoid erro_@S@(const std::string &@C@) {\n    std::cerr << @C@ << '\\n';\n}\n"""))
t("cpp","338","rand-token",r"""\b(std::)?rand\s*\(\s*\)""",
"O token de @S@ é gerado com rand(), um PRNG previsível e de baixa entropia (CWE-338). A correção usa RAND_bytes da OpenSSL, um gerador criptograficamente seguro.",
("""#include <cstdlib>\n#include <string>\n\nstd::string token_@S@() {\n    std::string t;\n    for (int i = 0; i < 16; ++i) t += "0123456789abcdef"[std::rand() % 16];\n    return t;\n}\n""",
 """#include <openssl/rand.h>\n#include <stdexcept>\n#include <string>\n\nstd::string token_@S@() {\n    unsigned char b[16];\n    if (RAND_bytes(b, sizeof b) != 1) throw std::runtime_error("rng");\n    std::string t;\n    for (unsigned char c : b) { t += "0123456789abcdef"[c >> 4]; t += "0123456789abcdef"[c & 15]; }\n    return t;\n}\n"""))
t("cpp","22","ifstream-concat",r"""std::ifstream\s+\w+\s*\(\s*\w+\s*\+""",
"O arquivo de @S@ é aberto concatenando a base com nome externo, o que permite ../ e leitura fora do diretório (CWE-22). A correção normaliza com std::filesystem e verifica o prefixo da base.",
("""#include <fstream>\n#include <sstream>\n#include <string>\n\nstd::string ler_@S@(const std::string &nome) {\n    const std::string base = "/srv/@T@/";\n    std::ifstream f(base + nome);\n    std::stringstream ss; ss << f.rdbuf();\n    return ss.str();\n}\n""",
 """#include <filesystem>\n#include <fstream>\n#include <sstream>\n#include <stdexcept>\n#include <string>\nnamespace fs = std::filesystem;\n\nstd::string ler_@S@(const std::string &nome) {\n    const fs::path base = fs::weakly_canonical("/srv/@T@");\n    fs::path alvo = fs::weakly_canonical(base / nome);\n    auto [b, a] = std::mismatch(base.begin(), base.end(), alvo.begin(), alvo.end());\n    if (b != base.end()) throw std::runtime_error("fora da base");\n    std::ifstream f(alvo);\n    std::stringstream ss; ss << f.rdbuf();\n    return ss.str();\n}\n"""))
# ---------------- SQL (generic)
t("sql","89","tsql-exec-concat",r"""(?i)EXEC(UTE)?\s*\(\s*'(?:[^']|'')*'\s*\+\s*@""",
"A procedure de @T@ monta SQL dinâmico concatenando o parâmetro @C@ e executa com EXEC, permitindo injeção (CWE-89). A correção usa sp_executesql com parâmetro tipado.",
("""CREATE PROCEDURE dbo.Buscar@SC@ @@C@ NVARCHAR(100)\nAS\nBEGIN\n    EXEC('SELECT * FROM dbo.@T@ WHERE @C@ = ''' + @@C@ + '''');\nEND;\n""",
 """CREATE PROCEDURE dbo.Buscar@SC@ @@C@ NVARCHAR(100)\nAS\nBEGIN\n    EXEC sp_executesql N'SELECT * FROM dbo.@T@ WHERE @C@ = @p', N'@p NVARCHAR(100)', @p = @@C@;\nEND;\n"""),
("""CREATE PROCEDURE dbo.Ordenar@SC@ @coluna SYSNAME\nAS\nBEGIN\n    EXECUTE('SELECT id, @C@ FROM dbo.@T@ ORDER BY ' + @coluna);\nEND;\n""",
 """CREATE PROCEDURE dbo.Ordenar@SC@ @coluna SYSNAME\nAS\nBEGIN\n    IF @coluna NOT IN (N'id', N'@C@') SET @coluna = N'id';\n    DECLARE @q NVARCHAR(400) = N'SELECT id, @C@ FROM dbo.@T@ ORDER BY ' + QUOTENAME(@coluna);\n    EXEC sp_executesql @q;\nEND;\n"""),rl="generic")
t("sql","89","plpgsql-execute-concat",r"""(?i)EXECUTE\s+'(?:[^']|'')*'\s*\|\|""",
"A função PL/pgSQL concatena o argumento @C@ ao texto do EXECUTE, permitindo injeção de SQL (CWE-89). A correção usa EXECUTE ... USING (ou format com %L/%I), que separa dados do comando.",
("""CREATE OR REPLACE FUNCTION contar_@T@(p_@C@ text) RETURNS bigint AS $$\nDECLARE n bigint;\nBEGIN\n    EXECUTE 'SELECT count(*) FROM @T@ WHERE @C@ = ''' || p_@C@ || '''' INTO n;\n    RETURN n;\nEND;\n$$ LANGUAGE plpgsql;\n""",
 """CREATE OR REPLACE FUNCTION contar_@T@(p_@C@ text) RETURNS bigint AS $$\nDECLARE n bigint;\nBEGIN\n    EXECUTE 'SELECT count(*) FROM @T@ WHERE @C@ = $1' INTO n USING p_@C@;\n    RETURN n;\nEND;\n$$ LANGUAGE plpgsql;\n"""),
("""CREATE OR REPLACE FUNCTION limpar_@T@(p_tabela text) RETURNS void AS $$\nBEGIN\n    EXECUTE 'DELETE FROM ' || p_tabela || ' WHERE criado_em < now() - interval ''90 days''';\nEND;\n$$ LANGUAGE plpgsql;\n""",
 """CREATE OR REPLACE FUNCTION limpar_@T@(p_tabela text) RETURNS void AS $$\nBEGIN\n    IF p_tabela NOT IN ('@T@', '@T@_hist') THEN RAISE EXCEPTION 'tabela invalida'; END IF;\n    EXECUTE format('DELETE FROM %I WHERE criado_em < now() - interval ''90 days''', p_tabela);\nEND;\n$$ LANGUAGE plpgsql;\n"""),rl="generic")
t("sql","89","mysql-prepare-concat",r"""(?i)CONCAT\(\s*'[^']*\b(WHERE|SET|VALUES|ORDER BY|FROM)\b(?:[^']|'')*'\s*,""",
"A procedure MySQL monta a query de @T@ com CONCAT do parâmetro e a executa via PREPARE, permitindo injeção (CWE-89). A correção usa placeholder ? com EXECUTE ... USING.",
("""DELIMITER //\nCREATE PROCEDURE buscar_@S@(IN p_@C@ VARCHAR(80))\nBEGIN\n    SET @q = CONCAT('SELECT * FROM @T@ WHERE @C@ = ''', p_@C@, '''');\n    PREPARE st FROM @q;\n    EXECUTE st;\n    DEALLOCATE PREPARE st;\nEND //\nDELIMITER ;\n""",
 """DELIMITER //\nCREATE PROCEDURE buscar_@S@(IN p_@C@ VARCHAR(80))\nBEGIN\n    SET @q = 'SELECT * FROM @T@ WHERE @C@ = ?';\n    SET @v = p_@C@;\n    PREPARE st FROM @q;\n    EXECUTE st USING @v;\n    DEALLOCATE PREPARE st;\nEND //\nDELIMITER ;\n"""),rl="generic")
t("sql","798","hardcoded-db-password",r"""(?i)(IDENTIFIED\s+BY|PASSWORD\s*=|(WITH|LOGIN)\s+(ENCRYPTED\s+)?PASSWORD)\s*'[^']+'""",
"O script de provisionamento de @T@ cria o usuário de banco com senha fixa no código, que vaza pelo versionamento (CWE-798). A correção recebe a senha por variável injetada em tempo de execução (ou usa autenticação externa).",
("""CREATE USER 'app_@T@'@'%' IDENTIFIED BY '@S@#2024!';\nGRANT SELECT, INSERT ON loja.@T@ TO 'app_@T@'@'%';\n""",
 """CREATE USER 'app_@T@'@'localhost' IDENTIFIED WITH auth_socket;\nGRANT SELECT, INSERT ON loja.@T@ TO 'app_@T@'@'localhost';\n"""),
("""CREATE ROLE svc_@T@ LOGIN PASSWORD 'svc_@C@_123';\nGRANT SELECT ON @T@ TO svc_@T@;\n""",
 """-- senha fornecida pelo cofre via psql: \\set senha `cat /run/secrets/svc_@T@`\nCREATE ROLE svc_@T@ LOGIN;\nALTER ROLE svc_@T@ PASSWORD :'senha';\nGRANT SELECT ON @T@ TO svc_@T@;\n"""),rl="generic")
t("sql","269","grant-all-public",r"""(?i)GRANT\s+ALL(\s+PRIVILEGES)?\b[^;]*\bTO\s+(PUBLIC|'?\w+'?@'%')""",
"Conceder ALL sobre @T@ a PUBLIC (ou a qualquer host) dá a todos os usuários poder de alterar/apagar dados, violando menor privilégio (CWE-269). A correção concede apenas os privilégios necessários a um papel específico.",
("""GRANT ALL ON TABLE @T@ TO PUBLIC;\n""",
 """REVOKE ALL ON TABLE @T@ FROM PUBLIC;\nGRANT SELECT, INSERT, UPDATE ON TABLE @T@ TO app_@T@;\n"""),
("""GRANT ALL PRIVILEGES ON crm.@T@ TO 'relatorio'@'%';\n""",
 """GRANT SELECT ON crm.@T@ TO 'relatorio'@'10.0.0.%';\n"""),rl="generic")
# ---------------- BASH
t("bash","78","eval-variable",r"""\beval\s+["']?[^\n]*\$""",
"eval reinterpreta o conteúdo de @C@ como código de shell, permitindo injeção de comandos (CWE-78/95). A correção usa array de argumentos ou case com valores permitidos.",
("""#!/bin/bash\nfiltro="$1"\neval "grep $filtro /var/log/@T@.log"\n""",
 """#!/bin/bash\nfiltro="$1"\ngrep -- "$filtro" /var/log/@T@.log\n"""),
("""#!/bin/bash\nacao="$1"\neval "@S@_$acao"\n""",
 """#!/bin/bash\nacao="$1"\ncase "$acao" in\n  iniciar|parar|status) "@S@_$acao" ;;\n  *) echo "acao invalida" >&2; exit 1 ;;\nesac\n"""))
t("bash","494","download-pipe-shell",r"""(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b""",
"O instalador de @T@ é baixado e executado direto no shell sem verificar integridade, então um servidor ou rede comprometidos executam código arbitrário (CWE-494). A correção baixa para arquivo, confere SHA-256 e só então executa.",
("""#!/bin/sh\ncurl -fsSL https://get.exemplo.dev/@S@-agent.sh | sh\n""",
 """#!/bin/sh\nset -eu\ncurl -fsSLo /tmp/@S@-agent.sh https://get.exemplo.dev/@S@-agent.sh\necho "${@CU@_SHA256:?}  /tmp/@S@-agent.sh" | sha256sum -c -\nsh /tmp/@S@-agent.sh\n"""),
("""#!/bin/bash\nwget -qO- "https://repo.exemplo.dev/@T@/install" | sudo bash\n""",
 """#!/bin/bash\nset -euo pipefail\nwget -qO /tmp/@T@-install "https://repo.exemplo.dev/@T@/install"\nsha256sum -c <<< "${@CU@_SHA256:?}  /tmp/@T@-install"\nsudo bash /tmp/@T@-install\n"""))
t("bash","377","predictable-tmp",r""">\s*/tmp/[\w.\-]*(\$\$|\$\{?\w+\}?)?[\w.\-]*(\s|$)""",
"O script grava dados de @T@ em arquivo de /tmp com nome fixo ou previsível, permitindo ataques de symlink e corrida (CWE-377). A correção cria o arquivo com mktemp e remove ao sair.",
("""#!/bin/bash\npsql -c "COPY @T@ TO STDOUT" > /tmp/@T@_export.csv\ngzip /tmp/@T@_export.csv\n""",
 """#!/bin/bash\nset -euo pipefail\ntmp=$(mktemp)\ntrap 'rm -f "$tmp"' EXIT\npsql -c "COPY @T@ TO STDOUT" > "$tmp"\ngzip -c "$tmp" > ./@T@_export.csv.gz\n"""),
("""#!/bin/sh\nlista=/tmp/@S@.$$\nls /srv/@T@ > /tmp/@S@.$$\nwc -l "$lista"\n""",
 """#!/bin/sh\nlista=$(mktemp) || exit 1\ntrap 'rm -f "$lista"' EXIT\nls /srv/@T@ > "$lista"\nwc -l "$lista"\n"""))
t("bash","732","chmod-world-writable",r"""chmod\s+(-R\s+)?(0?777|0?666|a\+w|o\+w)\b""",
"Dar permissão de escrita para todos nos arquivos de @T@ permite que qualquer usuário local altere ou substitua dados/scripts (CWE-732). A correção restringe ao dono e grupo.",
("""#!/bin/bash\nmkdir -p /srv/@T@/uploads\nchmod -R 777 /srv/@T@/uploads\n""",
 """#!/bin/bash\nmkdir -p /srv/@T@/uploads\nchown -R www-data:www-data /srv/@T@/uploads\nchmod -R 750 /srv/@T@/uploads\n"""),
("""#!/bin/sh\ncp @S@.conf /etc/@S@.conf\nchmod 666 /etc/@S@.conf\n""",
 """#!/bin/sh\ninstall -m 640 -o root -g @S@ @S@.conf /etc/@S@.conf\n"""))
t("bash","798","hardcoded-secret-var",r"""(?i)\b\w*(PASSWORD|PASSWD|SENHA|TOKEN|SECRET|API_KEY)\w*=["']?[A-Za-z0-9_#!@%.\-]{6,}""",
"A credencial do serviço de @T@ está escrita no script e fica exposta no repositório e em ps (CWE-798). A correção lê o segredo de variável de ambiente/arquivo de segredo e falha se ausente.",
("""#!/bin/bash\nDB_PASSWORD="@S@_Senha_2024"\nmysqldump -u app -p"$DB_PASSWORD" @T@ > @T@.sql\n""",
 """#!/bin/bash\n: "${DB_PASSWORD:?defina DB_PASSWORD}"\nMYSQL_PWD="$DB_PASSWORD" mysqldump -u app @T@ > @T@.sql\n"""),
("""#!/bin/sh\nAPI_TOKEN=tk_@C@_8a7b6c5d4e\ncurl -H "Authorization: Bearer $API_TOKEN" https://api.exemplo.dev/@T@\n""",
 """#!/bin/sh\nAPI_TOKEN=$(cat /run/secrets/@T@_token) || exit 1\ncurl -H "Authorization: Bearer $API_TOKEN" https://api.exemplo.dev/@T@\n"""))
