# Onda 2: templates/APIs novos (Cylab, CC-BY-4.0, original). Placeholders iguais a bill_templates.
E=[("viagens","destino","viagem"),("cupons","codigo","cupom"),("assinaturas","plano","assinatura"),("notas","serie","nota"),
("leiloes","lote","leilao"),("doacoes","campanha","doacao"),("imoveis","bairro","imovel"),("vagas","cargo","vaga"),
("receitas","medico","receita"),("sinistros","apolice","sinistro"),("emprestimos","parcela","emprestimo"),("ingressos","setor","ingresso"),("boletos","linha","boleto")]
T=[]
def t(lang,cwe,slug,regex,exp,*styles,rl=None): T.append(dict(lang=lang,cwe=cwe,slug=slug,regex=regex,exp=exp,styles=styles,rl=rl or lang))
# ===== PYTHON
t("python","79","template-string-user",r"""render_template_string\(\s*(f["']|[^)]*(\+|%\s|\.format))|Markup\(\s*f["']""",
"O HTML de @S@ é montado interpolando o valor do usuário antes do template/Markup, então o conteúdo não é escapado e gera XSS (CWE-79). A correção passa o valor como variável do template (autoescape) ou usa Markup.format, que escapa os argumentos.",
("""from flask import request, render_template_string\n\ndef pagina_@S@():\n    @C@ = request.args.get("@C@", "")\n    return render_template_string(f"<h2>@SC@: {@C@}</h2>")\n""",
 """from flask import request, render_template_string\n\ndef pagina_@S@():\n    @C@ = request.args.get("@C@", "")\n    return render_template_string("<h2>@SC@: {{ v }}</h2>", v=@C@)\n"""),
("""from markupsafe import Markup\n\ndef badge_@S@(rotulo):\n    return Markup(f"<span class='badge'>{rotulo}</span>")\n""",
 """from markupsafe import Markup\n\ndef badge_@S@(rotulo):\n    return Markup("<span class='badge'>{}</span>").format(rotulo)\n"""))
t("python","611","stdlib-xml-parse",r"""\b(etree|ET|ElementTree|minidom)\.(fromstring|parse|parseString)\(""",
"O XML de @T@ recebido de fora é processado com o parser padrão, sujeito a entidades externas e expansão exponencial (XXE/billion laughs, CWE-611). A correção usa defusedxml, que bloqueia DTD e entidades.",
("""import xml.etree.ElementTree as ET\n\ndef importar_@T@(payload: bytes):\n    raiz = ET.fromstring(payload)\n    return [n.findtext("@C@") for n in raiz.iter("@S@")]\n""",
 """import defusedxml.ElementTree as DET\n\ndef importar_@T@(payload: bytes):\n    raiz = DET.fromstring(payload)\n    return [n.findtext("@C@") for n in raiz.iter("@S@")]\n"""),
("""from xml.dom import minidom\n\ndef ler_@S@(texto):\n    doc = minidom.parseString(texto)\n    return doc.getElementsByTagName("@C@")[0].firstChild.data\n""",
 """from defusedxml import minidom as dminidom\n\ndef ler_@S@(texto):\n    doc = dminidom.parseString(texto)\n    return doc.getElementsByTagName("@C@")[0].firstChild.data\n"""))
t("python","95","eval-exec-input",r"""(?<![\w.])(eval|exec)\(""",
"O texto enviado para calcular/configurar @S@ é executado com eval/exec, permitindo execução de código arbitrário (CWE-95). A correção usa ast.literal_eval ou um mapa fechado de operações permitidas.",
("""def parse_filtro_@S@(texto):\n    return eval(texto)\n""",
 """import ast\n\ndef parse_filtro_@S@(texto):\n    return ast.literal_eval(texto)\n"""),
("""def aplicar_regra_@S@(valor, operacao):\n    exec(f"resultado = valor {operacao} 1", globals())\n    return globals()["resultado"]\n""",
 """import operator\nOPS = {"+": operator.add, "-": operator.sub, "*": operator.mul}\n\ndef aplicar_regra_@S@(valor, operacao):\n    if operacao not in OPS:\n        raise ValueError("operacao invalida")\n    return OPS[operacao](valor, 1)\n"""))
t("python","327","weak-cipher-mode",r"""\b(DES|DES3|ARC4|Blowfish)\.new\(|MODE_ECB""",
"Os dados de @S@ são cifrados com algoritmo fraco (DES/RC4) ou modo ECB, que vaza padrões e é quebrável (CWE-327). A correção usa AES-GCM com nonce aleatório, que garante confidencialidade e integridade.",
("""from Crypto.Cipher import AES\n\ndef cifrar_@C@(chave: bytes, dado: bytes) -> bytes:\n    pad = 16 - len(dado) % 16\n    return AES.new(chave, AES.MODE_ECB).encrypt(dado + bytes([pad]) * pad)\n""",
 """from Crypto.Cipher import AES\nfrom Crypto.Random import get_random_bytes\n\ndef cifrar_@C@(chave: bytes, dado: bytes) -> bytes:\n    nonce = get_random_bytes(12)\n    c = AES.new(chave, AES.MODE_GCM, nonce=nonce)\n    ct, tag = c.encrypt_and_digest(dado)\n    return nonce + tag + ct\n"""),
("""from Crypto.Cipher import DES\n\ndef proteger_@S@(chave8: bytes, bloco: bytes) -> bytes:\n    return DES.new(chave8, DES.MODE_CBC, iv=b"\\0" * 8).encrypt(bloco)\n""",
 """from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\n\ndef proteger_@S@(chave32: bytes, bloco: bytes) -> bytes:\n    nonce = os.urandom(12)\n    return nonce + AESGCM(chave32).encrypt(nonce, bloco, b"@T@")\n"""))
t("python","295","tls-verify-off",r"""verify\s*=\s*False|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False""",
"A chamada HTTPS ao serviço de @T@ desativa a validação de certificado, permitindo ataque man-in-the-middle (CWE-295). A correção mantém a verificação padrão (opcionalmente com CA bundle próprio).",
("""import requests\n\ndef consultar_@S@(ident):\n    r = requests.get(f"https://parceiro.exemplo/@T@/{ident}", verify=False, timeout=5)\n    return r.json()\n""",
 """import requests\n\ndef consultar_@S@(ident):\n    r = requests.get(f"https://parceiro.exemplo/@T@/{ident}", verify="/etc/ssl/certs/parceiro-ca.pem", timeout=5)\n    return r.json()\n"""),
("""import ssl, urllib.request\n\ndef baixar_@T@(url):\n    ctx = ssl._create_unverified_context()\n    return urllib.request.urlopen(url, context=ctx).read()\n""",
 """import ssl, urllib.request\n\ndef baixar_@T@(url):\n    ctx = ssl.create_default_context()\n    return urllib.request.urlopen(url, context=ctx).read()\n"""))
t("python","532","log-sensitive",r"""(logger|logging|log)\.(info|debug|warning|error|exception)\([^\n]*\b(senha|password|token|cartao|cvv)\b""",
"O log de @S@ grava credenciais/dados sensíveis em texto claro, que ficam expostos em arquivos e agregadores de log (CWE-532). A correção registra apenas identificadores não sensíveis.",
("""import logging\nlog = logging.getLogger("@T@")\n\ndef autenticar_@S@(usuario, senha):\n    log.info("login %s com senha %s", usuario, senha)\n    return verificar(usuario, senha)\n""",
 """import logging\nlog = logging.getLogger("@T@")\n\ndef autenticar_@S@(usuario, senha):\n    log.info("tentativa de login usuario=%s", usuario)\n    return verificar(usuario, senha)\n"""),
("""import logging\n\ndef cobrar_@S@(cartao, valor):\n    logging.debug(f"cobrando {valor} no cartao {cartao}")\n    return gateway.cobrar(cartao, valor)\n""",
 """import logging\n\ndef cobrar_@S@(numero_cartao, valor):\n    logging.debug("cobrando %s final %s", valor, numero_cartao[-4:])\n    return gateway.cobrar(numero_cartao, valor)\n"""))
t("python","22","tar-zip-extractall",r"""\.extractall\(""",
"O arquivo compactado de @T@ é extraído inteiro sem validar os nomes, e entradas com ../ ou caminho absoluto escrevem fora do destino (zip slip, CWE-22). A correção valida cada membro antes de extrair.",
("""import tarfile\n\ndef restaurar_@T@(pacote, destino):\n    with tarfile.open(pacote) as tf:\n        tf.extractall(destino)\n""",
 """import os, tarfile\n\ndef restaurar_@T@(pacote, destino):\n    base = os.path.realpath(destino)\n    with tarfile.open(pacote) as tf:\n        for m in tf.getmembers():\n            alvo = os.path.realpath(os.path.join(base, m.name))\n            if os.path.commonpath([base, alvo]) != base or m.issym() or m.islnk():\n                raise ValueError(f"entrada insegura: {m.name}")\n            tf.extract(m, base)\n"""),
("""import zipfile\n\ndef importar_@S@_zip(caminho):\n    zipfile.ZipFile(caminho).extractall("/srv/@T@/import")\n""",
 """import os, zipfile\n\ndef importar_@S@_zip(caminho):\n    base = os.path.realpath("/srv/@T@/import")\n    with zipfile.ZipFile(caminho) as z:\n        for nome in z.namelist():\n            alvo = os.path.realpath(os.path.join(base, nome))\n            if os.path.commonpath([base, alvo]) != base:\n                raise ValueError("zip slip")\n            z.extract(nome, base)\n"""))
# ===== JAVASCRIPT
t("javascript","915","mass-assign-merge",r"""(_\.merge|_\.defaultsDeep|Object\.assign|_\.extend)\(\s*\w+(\.\w+)*\s*,\s*req\.body""",
"O corpo da requisição é mesclado inteiro no objeto de @S@, permitindo sobrescrever campos privilegiados e até __proto__ (CWE-915/1321). A correção copia apenas campos permitidos.",
("""const _ = require('lodash');\n\napp.put('/@T@/:id', async (req, res) => {\n  const item = await @SC@.findById(req.params.id);\n  _.merge(item, req.body);\n  await item.save();\n  res.json(item);\n});\n""",
 """app.put('/@T@/:id', async (req, res) => {\n  const item = await @SC@.findById(req.params.id);\n  const { @C@, descricao } = req.body;\n  if (typeof @C@ === 'string') item.@C@ = @C@;\n  if (typeof descricao === 'string') item.descricao = descricao;\n  await item.save();\n  res.json(item);\n});\n"""),
("""router.post('/perfil/@S@', (req, res) => {\n  Object.assign(req.session.user, req.body);\n  res.sendStatus(204);\n});\n""",
 """const EDITAVEIS = ['nome', '@C@'];\n\nrouter.post('/perfil/@S@', (req, res) => {\n  for (const k of EDITAVEIS) if (k in req.body) req.session.user[k] = String(req.body[k]);\n  res.sendStatus(204);\n});\n"""))
t("javascript","22","express-file-param",r"""(sendFile|createReadStream|readFile(Sync)?|download)\(\s*(path\.join\([^)]*)?req\.(params|query|body)""",
"O arquivo de @S@ é escolhido por parâmetro da requisição e unido ao diretório sem validação, permitindo ../ (CWE-22). A correção resolve o caminho e exige que fique dentro da pasta base.",
("""const path = require('path');\n\napp.get('/@T@/arquivo/:nome', (req, res) => {\n  res.sendFile(path.join(__dirname, 'uploads', req.params.nome));\n});\n""",
 """const path = require('path');\nconst BASE = path.resolve(__dirname, 'uploads');\n\napp.get('/@T@/arquivo/:nome', (req, res) => {\n  const alvo = path.resolve(BASE, req.params.nome);\n  if (!alvo.startsWith(BASE + path.sep)) return res.sendStatus(400);\n  res.sendFile(alvo);\n});\n"""),
("""const fs = require('fs');\n\napp.get('/@S@/log', (req, res) => {\n  fs.createReadStream(req.query.arquivo).pipe(res);\n});\n""",
 """const fs = require('fs');\nconst path = require('path');\nconst LOGS = '/var/log/@T@';\n\napp.get('/@S@/log', (req, res) => {\n  const nome = path.basename(String(req.query.arquivo || ''));\n  fs.createReadStream(path.join(LOGS, nome)).on('error', () => res.sendStatus(404)).pipe(res);\n});\n"""))
t("javascript","918","http-client-user-url",r"""(axios(\.get|\.post)?|fetch|got|needle\.get)\(\s*req\.(query|body|params)""",
"O servidor faz requisição para a URL informada pelo cliente, permitindo SSRF contra rede interna e metadados (CWE-918). A correção limita a hosts permitidos e protocolo https.",
("""const axios = require('axios');\n\napp.get('/@T@/preview', async (req, res) => {\n  const r = await axios.get(req.query.url);\n  res.send(r.data);\n});\n""",
 """const axios = require('axios');\nconst HOSTS = new Set(['cdn.exemplo.com.br']);\n\napp.get('/@T@/preview', async (req, res) => {\n  let u;\n  try { u = new URL(String(req.query.url)); } catch { return res.sendStatus(400); }\n  if (u.protocol !== 'https:' || !HOSTS.has(u.hostname)) return res.sendStatus(400);\n  const r = await axios.get(u.toString(), { maxRedirects: 0 });\n  res.send(r.data);\n});\n"""),
("""app.post('/@S@/importar', async (req, res) => {\n  const dados = await fetch(req.body.fonte).then(r => r.json());\n  res.json(await importar@SC@(dados));\n});\n""",
 """const FONTES = { principal: 'https://dados.exemplo.com.br/@T@.json' };\n\napp.post('/@S@/importar', async (req, res) => {\n  const url = FONTES[req.body.fonte];\n  if (!url) return res.sendStatus(400);\n  const dados = await fetch(url).then(r => r.json());\n  res.json(await importar@SC@(dados));\n});\n"""))
t("javascript","798","hardcoded-config-secret",r"""(password|secret|secretAccessKey|accessKeyId|apiKey|clientSecret)\s*:\s*['"][^'"]{8,}['"]""",
"A configuração do cliente de @T@ embute credencial literal no código, exposta no repositório (CWE-798). A correção obtém o segredo do ambiente ou da cadeia padrão de credenciais.",
("""const { S3Client } = require('@aws-sdk/client-s3');\n\nconst s3@SC@ = new S3Client({\n  region: 'sa-east-1',\n  credentials: { accessKeyId: 'AKIAEXEMPLO@CU@', secretAccessKey: 'wJalrEXEMPLO/@C@/chave' },\n});\n""",
 """const { S3Client } = require('@aws-sdk/client-s3');\n\nconst s3@SC@ = new S3Client({ region: 'sa-east-1' }); // credenciais via cadeia padrao (env/role)\n"""),
("""const { Pool } = require('pg');\n\nmodule.exports = new Pool({ host: 'db', user: '@T@_app', password: '@S@-Senha!2024', database: '@T@' });\n""",
 """const { Pool } = require('pg');\n\nmodule.exports = new Pool({ host: 'db', user: '@T@_app', password: process.env.PGPASSWORD, database: '@T@' });\n"""))
t("javascript","79","dom-sink-html",r"""document\.write(ln)?\(|insertAdjacentHTML\(|\.outerHTML\s*=""",
"Valor de @C@ vindo da URL/dados é escrito no DOM como HTML (document.write/insertAdjacentHTML), executando scripts injetados (XSS, CWE-79). A correção cria nós e usa textContent.",
("""const p = new URLSearchParams(location.search);\ndocument.write('<h3>@SC@: ' + p.get('@C@') + '</h3>');\n""",
 """const p = new URLSearchParams(location.search);\nconst h = document.createElement('h3');\nh.textContent = '@SC@: ' + (p.get('@C@') || '');\ndocument.body.appendChild(h);\n"""),
("""function adicionar@SC@(lista, item) {\n  lista.insertAdjacentHTML('beforeend', `<li>${item.@C@}</li>`);\n}\n""",
 """function adicionar@SC@(lista, item) {\n  const li = document.createElement('li');\n  li.textContent = item.@C@;\n  lista.append(li);\n}\n"""))
t("javascript","1333","regexp-user-input",r"""new RegExp\(\s*req\.(query|body|params)""",
"Uma expressão regular é criada direto do texto de busca de @T@ enviado pelo usuário, permitindo ReDoS e mudança de semântica (CWE-1333). A correção escapa os metacaracteres e limita o tamanho.",
("""app.get('/@T@/buscar', (req, res) => {\n  const re = new RegExp(req.query.q, 'i');\n  res.json(lista@SC@.filter(x => re.test(x.@C@)));\n});\n""",
 """const escapeRe = s => s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');\n\napp.get('/@T@/buscar', (req, res) => {\n  const termo = String(req.query.q || '').slice(0, 64);\n  const re = new RegExp(escapeRe(termo), 'i');\n  res.json(lista@SC@.filter(x => re.test(x.@C@)));\n});\n"""))
t("javascript","94","dynamic-code-function",r"""new Function\(|vm\.runIn(New|This)?Context\(|\bvm\.Script\(""",
"A regra de @S@ enviada pelo usuário vira código JavaScript (new Function/vm), permitindo execução arbitrária no servidor (CWE-94). A correção interpreta apenas um conjunto fechado de operações.",
("""function calcular@SC@(expr, ctx) {\n  return new Function('ctx', 'return ' + expr)(ctx);\n}\n""",
 """const OPS = { soma: (a, b) => a + b, max: Math.max, min: Math.min };\n\nfunction calcular@SC@({ op, a, b }) {\n  if (!Object.hasOwn(OPS, op)) throw new Error('op invalida');\n  return OPS[op](Number(a), Number(b));\n}\n"""),
("""const vm = require('vm');\n\nexports.filtro@SC@ = (codigo, item) => vm.runInNewContext(codigo, { item });\n""",
 """exports.filtro@SC@ = ({ campo, valor }, item) => {\n  if (!['@C@', 'status'].includes(campo)) throw new Error('campo invalido');\n  return item[campo] === valor;\n};\n"""))
# ===== TYPESCRIPT
t("typescript","89","orm-raw-unsafe",r"""(\$queryRawUnsafe|\$executeRawUnsafe)\(|\.(raw|whereRaw)\(\s*`[^`]*\$\{""",
"A consulta de @T@ usa API raw/unsafe do ORM com interpolação do parâmetro, voltando a permitir injeção de SQL (CWE-89). A correção usa tagged template seguro ou bindings.",
("""import { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\n\nexport const por@CC@ = (v: string) =>\n  prisma.$queryRawUnsafe(`SELECT * FROM @T@ WHERE @C@ = '${v}'`);\n""",
 """import { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\n\nexport const por@CC@ = (v: string) =>\n  prisma.$queryRaw`SELECT * FROM @T@ WHERE @C@ = ${v}`;\n"""),
("""import { Knex } from 'knex';\n\nexport function ativos@SC@(db: Knex, @C@: string) {\n  return db('@T@').whereRaw(`@C@ = '${@C@}' AND ativo = 1`);\n}\n""",
 """import { Knex } from 'knex';\n\nexport function ativos@SC@(db: Knex, @C@: string) {\n  return db('@T@').whereRaw('@C@ = ? AND ativo = 1', [@C@]);\n}\n"""))
t("typescript","79","angular-bypass-sanitizer",r"""bypassSecurityTrust(Html|Url|Script|ResourceUrl|Style)\(""",
"O componente de @S@ marca conteúdo vindo da API/usuário como confiável com bypassSecurityTrust*, desativando a sanitização do Angular (XSS, CWE-79). A correção deixa o Angular sanitizar o valor.",
("""import { Component, Input } from '@angular/core';\nimport { DomSanitizer, SafeHtml } from '@angular/platform-browser';\n\n@Component({ selector: 'app-@S@', template: '<div [innerHTML]="html"></div>' })\nexport class @SC@Component {\n  html: SafeHtml = '';\n  constructor(private s: DomSanitizer) {}\n  @Input() set descricao(v: string) { this.html = this.s.bypassSecurityTrustHtml(v); }\n}\n""",
 """import { Component, Input, SecurityContext } from '@angular/core';\nimport { DomSanitizer } from '@angular/platform-browser';\n\n@Component({ selector: 'app-@S@', template: '<div [innerHTML]="html"></div>' })\nexport class @SC@Component {\n  html = '';\n  constructor(private s: DomSanitizer) {}\n  @Input() set descricao(v: string) { this.html = this.s.sanitize(SecurityContext.HTML, v) ?? ''; }\n}\n"""),
("""import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';\n\nexport function link@SC@(s: DomSanitizer, url: string): SafeResourceUrl {\n  return s.bypassSecurityTrustResourceUrl(url);\n}\n""",
 """import { SecurityContext } from '@angular/core';\nimport { DomSanitizer } from '@angular/platform-browser';\n\nexport function link@SC@(s: DomSanitizer, url: string): string {\n  return s.sanitize(SecurityContext.URL, url) ?? 'about:blank';\n}\n"""))
t("typescript","601","client-location-redirect",r"""location(\.href)?\s*=\s*(new URLSearchParams|params|query|router\.query|searchParams)|location\.(assign|replace)\(\s*(params|query|searchParams|new URLSearchParams)""",
"Após o login em @T@, o front-end redireciona para o valor do parâmetro da URL sem validação, permitindo open redirect e URLs javascript: (CWE-601). A correção aceita somente caminhos internos.",
("""export function posLogin@SC@(): void {\n  window.location.href = new URLSearchParams(window.location.search).get('next') ?? '/';\n}\n""",
 """export function posLogin@SC@(): void {\n  const n = new URLSearchParams(window.location.search).get('next') ?? '/';\n  const destino = n.startsWith('/') && !n.startsWith('//') ? n : '/@T@';\n  window.location.href = destino;\n}\n"""),
("""export function voltar@SC@(searchParams: URLSearchParams): void {\n  location.assign(searchParams.get('retorno') || '/');\n}\n""",
 """const ROTAS = new Set(['/', '/@T@', '/conta']);\n\nexport function voltar@SC@(sp: URLSearchParams): void {\n  const r = sp.get('retorno') || '/';\n  location.assign(ROTAS.has(r) ? r : '/');\n}\n"""))
t("typescript","22","readfile-template-path",r"""(readFileSync|readFile|unlink|unlinkSync|writeFileSync)\(\s*`[^`]*\$\{""",
"O caminho do arquivo de @S@ é montado com template literal a partir do nome recebido, permitindo path traversal (CWE-22). A correção usa resolve/validação e confere a pasta base.",
("""import { readFileSync } from 'fs';\n\nexport function lerAnexo@SC@(nome: string): Buffer {\n  return readFileSync(`./uploads/@T@/${nome}`);\n}\n""",
 """import { readFileSync } from 'fs';\nimport { resolve, sep } from 'path';\nconst BASE = resolve('./uploads/@T@');\n\nexport function lerAnexo@SC@(nome: string): Buffer {\n  const alvo = resolve(BASE, nome);\n  if (!alvo.startsWith(BASE + sep)) throw new Error('caminho invalido');\n  return readFileSync(alvo);\n}\n"""),
("""import { promises as fs } from 'fs';\n\nexport async function apagar@SC@(id: string): Promise<void> {\n  await fs.unlink(`/var/cache/@T@/${id}.json`);\n}\n""",
 """import { promises as fs } from 'fs';\nimport { join } from 'path';\n\nexport async function apagar@SC@(id: string): Promise<void> {\n  if (!/^[a-z0-9-]{1,40}$/.test(id)) throw new Error('id invalido');\n  await fs.unlink(join('/var/cache/@T@', id + '.json'));\n}\n"""))
t("typescript","614","cookie-insecure-flags",r"""(httpOnly|secure)\s*:\s*false""",
"O cookie de sessão de @T@ é emitido sem Secure/HttpOnly, podendo trafegar sem TLS e ser lido por scripts em XSS (CWE-614/1004). A correção liga secure, httpOnly e sameSite.",
("""import { Response } from 'express';\n\nexport function setSessao@SC@(res: Response, sid: string): void {\n  res.cookie('sid_@S@', sid, { httpOnly: false, secure: false });\n}\n""",
 """import { Response } from 'express';\n\nexport function setSessao@SC@(res: Response, sid: string): void {\n  res.cookie('sid_@S@', sid, { httpOnly: true, secure: true, sameSite: 'lax' });\n}\n"""),
("""import session from 'express-session';\n\nexport const sessao@SC@ = session({\n  secret: process.env.SESSION_SECRET!,\n  cookie: { secure: false, maxAge: 86400000 },\n});\n""",
 """import session from 'express-session';\n\nexport const sessao@SC@ = session({\n  secret: process.env.SESSION_SECRET!,\n  cookie: { secure: true, httpOnly: true, sameSite: 'strict', maxAge: 86400000 },\n});\n"""))
t("typescript","502","unsafe-unserialize",r"""\bunserialize\(|yaml\.load\(\s*\w+\s*\)""",
"Os dados de @S@ são desserializados com node-serialize/js-yaml sem schema seguro, o que permite executar funções ou construir objetos arbitrários (CWE-502). A correção usa JSON.parse ou schema restrito.",
("""import serialize from 'node-serialize';\n\nexport function restaurar@SC@(cookie: string): unknown {\n  return serialize.unserialize(Buffer.from(cookie, 'base64').toString());\n}\n""",
 """export function restaurar@SC@(cookie: string): unknown {\n  return JSON.parse(Buffer.from(cookie, 'base64').toString());\n}\n"""),
("""import yaml from 'js-yaml';\n\nexport const carregar@SC@ = (texto: string) => yaml.load(texto);\n""",
 """import yaml from 'js-yaml';\n\nexport const carregar@SC@ = (texto: string) => yaml.load(texto, { schema: yaml.FAILSAFE_SCHEMA });\n"""))
t("typescript","347","jwt-decode-no-verify",r"""jwt\.decode\(|algorithms\s*:\s*\[[^\]]*['"]none['"]""",
"A identidade do usuário de @T@ é lida do JWT sem verificar a assinatura (decode ou alg none), permitindo forjar tokens (CWE-347). A correção usa jwt.verify com segredo e algoritmo fixo.",
("""import jwt from 'jsonwebtoken';\n\nexport function usuario@SC@(token: string): string {\n  const p = jwt.decode(token) as { sub: string };\n  return p.sub;\n}\n""",
 """import jwt from 'jsonwebtoken';\n\nexport function usuario@SC@(token: string): string {\n  const p = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] }) as { sub: string };\n  return p.sub;\n}\n"""),
("""import jwt from 'jsonwebtoken';\n\nexport const validar@SC@ = (t: string, k: string) => jwt.verify(t, k, { algorithms: ['HS256', 'none'] });\n""",
 """import jwt from 'jsonwebtoken';\n\nexport const validar@SC@ = (t: string, k: string) => jwt.verify(t, k, { algorithms: ['HS256'] });\n"""))
# ===== JAVA
t("java","22","file-from-parameter",r"""new\s+(File|FileInputStream|FileReader)\(\s*[^;]*request\.getParameter""",
"O servlet de @T@ abre arquivo com nome vindo direto do parâmetro HTTP, permitindo ../ (CWE-22). A correção normaliza o caminho e exige que permaneça sob o diretório base.",
("""import java.io.*;\nimport javax.servlet.http.*;\n\npublic class Download@SC@Servlet extends HttpServlet {\n  protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws IOException {\n    try (InputStream in = new FileInputStream("/srv/@T@/" + request.getParameter("arquivo"))) {\n      in.transferTo(resp.getOutputStream());\n    }\n  }\n}\n""",
 """import java.io.*;\nimport java.nio.file.*;\nimport javax.servlet.http.*;\n\npublic class Download@SC@Servlet extends HttpServlet {\n  private static final Path BASE = Paths.get("/srv/@T@").toAbsolutePath().normalize();\n  protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws IOException {\n    Path alvo = BASE.resolve(request.getParameter("arquivo")).normalize();\n    if (!alvo.startsWith(BASE)) { resp.sendError(400); return; }\n    Files.copy(alvo, resp.getOutputStream());\n  }\n}\n"""),
("""import java.io.File;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Remove@SC@ {\n  boolean apagar(HttpServletRequest request) {\n    return new File("/tmp/@T@", request.getParameter("nome")).delete();\n  }\n}\n""",
 """import java.io.File;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Remove@SC@ {\n  boolean apagar(HttpServletRequest request) {\n    String nome = java.nio.file.Paths.get(request.getParameter("nome")).getFileName().toString();\n    return new File("/tmp/@T@", nome).delete();\n  }\n}\n"""))
t("java","79","servlet-writer-param",r"""\.(print|println|write|append)\([^;]*request\.getParameter""",
"O servlet de @S@ escreve o parâmetro da requisição direto na resposta HTML, gerando XSS refletido (CWE-79). A correção codifica o valor com OWASP Encoder antes de escrever.",
("""import java.io.IOException;\nimport javax.servlet.http.*;\n\npublic class Busca@SC@Servlet extends HttpServlet {\n  protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws IOException {\n    resp.setContentType("text/html");\n    resp.getWriter().println("<p>Nenhum resultado para " + request.getParameter("@C@") + "</p>");\n  }\n}\n""",
 """import java.io.IOException;\nimport javax.servlet.http.*;\nimport org.owasp.encoder.Encode;\n\npublic class Busca@SC@Servlet extends HttpServlet {\n  protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws IOException {\n    resp.setContentType("text/html");\n    String v = Encode.forHtml(request.getParameter("@C@"));\n    resp.getWriter().println("<p>Nenhum resultado para " + v + "</p>");\n  }\n}\n"""))
t("java","918","url-from-parameter",r"""new\s+URL\(\s*request\.getParameter|URI\.create\(\s*request\.getParameter""",
"O backend busca a URL passada pelo cliente para gerar a prévia/webhook de @S@, permitindo SSRF contra serviços internos (CWE-918). A correção valida host/esquema ou monta a URL com base fixa.",
("""import java.io.InputStream;\nimport java.net.URL;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Preview@SC@ {\n  InputStream abrir(HttpServletRequest request) throws Exception {\n    return new URL(request.getParameter("url")).openStream();\n  }\n}\n""",
 """import java.io.InputStream;\nimport java.net.URL;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Preview@SC@ {\n  InputStream abrir(HttpServletRequest request) throws Exception {\n    String id = request.getParameter("id");\n    if (id == null || !id.matches("[0-9]{1,12}")) throw new IllegalArgumentException("id");\n    return new URL("https://imagens.exemplo.com.br/@T@/" + id).openStream();\n  }\n}\n"""),
("""import java.net.URI;\nimport java.net.http.*;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Webhook@SC@ {\n  void disparar(HttpClient c, HttpServletRequest request) throws Exception {\n    c.send(HttpRequest.newBuilder(URI.create(request.getParameter("callback"))).build(), HttpResponse.BodyHandlers.discarding());\n  }\n}\n""",
 """import java.net.URI;\nimport java.net.http.*;\nimport java.util.Set;\nimport javax.servlet.http.HttpServletRequest;\n\nclass Webhook@SC@ {\n  private static final Set<String> HOSTS = Set.of("hooks.parceiro.com.br");\n  void disparar(HttpClient c, HttpServletRequest request) throws Exception {\n    URI u = new URI(request.getParameter("callback"));\n    if (!"https".equals(u.getScheme()) || !HOSTS.contains(u.getHost())) throw new SecurityException("destino");\n    c.send(HttpRequest.newBuilder(u).build(), HttpResponse.BodyHandlers.discarding());\n  }\n}\n"""))
t("java","330","insecure-random",r"""new\s+Random\(|Math\.random\(""",
"O código/token de @S@ é gerado com java.util.Random ou Math.random, previsíveis a partir de poucas saídas (CWE-330). A correção usa SecureRandom.",
("""import java.util.Random;\n\npublic class Codigo@SC@ {\n  public static String gerar() {\n    return String.format("%06d", new Random().nextInt(1000000));\n  }\n}\n""",
 """import java.security.SecureRandom;\n\npublic class Codigo@SC@ {\n  private static final SecureRandom RNG = new SecureRandom();\n  public static String gerar() {\n    return String.format("%06d", RNG.nextInt(1000000));\n  }\n}\n"""),
("""class Senha@SC@Temporaria {\n  static String nova() {\n    return Long.toHexString(Double.doubleToLongBits(Math.random()));\n  }\n}\n""",
 """import java.security.SecureRandom;\nimport java.util.Base64;\n\nclass Senha@SC@Temporaria {\n  static String nova() {\n    byte[] b = new byte[18];\n    new SecureRandom().nextBytes(b);\n    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);\n  }\n}\n"""))
t("java","327","cipher-weak-mode",r"""Cipher\.getInstance\(\s*"(DES|DESede|RC4|Blowfish|AES|AES/ECB[^"]*|DES/[^"]*)"\s*\)""",
"Os dados de @S@ são cifrados com algoritmo fraco ou AES em ECB (o padrão de \"AES\"), que vaza padrões e não autentica (CWE-327). A correção usa AES/GCM/NoPadding com IV aleatório.",
("""import javax.crypto.Cipher;\nimport javax.crypto.SecretKey;\n\npublic class Cripto@SC@ {\n  public byte[] cifrar(SecretKey k, byte[] dado) throws Exception {\n    Cipher c = Cipher.getInstance("AES");\n    c.init(Cipher.ENCRYPT_MODE, k);\n    return c.doFinal(dado);\n  }\n}\n""",
 """import java.security.SecureRandom;\nimport javax.crypto.Cipher;\nimport javax.crypto.SecretKey;\nimport javax.crypto.spec.GCMParameterSpec;\n\npublic class Cripto@SC@ {\n  public byte[] cifrar(SecretKey k, byte[] dado) throws Exception {\n    byte[] iv = new byte[12];\n    new SecureRandom().nextBytes(iv);\n    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n    c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, iv));\n    byte[] ct = c.doFinal(dado);\n    byte[] out = new byte[12 + ct.length];\n    System.arraycopy(iv, 0, out, 0, 12);\n    System.arraycopy(ct, 0, out, 12, ct.length);\n    return out;\n  }\n}\n"""),
("""import javax.crypto.Cipher;\nimport javax.crypto.spec.SecretKeySpec;\n\nclass Legado@SC@ {\n  byte[] proteger(byte[] chave8, byte[] d) throws Exception {\n    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave8, "DES"));\n    return c.doFinal(d);\n  }\n}\n""",
 """import javax.crypto.Cipher;\nimport javax.crypto.spec.GCMParameterSpec;\nimport javax.crypto.spec.SecretKeySpec;\n\nclass Legado@SC@ {\n  byte[] proteger(byte[] chave32, byte[] iv12, byte[] d) throws Exception {\n    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave32, "AES"), new GCMParameterSpec(128, iv12));\n    return c.doFinal(d);\n  }\n}\n"""))
t("java","90","ldap-filter-concat",r""""\(&?\(?\w*\(?(uid|cn|mail|sAMAccountName)=["']?\s*\+|\((uid|cn|mail)="\s*\+""",
"O filtro LDAP para localizar o @S@ concatena o valor do usuário, permitindo injetar *, ) ou | e alterar a busca (CWE-90). A correção usa filtro parametrizado ({0}) com argumentos.",
("""import javax.naming.directory.*;\n\nclass Ldap@SC@ {\n  Object buscar(DirContext ctx, String uid) throws Exception {\n    SearchControls sc = new SearchControls();\n    return ctx.search("ou=@T@,dc=exemplo,dc=br", "(uid=" + uid + ")", sc);\n  }\n}\n""",
 """import javax.naming.directory.*;\n\nclass Ldap@SC@ {\n  Object buscar(DirContext ctx, String uid) throws Exception {\n    SearchControls sc = new SearchControls();\n    return ctx.search("ou=@T@,dc=exemplo,dc=br", "(uid={0})", new Object[]{uid}, sc);\n  }\n}\n"""),
("""import javax.naming.directory.*;\n\nclass Grupo@SC@ {\n  Object membros(DirContext ctx, String nome) throws Exception {\n    String filtro = "(&(objectClass=group)(cn=" + nome + "))";\n    return ctx.search("dc=exemplo,dc=br", filtro, new SearchControls());\n  }\n}\n""",
 """import javax.naming.directory.*;\n\nclass Grupo@SC@ {\n  Object membros(DirContext ctx, String nome) throws Exception {\n    return ctx.search("dc=exemplo,dc=br", "(&(objectClass=group)(cn={0}))", new Object[]{nome}, new SearchControls());\n  }\n}\n"""))
t("java","295","trust-all-certs",r"""checkServerTrusted\([^)]*\)\s*(throws\s+[\w.]+\s*)?\{\s*\}|setHostnameVerifier\(\s*\([^)]*\)\s*->\s*true""",
"O cliente HTTPS de @T@ aceita qualquer certificado/hostname, anulando o TLS e permitindo MITM (CWE-295). A correção usa o SSLContext e o verificador padrão da JVM.",
("""import javax.net.ssl.*;\nimport java.security.cert.X509Certificate;\n\nclass Tls@SC@ {\n  SSLContext ctx() throws Exception {\n    TrustManager tm = new X509TrustManager() {\n      public void checkClientTrusted(X509Certificate[] c, String a) {}\n      public void checkServerTrusted(X509Certificate[] c, String a) {}\n      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }\n    };\n    SSLContext s = SSLContext.getInstance("TLS");\n    s.init(null, new TrustManager[]{tm}, null);\n    return s;\n  }\n}\n""",
 """import javax.net.ssl.*;\n\nclass Tls@SC@ {\n  SSLContext ctx() throws Exception {\n    SSLContext s = SSLContext.getInstance("TLSv1.3");\n    s.init(null, null, null);\n    return s;\n  }\n}\n"""),
("""import javax.net.ssl.HttpsURLConnection;\n\nclass Conexao@SC@ {\n  void preparar(HttpsURLConnection c) {\n    c.setHostnameVerifier((host, sessao) -> true);\n  }\n}\n""",
 """import javax.net.ssl.HttpsURLConnection;\n\nclass Conexao@SC@ {\n  void preparar(HttpsURLConnection c) {\n    c.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());\n  }\n}\n"""))
# ===== PHP
t("php","502","unserialize-input",r"""unserialize\(\s*(\$_(COOKIE|GET|POST|REQUEST)|base64_decode\(\s*\$_)""",
"O estado de @S@ é desserializado com unserialize() a partir de dados do cliente, permitindo injeção de objetos e POP chains (CWE-502). A correção usa json_decode.",
("""<?php\n$carrinho = unserialize($_COOKIE['@S@_carrinho']);\nforeach ($carrinho as $item) { adicionar_@S@($item); }\n""",
 """<?php\n$carrinho = json_decode($_COOKIE['@S@_carrinho'] ?? '[]', true, 8, JSON_THROW_ON_ERROR);\nforeach ((array) $carrinho as $item) { adicionar_@S@($item); }\n"""),
("""<?php\n$prefs = unserialize(base64_decode($_POST['prefs_@S@']));\n""",
 """<?php\n$prefs = json_decode(base64_decode($_POST['prefs_@S@'] ?? ''), true);\nif (!is_array($prefs)) { $prefs = []; }\n"""))
t("php","95","eval-user-code",r"""\b(eval|assert|create_function)\s*\(""",
"A expressão de cálculo/ordenação de @S@ vinda do usuário é executada com eval/create_function, permitindo execução de código PHP arbitrário (CWE-95). A correção restringe a operações permitidas.",
("""<?php\nfunction calcular_@S@($expr) {\n    return eval('return ' . $expr . ';');\n}\n""",
 """<?php\nfunction calcular_@S@($a, $op, $b) {\n    $a = (float) $a; $b = (float) $b;\n    return match ($op) { '+' => $a + $b, '-' => $a - $b, '*' => $a * $b, default => throw new InvalidArgumentException('op') };\n}\n"""),
("""<?php\n$campo = $_GET['ordem'] ?? '@C@';\n$f = create_function('$a,$b', 'return strcmp($a["' . $campo . '"], $b["' . $campo . '"]);');\nusort($lista_@T@, $f);\n""",
 """<?php\n$campo = in_array($_GET['ordem'] ?? '', ['@C@', 'id'], true) ? $_GET['ordem'] : '@C@';\nusort($lista_@T@, fn($a, $b) => strcmp((string) $a[$campo], (string) $b[$campo]));\n"""))
t("php","918","fetch-user-url",r"""(curl_init|file_get_contents|fopen)\(\s*\$_(GET|POST|REQUEST)\[|curl_init\(\s*\$url\b""",
"O servidor busca a URL fornecida pelo usuário (para importar @T@), permitindo SSRF contra serviços internos e file:// (CWE-918). A correção valida esquema e host contra lista permitida.",
("""<?php\n$conteudo = file_get_contents($_GET['feed']);\nimportar_@T@($conteudo);\n""",
 """<?php\n$feed = $_GET['feed'] ?? '';\n$p = parse_url($feed);\nif (($p['scheme'] ?? '') !== 'https' || !in_array($p['host'] ?? '', ['feeds.exemplo.com.br'], true)) { http_response_code(400); exit; }\nimportar_@T@(file_get_contents($feed));\n"""),
("""<?php\n$url = $_POST['avatar_url'];\n$ch = curl_init($url);\ncurl_setopt($ch, CURLOPT_RETURNTRANSFER, true);\nsalvar_@S@_avatar(curl_exec($ch));\n""",
 """<?php\n$entrada = $_POST['avatar_url'] ?? '';\n$p = parse_url($entrada);\nif (($p['scheme'] ?? '') !== 'https' || ($p['host'] ?? '') !== 'avatars.exemplo.com.br') { http_response_code(400); exit; }\n$ch = curl_init($entrada);\ncurl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_FOLLOWLOCATION => false]);\nsalvar_@S@_avatar(curl_exec($ch));\n"""))
t("php","328","weak-password-hash",r"""\b(md5|sha1)\(\s*\$(senha|password|pass|pwd|_POST)""",
"A senha do @S@ é armazenada/comparada com md5/sha1, hash rápido e sem salt, quebrável por tabelas e GPU (CWE-328). A correção usa password_hash/password_verify.",
("""<?php\nfunction cadastrar_@S@(PDO $db, $login, $senha) {\n    $st = $db->prepare('INSERT INTO @T@ (login, senha) VALUES (?, ?)');\n    $st->execute([$login, md5($senha)]);\n}\n""",
 """<?php\nfunction cadastrar_@S@(PDO $db, $login, $senha) {\n    $st = $db->prepare('INSERT INTO @T@ (login, senha) VALUES (?, ?)');\n    $st->execute([$login, password_hash($senha, PASSWORD_ARGON2ID)]);\n}\n"""),
("""<?php\nfunction confere_@S@($hash_salvo) {\n    return sha1($_POST['senha']) === $hash_salvo;\n}\n""",
 """<?php\nfunction confere_@S@($hash_salvo) {\n    return password_verify($_POST['senha'] ?? '', $hash_salvo);\n}\n"""))
t("php","89","laravel-raw-interp",r"""(whereRaw|selectRaw|orderByRaw|havingRaw|DB::raw|DB::select|DB::statement)\(\s*("[^"]*\$|'[^']*'\s*\.\s*\$)""",
"A query Laravel de @T@ usa método *Raw/DB::select com variável interpolada, contornando o binding e permitindo injeção (CWE-89). A correção passa os valores no array de bindings.",
("""<?php\nfunction busca_@S@($@C@) {\n    return DB::select("SELECT * FROM @T@ WHERE @C@ = '$@C@'");\n}\n""",
 """<?php\nfunction busca_@S@($@C@) {\n    return DB::select('SELECT * FROM @T@ WHERE @C@ = ?', [$@C@]);\n}\n"""),
("""<?php\nfunction recentes_@T@($dias) {\n    return @SC@::whereRaw('criado_em > NOW() - INTERVAL ' . $dias . ' DAY')->get();\n}\n""",
 """<?php\nfunction recentes_@T@($dias) {\n    return @SC@::whereRaw('criado_em > NOW() - INTERVAL ? DAY', [(int) $dias])->get();\n}\n"""))
t("php","611","libxml-noent",r"""LIBXML_NOENT|LIBXML_DTDLOAD""",
"O XML de @T@ é carregado com LIBXML_NOENT/DTDLOAD, que substitui entidades externas e permite XXE (CWE-611). A correção remove essas flags e usa LIBXML_NONET.",
("""<?php\n$xml = simplexml_load_string(file_get_contents('php://input'), 'SimpleXMLElement', LIBXML_NOENT);\nprocessar_@S@((string) $xml->@C@);\n""",
 """<?php\n$xml = simplexml_load_string(file_get_contents('php://input'), 'SimpleXMLElement', LIBXML_NONET);\nprocessar_@S@((string) $xml->@C@);\n"""),
("""<?php\n$doc = new DOMDocument();\n$doc->loadXML($_POST['xml_@S@'], LIBXML_DTDLOAD | LIBXML_NOENT);\n""",
 """<?php\n$doc = new DOMDocument();\n$doc->loadXML($_POST['xml_@S@'] ?? '', LIBXML_NONET);\n"""))
t("php","330","weak-random-token",r"""\b(rand|mt_rand|uniqid|lcg_value)\(""",
"O token de @S@ é gerado com rand/mt_rand/uniqid, que não são criptograficamente seguros e podem ser previstos (CWE-330). A correção usa random_bytes/random_int.",
("""<?php\nfunction token_reset_@S@() {\n    return md5(uniqid('', true));\n}\n""",
 """<?php\nfunction token_reset_@S@() {\n    return bin2hex(random_bytes(32));\n}\n"""),
("""<?php\nfunction codigo_@S@() {\n    return str_pad((string) mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);\n}\n""",
 """<?php\nfunction codigo_@S@() {\n    return str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);\n}\n"""))
# ===== CSHARP
t("csharp","79","html-content-interp",r"""Content\(\s*\$"|new\s+HtmlString\(\s*\$"|Html\.Raw\(""",
"O controller de @T@ monta HTML interpolando valor do usuário e o devolve como conteúdo bruto, causando XSS (CWE-79). A correção codifica com HtmlEncoder antes de compor.",
("""using Microsoft.AspNetCore.Mvc;\n\npublic class @SC@Controller : Controller {\n    public IActionResult Ola(string nome) =>\n        Content($"<p>Bem-vindo, {nome}</p>", "text/html");\n}\n""",
 """using System.Text.Encodings.Web;\nusing Microsoft.AspNetCore.Mvc;\n\npublic class @SC@Controller : Controller {\n    public IActionResult Ola(string nome) =>\n        Content("<p>Bem-vindo, " + HtmlEncoder.Default.Encode(nome ?? "") + "</p>", "text/html");\n}\n"""),
("""using Microsoft.AspNetCore.Html;\n\npublic static class Badge@SC@ {\n    public static IHtmlContent Render(string @C@) => new HtmlString($"<b>{@C@}</b>");\n}\n""",
 """using Microsoft.AspNetCore.Html;\n\npublic static class Badge@SC@ {\n    public static IHtmlContent Render(string @C@) =>\n        new HtmlContentBuilder().AppendHtml("<b>").Append(@C@).AppendHtml("</b>");\n}\n"""))
t("csharp","611","xml-dtd-parse",r"""DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver""",
"O XML de @T@ é lido com DTD habilitado ou resolver de URL, permitindo XXE para ler arquivos ou fazer SSRF (CWE-611). A correção proíbe DTD e zera o XmlResolver.",
("""using System.Xml;\n\npublic class Leitor@SC@ {\n    public XmlReader Abrir(System.IO.Stream s) {\n        var cfg = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };\n        return XmlReader.Create(s, cfg);\n    }\n}\n""",
 """using System.Xml;\n\npublic class Leitor@SC@ {\n    public XmlReader Abrir(System.IO.Stream s) {\n        var cfg = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };\n        return XmlReader.Create(s, cfg);\n    }\n}\n"""),
("""using System.Xml;\n\nclass Import@SC@ {\n    XmlDocument Carregar(string xml) {\n        var d = new XmlDocument { XmlResolver = new XmlUrlResolver() };\n        d.LoadXml(xml);\n        return d;\n    }\n}\n""",
 """using System.Xml;\n\nclass Import@SC@ {\n    XmlDocument Carregar(string xml) {\n        var d = new XmlDocument { XmlResolver = null };\n        d.LoadXml(xml);\n        return d;\n    }\n}\n"""))
t("csharp","918","httpclient-user-url",r"""\.(GetAsync|GetStringAsync|GetStreamAsync|PostAsync)\(\s*(url|Request\.Query\[[^\]]+\])""",
"O serviço de @T@ faz HttpClient.Get na URL recebida do cliente, permitindo SSRF (CWE-918). A correção usa base fixa e escapa só o identificador.",
("""using System.Net.Http;\nusing System.Threading.Tasks;\n\npublic class Proxy@SC@ {\n    private readonly HttpClient _http = new();\n    public Task<string> Buscar(string url) => _http.GetStringAsync(url);\n}\n""",
 """using System;\nusing System.Net.Http;\nusing System.Threading.Tasks;\n\npublic class Proxy@SC@ {\n    private static readonly Uri Base = new("https://api.exemplo.com.br/@T@/");\n    private readonly HttpClient _http = new();\n    public Task<string> Buscar(string id) => _http.GetStringAsync(new Uri(Base, Uri.EscapeDataString(id)));\n}\n"""),
("""using Microsoft.AspNetCore.Mvc;\nusing System.Net.Http;\n\npublic class Img@SC@Controller : Controller {\n    public async Task<IActionResult> Get([FromServices] HttpClient h) =>\n        File(await h.GetStreamAsync(Request.Query["src"]), "image/png");\n}\n""",
 """using Microsoft.AspNetCore.Mvc;\nusing System;\nusing System.Net.Http;\n\npublic class Img@SC@Controller : Controller {\n    public async Task<IActionResult> Get([FromServices] HttpClient h, string nome) {\n        if (!System.Text.RegularExpressions.Regex.IsMatch(nome ?? "", "^[a-z0-9-]{1,40}$")) return BadRequest();\n        return File(await h.GetStreamAsync(new Uri($"https://cdn.exemplo.com.br/@T@/{nome}.png")), "image/png");\n    }\n}\n"""))
t("csharp","601","mvc-redirect-return",r"""(?<!Local)Redirect\(\s*\w*[rR]eturn\w*\s*\)""",
"Após autenticar em @T@, o controller redireciona para o returnUrl informado sem checagem, permitindo open redirect (CWE-601). A correção usa Url.IsLocalUrl/LocalRedirect.",
("""using Microsoft.AspNetCore.Mvc;\n\npublic class Conta@SC@Controller : Controller {\n    public IActionResult Entrar(string returnUrl) {\n        Autenticar();\n        return Redirect(returnUrl);\n    }\n}\n""",
 """using Microsoft.AspNetCore.Mvc;\n\npublic class Conta@SC@Controller : Controller {\n    public IActionResult Entrar(string returnUrl) {\n        Autenticar();\n        return Url.IsLocalUrl(returnUrl) ? LocalRedirect(returnUrl) : RedirectToAction("Index", "@SC@");\n    }\n}\n"""))
t("csharp","338","system-random-token",r"""new\s+Random\(""",
"System.Random gera o código/chave de @S@ de forma previsível (CWE-338). A correção usa RandomNumberGenerator, criptograficamente seguro.",
("""using System;\n\npublic static class Otp@SC@ {\n    public static string Novo() => new Random().Next(0, 1000000).ToString("D6");\n}\n""",
 """using System.Security.Cryptography;\n\npublic static class Otp@SC@ {\n    public static string Novo() => RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");\n}\n"""),
("""using System;\n\nclass Chave@SC@ {\n    static readonly Random R = new Random();\n    public static byte[] Gerar() { var b = new byte[32]; R.NextBytes(b); return b; }\n}\n""",
 """using System.Security.Cryptography;\n\nclass Chave@SC@ {\n    public static byte[] Gerar() => RandomNumberGenerator.GetBytes(32);\n}\n"""))
t("csharp","798","connstring-password",r"""(?i)"[^"]*(Password|Pwd)\s*=\s*[^;"{]+""",
"A connection string do banco de @T@ contém senha literal no código (CWE-798). A correção lê a string da configuração/segredos (IConfiguration, user-secrets, Key Vault ou variável de ambiente).",
("""using Microsoft.Data.SqlClient;\n\npublic class Db@SC@ {\n    public SqlConnection Abrir() =>\n        new SqlConnection("Server=sql01;Database=@T@;User Id=app;Password=@S@#2024;");\n}\n""",
 """using Microsoft.Data.SqlClient;\nusing Microsoft.Extensions.Configuration;\n\npublic class Db@SC@ {\n    private readonly IConfiguration _cfg;\n    public Db@SC@(IConfiguration cfg) => _cfg = cfg;\n    public SqlConnection Abrir() => new SqlConnection(_cfg.GetConnectionString("@SC@"));\n}\n"""),
("""using Npgsql;\n\nclass Repo@SC@ {\n    const string Cs = "Host=pg;Username=@T@;Pwd=@C@_123;Database=@T@";\n    NpgsqlConnection Conn() => new NpgsqlConnection(Cs);\n}\n""",
 """using System;\nusing Npgsql;\n\nclass Repo@SC@ {\n    NpgsqlConnection Conn() => new NpgsqlConnection(Environment.GetEnvironmentVariable("@CU@_PG_CONN"));\n}\n"""))
t("csharp","327","weak-symmetric",r"""\b(DES|TripleDES|RC2)\.Create\(|CipherMode\.ECB|new\s+(DES|TripleDES|RC2)CryptoServiceProvider""",
"Os dados de @S@ são cifrados com DES/3DES/RC2 ou modo ECB, considerados inseguros (CWE-327). A correção usa AesGcm com nonce aleatório.",
("""using System.Security.Cryptography;\n\npublic static class Cifra@SC@ {\n    public static byte[] Cifrar(byte[] k, byte[] d) {\n        using var des = TripleDES.Create();\n        des.Key = k;\n        return des.CreateEncryptor().TransformFinalBlock(d, 0, d.Length);\n    }\n}\n""",
 """using System.Security.Cryptography;\n\npublic static class Cifra@SC@ {\n    public static byte[] Cifrar(byte[] k, byte[] d) {\n        var nonce = RandomNumberGenerator.GetBytes(12);\n        var ct = new byte[d.Length]; var tag = new byte[16];\n        using var g = new AesGcm(k, 16);\n        g.Encrypt(nonce, d, ct, tag);\n        return [.. nonce, .. tag, .. ct];\n    }\n}\n"""),
("""using System.Security.Cryptography;\n\nclass Token@SC@ {\n    byte[] Proteger(Aes aes, byte[] d) {\n        aes.Mode = CipherMode.ECB;\n        return aes.CreateEncryptor().TransformFinalBlock(d, 0, d.Length);\n    }\n}\n""",
 """using System.Security.Cryptography;\n\nclass Token@SC@ {\n    byte[] Proteger(byte[] chave, byte[] d) {\n        var nonce = RandomNumberGenerator.GetBytes(12);\n        var ct = new byte[d.Length]; var tag = new byte[16];\n        using var g = new AesGcm(chave, 16);\n        g.Encrypt(nonce, d, ct, tag);\n        return [.. nonce, .. tag, .. ct];\n    }\n}\n"""))
# ===== C
t("c","120","sprintf-unbounded",r"""(?<![\w])v?sprintf\s*\(""",
"sprintf escreve o texto de @S@ em buffer fixo sem limite; entrada longa estoura o buffer (CWE-120). A correção usa snprintf/vsnprintf com o tamanho e verifica truncamento.",
("""#include <stdio.h>\n\nvoid montar_@C@(char out[64], const char *@C@, int id) {\n    sprintf(out, "@T@/%d/%s.json", id, @C@);\n}\n""",
 """#include <stdio.h>\n\nint montar_@C@(char out[64], const char *@C@, int id) {\n    int n = snprintf(out, 64, "@T@/%d/%s.json", id, @C@);\n    return (n < 0 || n >= 64) ? -1 : 0;\n}\n"""),
("""#include <stdio.h>\n#include <stdarg.h>\n\nvoid msg_@S@(char *buf, const char *fmt, ...) {\n    va_list ap; va_start(ap, fmt);\n    vsprintf(buf, fmt, ap);\n    va_end(ap);\n}\n""",
 """#include <stdio.h>\n#include <stdarg.h>\n\nvoid msg_@S@(char *buf, size_t n, const char *fmt, ...) {\n    va_list ap; va_start(ap, fmt);\n    vsnprintf(buf, n, fmt, ap);\n    va_end(ap);\n}\n"""))
t("c","120","scanf-unbounded-s",r"""scanf\s*\(\s*[^;]*"[^"]*%s""",
"scanf com %s sem largura lê o @C@ sem limite para buffer fixo, permitindo estouro (CWE-120). A correção especifica largura máxima (ex.: %31s) e checa o retorno.",
("""#include <stdio.h>\n\nint ler_@S@(void) {\n    char @C@[32];\n    scanf("%s", @C@);\n    return printf("@S@: %s\\n", @C@);\n}\n""",
 """#include <stdio.h>\n\nint ler_@S@(void) {\n    char @C@[32];\n    if (scanf("%31s", @C@) != 1) return -1;\n    return printf("@S@: %s\\n", @C@);\n}\n"""),
("""#include <stdio.h>\n\nint parse_@S@(const char *linha, int *id, char nome[16]) {\n    return sscanf(linha, "%d;%s", id, nome);\n}\n""",
 """#include <stdio.h>\n\nint parse_@S@(const char *linha, int *id, char nome[16]) {\n    return sscanf(linha, "%d;%15s", id, nome);\n}\n"""))
t("c","367","access-then-open",r"""\baccess\s*\(""",
"O programa verifica o arquivo de @S@ com access() e depois o abre; entre as duas chamadas o arquivo pode ser trocado por um symlink (TOCTOU, CWE-367). A correção abre direto com O_NOFOLLOW e valida via fstat no descritor.",
("""#include <fcntl.h>\n#include <unistd.h>\n\nint abrir_@S@(const char *caminho) {\n    if (access(caminho, W_OK) != 0) return -1;\n    return open(caminho, O_WRONLY | O_APPEND);\n}\n""",
 """#include <fcntl.h>\n#include <sys/stat.h>\n#include <unistd.h>\n\nint abrir_@S@(const char *caminho) {\n    int fd = open(caminho, O_WRONLY | O_APPEND | O_NOFOLLOW);\n    struct stat st;\n    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { if (fd >= 0) close(fd); return -1; }\n    return fd;\n}\n"""))
t("c","377","insecure-tempname",r"""\b(tmpnam|tempnam|mktemp)\s*\(""",
"O arquivo temporário de @T@ usa tmpnam/mktemp, cujo nome previsível permite corrida e ataque de symlink (CWE-377). A correção usa mkstemp, que cria o arquivo de forma atômica.",
("""#include <stdio.h>\n\nFILE *tmp_@S@(void) {\n    char nome[L_tmpnam];\n    tmpnam(nome);\n    return fopen(nome, "w+");\n}\n""",
 """#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n\nFILE *tmp_@S@(void) {\n    char nome[] = "/tmp/@S@XXXXXX";\n    int fd = mkstemp(nome);\n    if (fd < 0) return NULL;\n    unlink(nome);\n    return fdopen(fd, "w+");\n}\n"""),
("""#include <stdlib.h>\n#include <fcntl.h>\n\nint spool_@T@(void) {\n    char modelo[] = "/tmp/@T@.XXXXXX";\n    mktemp(modelo);\n    return open(modelo, O_CREAT | O_WRONLY, 0600);\n}\n""",
 """#include <stdlib.h>\n\nint spool_@T@(void) {\n    char modelo[] = "/tmp/@T@.XXXXXX";\n    return mkstemp(modelo);\n}\n"""))
t("c","338","libc-rand-key",r"""\b(rand|random|drand48)\s*\(\s*\)""",
"A chave/identificador de sessão de @S@ é gerado com rand()/random(), PRNG previsível semeado com pouca entropia (CWE-338). A correção usa getrandom() do kernel.",
("""#include <stdlib.h>\n#include <time.h>\n\nvoid chave_@S@(unsigned char k[16]) {\n    srand((unsigned) time(NULL));\n    for (int i = 0; i < 16; i++) k[i] = (unsigned char) rand();\n}\n""",
 """#include <sys/random.h>\n\nint chave_@S@(unsigned char k[16]) {\n    return getrandom(k, 16, 0) == 16 ? 0 : -1;\n}\n"""),
("""#include <stdlib.h>\n\nlong sessao_@S@(void) {\n    return random();\n}\n""",
 """#include <sys/random.h>\n\nlong sessao_@S@(void) {\n    long v = 0;\n    if (getrandom(&v, sizeof v, 0) != sizeof v) return -1;\n    return v & 0x7fffffffL;\n}\n"""))
t("c","787","memcpy-len-from-input",r"""memcpy\(\s*\w+(->\w+)?\s*,\s*[^,]+,\s*\w+(->|\.)(len|tamanho|size)\s*\)""",
"O tamanho copiado para o buffer de @S@ vem do próprio pacote (campo len) sem validação contra o destino, permitindo escrita fora dos limites (CWE-787). A correção valida o tamanho antes do memcpy.",
("""#include <string.h>\n#include <stdint.h>\n\nstruct msg_@S@ { uint16_t len; uint8_t dados[512]; };\n\nvoid copiar_@S@(uint8_t dst[64], const struct msg_@S@ *m) {\n    memcpy(dst, m->dados, m->len);\n}\n""",
 """#include <string.h>\n#include <stdint.h>\n\nstruct msg_@S@ { uint16_t len; uint8_t dados[512]; };\n\nint copiar_@S@(uint8_t dst[64], const struct msg_@S@ *m) {\n    size_t n = m->len;\n    if (n > 64 || n > sizeof m->dados) return -1;\n    memcpy(dst, m->dados, n);\n    return 0;\n}\n"""))
t("c","732","world-writable-mode",r"""\b(chmod|open|creat|mkdir)\s*\([^;]*\b0?(777|666)\s*\)""",
"O arquivo/diretório de @T@ é criado com permissão 0666/0777, gravável por qualquer usuário local (CWE-732). A correção usa modo restrito (0640/0750).",
("""#include <fcntl.h>\n\nint criar_log_@S@(void) {\n    return open("/var/log/@T@.log", O_CREAT | O_WRONLY | O_APPEND, 0666);\n}\n""",
 """#include <fcntl.h>\n\nint criar_log_@S@(void) {\n    return open("/var/log/@T@.log", O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0640);\n}\n"""),
("""#include <sys/stat.h>\n\nint preparar_@T@(void) {\n    return mkdir("/srv/@T@/spool", 0777);\n}\n""",
 """#include <sys/stat.h>\n\nint preparar_@T@(void) {\n    return mkdir("/srv/@T@/spool", 0750);\n}\n"""))
# ===== CPP
t("cpp","120","memcpy-string-size",r"""(std::)?memcpy\([^;]*\.(size|length)\(\)\s*\)""",
"Copia-se o conteúdo de @C@ para um array fixo usando o tamanho da string de origem, sem limitar ao destino, causando estouro (CWE-120). A correção limita com std::min e termina a string.",
("""#include <cstring>\n#include <string>\n\nstruct Registro@SC@ { char @C@[24]; };\n\nvoid preencher(Registro@SC@ &r, const std::string &v) {\n    std::memcpy(r.@C@, v.data(), v.size());\n}\n""",
 """#include <algorithm>\n#include <cstring>\n#include <string>\n\nstruct Registro@SC@ { char @C@[24]; };\n\nvoid preencher(Registro@SC@ &r, const std::string &v) {\n    const auto n = std::min(v.size(), sizeof(r.@C@) - 1);\n    std::memcpy(r.@C@, v.data(), n);\n    r.@C@[n] = '\\0';\n}\n"""))
t("cpp","416","dangling-cstr",r"""const\s+char\s*\*\s*\w+\s*=\s*[\w:]+\([^;]*\)\.c_str\(\)\s*;|const\s+char\s*\*\s*\w+\s*=\s*\(\s*[\w:]+\([^;]*\)\s*\+[^;]*\)\.c_str\(\)""",
"O ponteiro obtido com c_str() de uma std::string temporária fica pendente assim que a expressão termina; usá-lo depois é use-after-free (CWE-416). A correção mantém a std::string viva numa variável.",
("""#include <cstdio>\n#include <string>\n\nstd::string nome_@S@(int id);\n\nvoid imprimir_@S@(int id) {\n    const char *n = nome_@S@(id).c_str();\n    std::puts(n);\n}\n""",
 """#include <cstdio>\n#include <string>\n\nstd::string nome_@S@(int id);\n\nvoid imprimir_@S@(int id) {\n    const std::string n = nome_@S@(id);\n    std::puts(n.c_str());\n}\n"""),
("""#include <string>\n\nconst char *rota_@S@(const std::string &@C@) {\n    const char *r = (std::string("/@T@/") + @C@).c_str();\n    return r;\n}\n""",
 """#include <string>\n\nstd::string rota_@S@(const std::string &@C@) {\n    return std::string("/@T@/") + @C@;\n}\n"""))
t("cpp","190","new-array-mul",r"""new\s+[\w:]+(\s+[\w:]+)?\[\s*\w+\s*\*\s*\w+\s*\]""",
"O buffer de @T@ é alocado com new[] usando produto de dimensões externas sem checar overflow; o valor pode estourar e alocar menos que o necessário (CWE-190). A correção valida a multiplicação e usa std::vector.",
("""#include <cstddef>\n\nunsigned char *matriz_@S@(std::size_t linhas, std::size_t colunas) {\n    return new unsigned char[linhas * colunas];\n}\n""",
 """#include <cstddef>\n#include <limits>\n#include <stdexcept>\n#include <vector>\n\nstd::vector<unsigned char> matriz_@S@(std::size_t linhas, std::size_t colunas) {\n    if (colunas && linhas > std::numeric_limits<std::size_t>::max() / colunas) throw std::length_error("overflow");\n    return std::vector<unsigned char>(linhas * colunas);\n}\n"""))
t("cpp","22","ofstream-concat-path",r"""std::ofstream\s+\w+\s*\(\s*\w+\s*\+|fs::remove(_all)?\(\s*\w+\s*/\s*\w+\s*\)""",
"O caminho de escrita/remoção de @S@ é composto com nome externo sem normalizar, permitindo ../ fora do diretório (CWE-22). A correção normaliza e verifica que o alvo permanece sob a base.",
("""#include <fstream>\n#include <string>\n\nvoid salvar_@S@(const std::string &nome, const std::string &conteudo) {\n    const std::string dir = "/srv/@T@/";\n    std::ofstream out(dir + nome);\n    out << conteudo;\n}\n""",
 """#include <filesystem>\n#include <fstream>\n#include <stdexcept>\n#include <string>\nnamespace fs = std::filesystem;\n\nvoid salvar_@S@(const std::string &nome, const std::string &conteudo) {\n    const fs::path base = "/srv/@T@";\n    const fs::path alvo = base / fs::path(nome).filename();\n    if (alvo.filename().empty() || alvo.filename() == "..") throw std::invalid_argument("nome");\n    std::ofstream out(alvo);\n    out << conteudo;\n}\n"""),
("""#include <filesystem>\n#include <string>\nnamespace fs = std::filesystem;\n\nvoid limpar_@S@(const std::string &sub) {\n    const fs::path base = "/var/cache/@T@";\n    fs::remove_all(base / sub);\n}\n""",
 """#include <filesystem>\n#include <stdexcept>\n#include <string>\nnamespace fs = std::filesystem;\n\nvoid limpar_@S@(const std::string &sub) {\n    const fs::path base = fs::canonical("/var/cache/@T@");\n    const fs::path alvo = fs::weakly_canonical(base / sub);\n    if (alvo == base || alvo.string().rfind(base.string() + "/", 0) != 0) throw std::runtime_error("fora da base");\n    fs::remove_all(alvo);\n}\n"""))
t("cpp","327","openssl-weak-algo",r"""EVP_(des_\w+|aes_\d+_ecb|rc4|md5|sha1)\s*\(\s*\)|\bMD5\s*\(""",
"O código de @T@ usa primitiva fraca da OpenSSL (DES/RC4/AES-ECB/MD5/SHA-1) para proteger dados (CWE-327). A correção usa AES-256-GCM ou SHA-256.",
("""#include <openssl/evp.h>\n\nbool iniciar_@S@(EVP_CIPHER_CTX *c, const unsigned char *k) {\n    return EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), nullptr, k, nullptr) == 1;\n}\n""",
 """#include <openssl/evp.h>\n\nbool iniciar_@S@(EVP_CIPHER_CTX *c, const unsigned char *k, const unsigned char iv[12]) {\n    return EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, k, iv) == 1;\n}\n"""),
("""#include <openssl/evp.h>\n#include <string>\n\nbool digest_@S@(const std::string &d, unsigned char *out, unsigned int *n) {\n    return EVP_Digest(d.data(), d.size(), out, n, EVP_md5(), nullptr) == 1;\n}\n""",
 """#include <openssl/evp.h>\n#include <string>\n\nbool digest_@S@(const std::string &d, unsigned char *out, unsigned int *n) {\n    return EVP_Digest(d.data(), d.size(), out, n, EVP_sha256(), nullptr) == 1;\n}\n"""))
t("cpp","134","fmt-cstr-sink",r"""(snprintf\(\s*\w+\s*,\s*[^,]+,\s*|syslog\(\s*\w+\s*,\s*)\w+\.c_str\(\)\s*\)""",
"A mensagem de @S@ (std::string externa) é usada como string de formato em snprintf/syslog, permitindo %n/%x (CWE-134). A correção passa o texto como argumento de \"%s\".",
("""#include <syslog.h>\n#include <string>\n\nvoid auditar_@S@(const std::string &evento) {\n    syslog(LOG_NOTICE, evento.c_str());\n}\n""",
 """#include <syslog.h>\n#include <string>\n\nvoid auditar_@S@(const std::string &evento) {\n    syslog(LOG_NOTICE, "%s", evento.c_str());\n}\n"""),
("""#include <cstdio>\n#include <string>\n\nvoid titulo_@S@(char *buf, std::size_t n, const std::string &t) {\n    std::snprintf(buf, n, t.c_str());\n}\n""",
 """#include <cstdio>\n#include <string>\n\nvoid titulo_@S@(char *buf, std::size_t n, const std::string &t) {\n    std::snprintf(buf, n, "%s", t.c_str());\n}\n"""))
t("cpp","798","hardcoded-key-literal",r"""(?i)(std::string|char\s*\*|char|auto)\s+\w*(key|chave|senha|password|token|secret)\w*(\[\])?\s*=\s*"[^"]{6,}\"""",
"Uma chave/senha do serviço de @T@ está embutida no binário como literal, recuperável com strings/engenharia reversa (CWE-798). A correção lê o segredo do ambiente/cofre em tempo de execução.",
("""#include <string>\n\nstatic const std::string api_key_@S@ = "k3y-@C@-7f9a2b";\n\nstd::string header_@S@() { return "Authorization: Bearer " + api_key_@S@; }\n""",
 """#include <cstdlib>\n#include <stdexcept>\n#include <string>\n\nstd::string header_@S@() {\n    const char *k = std::getenv("@CU@_API_KEY");\n    if (!k) throw std::runtime_error("@CU@_API_KEY ausente");\n    return std::string("Authorization: Bearer ") + k;\n}\n"""),
("""#include <cstring>\n\nbool admin_@S@(const char *entrada) {\n    const char senha_admin[] = "Adm!n@T@2024";\n    return std::strcmp(entrada, senha_admin) == 0;\n}\n""",
 """#include <string>\n\nbool verificar_hash(const std::string &entrada, const std::string &hash_armazenado);\nstd::string carregar_hash_admin_@S@();\n\nbool admin_@S@(const char *entrada) {\n    return verificar_hash(entrada, carregar_hash_admin_@S@());\n}\n"""))
# ===== SQL
t("sql","89","oracle-execute-immediate",r"""(?i)EXECUTE\s+IMMEDIATE\s+'(?:[^']|'')*'\s*\|\|""",
"O bloco PL/SQL de @T@ concatena o parâmetro ao EXECUTE IMMEDIATE, permitindo injeção de SQL (CWE-89). A correção usa bind variable com USING.",
("""CREATE OR REPLACE PROCEDURE cancelar_@S@(p_@C@ IN VARCHAR2) AS\nBEGIN\n  EXECUTE IMMEDIATE 'UPDATE @T@ SET status = ''C'' WHERE @C@ = ''' || p_@C@ || '''';\nEND;\n/\n""",
 """CREATE OR REPLACE PROCEDURE cancelar_@S@(p_@C@ IN VARCHAR2) AS\nBEGIN\n  EXECUTE IMMEDIATE 'UPDATE @T@ SET status = ''C'' WHERE @C@ = :1' USING p_@C@;\nEND;\n/\n"""),
("""CREATE OR REPLACE FUNCTION total_@T@(p_filtro VARCHAR2) RETURN NUMBER AS\n  n NUMBER;\nBEGIN\n  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM @T@ WHERE ' || p_filtro INTO n;\n  RETURN n;\nEND;\n/\n""",
 """CREATE OR REPLACE FUNCTION total_@T@(p_@C@ VARCHAR2) RETURN NUMBER AS\n  n NUMBER;\nBEGIN\n  EXECUTE IMMEDIATE 'SELECT COUNT(*) FROM @T@ WHERE @C@ = :v' INTO n USING p_@C@;\n  RETURN n;\nEND;\n/\n"""),rl="generic")
t("sql","89","tsql-sql-var-concat",r"""(?i)SET\s+@\w+\s*=\s*N?'(?:[^']|'')*'\s*\+\s*@\w+""",
"A procedure de @T@ monta @sql concatenando o parâmetro e o executa, mesmo via sp_executesql, permitindo injeção (CWE-89). A correção mantém o SQL constante e passa o valor como parâmetro.",
("""CREATE PROCEDURE dbo.Filtrar@SC@ @@C@ NVARCHAR(60)\nAS\nBEGIN\n    DECLARE @sql NVARCHAR(MAX);\n    SET @sql = N'SELECT * FROM dbo.@T@ WHERE @C@ LIKE ''%' + @@C@ + N'%''';\n    EXEC sp_executesql @sql;\nEND;\n""",
 """CREATE PROCEDURE dbo.Filtrar@SC@ @@C@ NVARCHAR(60)\nAS\nBEGIN\n    DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM dbo.@T@ WHERE @C@ LIKE ''%'' + @v + ''%''';\n    EXEC sp_executesql @sql, N'@v NVARCHAR(60)', @v = @@C@;\nEND;\n"""),rl="generic")
t("sql","426","security-definer-no-path",r"""(?is)SECURITY\s+DEFINER(?![\s\S]*SET\s+search_path)""",
"A função de @T@ roda como SECURITY DEFINER sem fixar search_path; um usuário pode criar objetos em schema próprio e sequestrar chamadas com o privilégio do dono (CWE-426). A correção fixa search_path seguro e qualifica os objetos.",
("""CREATE FUNCTION arquivar_@S@(p_id int) RETURNS void\nLANGUAGE sql SECURITY DEFINER AS $$\n  UPDATE @T@ SET arquivado = true WHERE id = p_id;\n$$;\n""",
 """CREATE FUNCTION arquivar_@S@(p_id int) RETURNS void\nLANGUAGE sql SECURITY DEFINER\nSET search_path = pg_catalog, public AS $$\n  UPDATE public.@T@ SET arquivado = true WHERE id = p_id;\n$$;\nREVOKE ALL ON FUNCTION arquivar_@S@(int) FROM PUBLIC;\n"""),rl="generic")
t("sql","256","plaintext-password-column",r"""(?i)\b(senha|password|pwd|passwd)\w*\s+(VARCHAR|NVARCHAR|TEXT|CHAR|VARCHAR2)\b""",
"A tabela de @T@ guarda a senha em coluna de texto, induzindo armazenamento em claro (CWE-256). A correção armazena apenas hash forte (argon2/bcrypt) em coluna binária.",
("""CREATE TABLE @T@_acesso (\n  id SERIAL PRIMARY KEY,\n  login VARCHAR(80) UNIQUE NOT NULL,\n  senha VARCHAR(60) NOT NULL\n);\n""",
 """CREATE TABLE @T@_acesso (\n  id SERIAL PRIMARY KEY,\n  login VARCHAR(80) UNIQUE NOT NULL,\n  hash_argon2 BYTEA NOT NULL -- gerado pela aplicacao (argon2id)\n);\n"""),
("""ALTER TABLE @T@ ADD COLUMN password_portal TEXT;\n""",
 """ALTER TABLE @T@ ADD COLUMN hash_portal BYTEA;\nCOMMENT ON COLUMN @T@.hash_portal IS 'hash argon2id; nunca gravar o segredo em claro';\n"""),rl="generic")
t("sql","78","xp-cmdshell",r"""(?i)'xp_cmdshell'\s*,\s*1|EXEC(UTE)?\s+(master\.\.|master\.dbo\.)?xp_cmdshell""",
"A rotina de @T@ habilita/usa xp_cmdshell, executando comandos do sistema operacional a partir do SQL e ampliando muito o impacto de qualquer injeção (CWE-78). A correção mantém xp_cmdshell desabilitado e usa recursos nativos ou job externo.",
("""EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'bcp loja.dbo.@T@ out C:\\export\\@T@.csv -c -T';\n""",
 """EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;\n-- exportacao de @T@ feita por job externo (bcp agendado fora do SQL Server)\n"""),
("""CREATE PROCEDURE dbo.Backup@SC@ @pasta NVARCHAR(200)\nAS\n    DECLARE @c NVARCHAR(400) = N'robocopy D:\\@T@ ' + @pasta;\n    EXEC master..xp_cmdshell @c;\n""",
 """CREATE PROCEDURE dbo.Backup@SC@\nAS\n    BACKUP DATABASE loja TO DISK = N'D:\\backup\\@T@.bak' WITH COPY_ONLY, CHECKSUM;\n"""),rl="generic")
t("sql","89","pg-format-unsafe-s",r"""(?i)format\(\s*'(?:[^']|'')*%s""",
"A função usa format() com %s para inserir valor/identificador de @T@ no SQL dinâmico, sem quoting, permitindo injeção (CWE-89). A correção usa %L para valores e %I para identificadores.",
("""CREATE OR REPLACE FUNCTION por_@C@_@S@(p_v text) RETURNS SETOF @T@ AS $$\nBEGIN\n  RETURN QUERY EXECUTE format('SELECT * FROM @T@ WHERE @C@ = ''%s''', p_v);\nEND;\n$$ LANGUAGE plpgsql;\n""",
 """CREATE OR REPLACE FUNCTION por_@C@_@S@(p_v text) RETURNS SETOF @T@ AS $$\nBEGIN\n  RETURN QUERY EXECUTE format('SELECT * FROM @T@ WHERE @C@ = %L', p_v);\nEND;\n$$ LANGUAGE plpgsql;\n"""),
("""CREATE OR REPLACE FUNCTION ordenar_@T@(p_col text) RETURNS SETOF @T@ AS $$\nBEGIN\n  RETURN QUERY EXECUTE format('SELECT * FROM @T@ ORDER BY %s', p_col);\nEND;\n$$ LANGUAGE plpgsql;\n""",
 """CREATE OR REPLACE FUNCTION ordenar_@T@(p_col text) RETURNS SETOF @T@ AS $$\nBEGIN\n  IF p_col NOT IN ('id', '@C@') THEN p_col := 'id'; END IF;\n  RETURN QUERY EXECUTE format('SELECT * FROM @T@ ORDER BY %I', p_col);\nEND;\n$$ LANGUAGE plpgsql;\n"""),rl="generic")
t("sql","798","link-mapping-password",r"""(?i)CONNECT\s+TO\s+\w+\s+IDENTIFIED\s+BY|OPTIONS\s*\([^)]*\bpassword\s+'""",
"O database link / user mapping usado por @T@ grava a senha remota em claro no DDL versionado (CWE-798). A correção usa autenticação por certificado/usuário corrente sem senha literal.",
("""CREATE DATABASE LINK lnk_@T@\n  CONNECT TO rel_@T@ IDENTIFIED BY "@S@Senha24"\n  USING 'DWPROD';\n""",
 """CREATE DATABASE LINK lnk_@T@\n  CONNECT TO CURRENT_USER\n  USING 'DWPROD';\n"""),
("""CREATE USER MAPPING FOR app_@T@ SERVER dw_remoto\n  OPTIONS (user 'leitor_@T@', password 'L3itor@C@!');\n""",
 """CREATE USER MAPPING FOR app_@T@ SERVER dw_remoto\n  OPTIONS (user 'leitor_@T@', sslcert '/etc/pg/@T@.crt', sslkey '/etc/pg/@T@.key');\n"""),rl="generic")
# ===== BASH
t("bash","88","unquoted-rm-var",r"""\brm\s+-\w*\s+\$\{?\w+\}?(/|\s|$)""",
"A variável usada no rm de @T@ não está entre aspas nem validada; vazia ou com espaços/glob ela apaga caminhos errados ou injeta opções (CWE-88). A correção usa aspas, ${VAR:?} e -- antes do caminho.",
("""#!/bin/bash\nDESTINO=$1\nrm -rf $DESTINO/@T@_cache\n""",
 """#!/bin/bash\nDESTINO=$1\nrm -rf -- "${DESTINO:?destino obrigatorio}/@T@_cache"\n"""),
("""#!/bin/sh\nfor arq in $(ls /srv/@T@/tmp); do\n  rm -f $arq\ndone\n""",
 """#!/bin/sh\nfind /srv/@T@/tmp -maxdepth 1 -type f -exec rm -f -- {} +\n"""))
t("bash","295","tls-insecure-flag",r"""\bcurl\b[^\n]*(\s-k\b|\s--insecure\b)|--no-check-certificate""",
"O download/chamada de @T@ desliga a verificação TLS (-k / --no-check-certificate), permitindo MITM (CWE-295). A correção remove a flag e, se necessário, aponta o CA correto.",
("""#!/bin/bash\ncurl -k -sS -o @T@.json "https://api.interna.exemplo/@T@"\n""",
 """#!/bin/bash\ncurl --cacert /etc/ssl/certs/interna-ca.pem -sS -o @T@.json "https://api.interna.exemplo/@T@"\n"""),
("""#!/bin/sh\nwget --no-check-certificate -q https://repo.exemplo.dev/@S@.tar.gz\n""",
 """#!/bin/sh\nwget -q https://repo.exemplo.dev/@S@.tar.gz\n"""))
t("bash","214","password-on-cmdline",r"""\b(mysql|mysqldump|mysqladmin)\b[^\n]*\s-p\S+|sshpass\s+-p\s*\S+""",
"A senha do banco/host de @T@ é passada na linha de comando, visível em ps e no histórico (CWE-214). A correção usa arquivo de opções com permissão restrita ou chave SSH.",
("""#!/bin/bash\nmysqldump -u backup -pB4ckup@C@ @T@ | gzip > @T@.sql.gz\n""",
 """#!/bin/bash\n# /etc/@T@/backup.cnf (chmod 600) contem [client] user/password\nmysqldump --defaults-extra-file=/etc/@T@/backup.cnf @T@ | gzip > @T@.sql.gz\n"""),
("""#!/bin/bash\nsshpass -p 'S3nha@S@' scp relatorio.csv deploy@srv-@T@:/dados/\n""",
 """#!/bin/bash\nscp -i ~/.ssh/deploy_@T@ -o IdentitiesOnly=yes relatorio.csv deploy@srv-@T@:/dados/\n"""))
t("bash","78","sh-c-interpolated",r"""\b(ba)?sh\s+-c\s+"[^"]*\$""",
"O valor de @C@ é interpolado dentro da string passada a sh -c, então metacaracteres viram comandos (CWE-78). A correção mantém o script de sh -c constante (aspas simples) e passa o valor como argumento posicional.",
("""#!/bin/bash\n@C@="$1"\nsudo -u @T@ sh -c "cd /srv/@T@ && ./processar.sh $@C@"\n""",
 """#!/bin/bash\n@C@="$1"\nsudo -u @T@ sh -c 'cd /srv/@T@ && ./processar.sh "$1"' _ "$@C@"\n"""),
("""#!/bin/bash\nfind /dados/@T@ -name '*.csv' -exec bash -c "gzip {} && echo $PREFIXO {}" \\;\n""",
 """#!/bin/bash\nfind /dados/@T@ -name '*.csv' -exec bash -c 'gzip -- "$1" && echo "$2" "$1"' _ {} "$PREFIXO" \\;\n"""))
t("bash","250","sudoers-nopasswd-all",r"""NOPASSWD:\s*ALL\b""",
"O script de provisionamento de @T@ concede sudo irrestrito sem senha ao usuário de serviço; comprometer o serviço vira root (CWE-250). A correção limita o sudo ao comando específico necessário.",
("""#!/bin/bash\necho "svc_@S@ ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/svc_@S@\n""",
 """#!/bin/bash\necho "svc_@S@ ALL=(root) NOPASSWD: /usr/bin/systemctl restart @S@.service" > /etc/sudoers.d/svc_@S@\nchmod 440 /etc/sudoers.d/svc_@S@\nvisudo -cf /etc/sudoers.d/svc_@S@\n"""))
t("bash","312","secret-echo-to-file",r"""echo\s+"?[\w=]*\$\{?\w*(TOKEN|SENHA|PASSWORD|SECRET|KEY)\w*\}?"?\s*>>?\s*\S+""",
"O segredo de @T@ é gravado com echo em arquivo criado com umask padrão (legível por outros) (CWE-312). A correção cria o arquivo com permissão 600 antes de escrever.",
("""#!/bin/bash\necho "$@CU@_TOKEN" > /etc/@T@/token\n""",
 """#!/bin/bash\n( umask 077 && printf '%s' "$@CU@_TOKEN" > /etc/@T@/token )\n"""),
("""#!/bin/sh\necho "DB_PASSWORD=$DB_PASSWORD" >> /opt/@T@/.env\n""",
 """#!/bin/sh\ninstall -m 600 /dev/null /opt/@T@/.env.new\nprintf 'DB_PASSWORD=%s\\n' "$DB_PASSWORD" > /opt/@T@/.env.new && mv /opt/@T@/.env.new /opt/@T@/.env\n"""))
t("bash","494","source-remote-script",r"""(source|\.)\s+<\(\s*(curl|wget)""",
"O script carrega funções/config de @T@ executando código remoto via source <(curl ...) sem verificação de integridade (CWE-494). A correção usa arquivo local verificado (hash ou origem confiável) antes de carregar.",
("""#!/bin/bash\nsource <(curl -fsSL https://raw.exemplo.dev/@T@/lib.sh)\ninit_@S@\n""",
 """#!/bin/bash\nset -euo pipefail\nlib=$(mktemp)\ncurl -fsSLo "$lib" https://raw.exemplo.dev/@T@/v1.4.2/lib.sh\necho "${@CU@_LIB_SHA256:?}  $lib" | sha256sum -c -\nsource "$lib"\ninit_@S@\n"""),
("""#!/bin/bash\n. <(wget -qO- http://config.exemplo.dev/@S@.env)\n""",
 """#!/bin/bash\nset -euo pipefail\ncfg=/etc/@S@/@S@.env   # distribuido via gerenciador de configuracao, dono root, 0640\n[ "$(stat -c %U "$cfg")" = root ] || exit 1\n. "$cfg"\n"""))
