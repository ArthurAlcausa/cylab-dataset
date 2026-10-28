import json, os
C="https://cwe.mitre.org/data/definitions/%s.html"
RULES={}
def R(lang,slug,cwe,msg,body,langs=None):
    rid=f"cylab.{lang}.{slug}"
    RULES[rid]=f"""rules:
  - id: {rid}
    message: "{msg} (CWE-{cwe})"
    severity: ERROR
    languages: [{langs or lang}]
    metadata:
      cwe: "CWE-{cwe}"
      source: sintetico-cylab
{body}"""
    return rid
P=[]
def add(lang,cwe,rid,before,after,exp,split="train"):
    P.append(dict(lang=lang,cwe=f"CWE-{cwe}",source=f"sintetico-cylab {C%cwe}",license="CC-BY-4.0",
      opengrep_rule=rid,before=before.strip()+"\n",after=after.strip()+"\n",explanation_pt=exp,split=split))

# ---------- PYTHON ----------
r=R("python","sql-injection",89,"SQL montado com formatacao de string","""    patterns:
      - pattern-either:
          - pattern: $C.execute(f"...", ...)
          - pattern: $C.execute("..." % $X, ...)
          - pattern: $C.execute("..." + $X, ...)
          - pattern: $C.execute("...".format(...), ...)
""")
add("python",89,r,'''
import sqlite3

def buscar_usuario(conn: sqlite3.Connection, email: str):
    cur = conn.cursor()
    cur.execute(f"SELECT id, nome FROM usuarios WHERE email = '{email}'")
    return cur.fetchone()
''','''
import sqlite3

def buscar_usuario(conn: sqlite3.Connection, email: str):
    cur = conn.cursor()
    cur.execute("SELECT id, nome FROM usuarios WHERE email = ?", (email,))
    return cur.fetchone()
''',"A consulta interpola o e-mail diretamente no SQL com f-string, permitindo injeção de SQL (CWE-89). A correção usa parâmetro vinculado (?), deixando o driver tratar o valor como dado.")
add("python",89,r,'''
def listar_pedidos(cursor, status):
    cursor.execute("SELECT * FROM pedidos WHERE status = '%s'" % status)
    return cursor.fetchall()
''','''
def listar_pedidos(cursor, status):
    cursor.execute("SELECT * FROM pedidos WHERE status = %s", (status,))
    return cursor.fetchall()
''',"Formatar a query com o operador % concatena entrada do usuário ao SQL (CWE-89). A versão corrigida passa o status como parâmetro separado para o cursor.","holdout")
r=R("python","command-injection",78,"Comando de shell com entrada externa","""    pattern-either:
      - pattern: subprocess.$F(..., shell=True, ...)
      - pattern: os.system(...)
""")
add("python",78,r,'''
import subprocess

def compactar(nome_arquivo: str) -> None:
    subprocess.run(f"tar czf backup.tgz {nome_arquivo}", shell=True, check=True)
''','''
import subprocess

def compactar(nome_arquivo: str) -> None:
    subprocess.run(["tar", "czf", "backup.tgz", "--", nome_arquivo], check=True)
''',"Usar shell=True com texto interpolado permite injeção de comandos do sistema operacional (CWE-78). A correção passa argumentos como lista, sem shell, e usa '--' para encerrar opções.")
add("python",78,r,'''
import os

def pingar(host):
    os.system("ping -c 1 " + host)
''','''
import subprocess

def pingar(host):
    subprocess.run(["ping", "-c", "1", "--", host], check=False)
''',"os.system executa a string via shell; um host como '8.8.8.8; rm -rf ~' injeta comandos (CWE-78). A versão segura chama o binário diretamente com lista de argumentos.")
r=R("python","path-traversal",22,"Caminho de arquivo construido com entrada externa sem validacao","""    patterns:
      - pattern-either:
          - pattern: open(os.path.join($BASE, request.$A.get(...)), ...)
          - pattern: send_file(os.path.join($BASE, $X), ...)
      - pattern-not-inside: |
          if not $P.startswith(...):
              ...
          ...
""")
add("python",22,r,'''
import os
from flask import Flask, send_file

app = Flask(__name__)
BASE = "/srv/relatorios"

@app.get("/relatorio/<nome>")
def relatorio(nome):
    return send_file(os.path.join(BASE, nome))
''','''
import os
from flask import Flask, abort, send_from_directory

app = Flask(__name__)
BASE = "/srv/relatorios"

@app.get("/relatorio/<nome>")
def relatorio(nome):
    return send_from_directory(BASE, nome)
''',"Unir o nome recebido ao diretório base permite '../' e leitura de arquivos fora da pasta (CWE-22). send_from_directory normaliza o caminho e rejeita saídas do diretório.")
r=R("python","hardcoded-secret",798,"Credencial embutida no codigo-fonte","""    patterns:
      - pattern-either:
          - pattern: $K = "..."
      - metavariable-regex:
          metavariable: $K
          regex: (?i).*(api_key|secret|password|senha|token).*
""")
add("python",798,r,'''
import requests

API_KEY = "sk_live_cylab_51HfakeExampleKey"

def cobrar(valor):
    return requests.post("https://pagamentos.exemplo.com/v1/cobrancas",
                         headers={"Authorization": f"Bearer {API_KEY}"},
                         json={"valor": valor}, timeout=10)
''','''
import os
import requests

def cobrar(valor):
    api_key = os.environ["PAGAMENTOS_API_KEY"]
    return requests.post("https://pagamentos.exemplo.com/v1/cobrancas",
                         headers={"Authorization": f"Bearer {api_key}"},
                         json={"valor": valor}, timeout=10)
''',"A chave de API está fixa no código e vaza em repositórios e artefatos (CWE-798). A correção lê o segredo de variável de ambiente fornecida pelo cofre de segredos.")
r=R("python","weak-hash",328,"Hash fraco (MD5/SHA1) para dado sensivel","""    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
""")
add("python",328,r,'''
import hashlib

def hash_senha(senha: str) -> str:
    return hashlib.md5(senha.encode()).hexdigest()
''','''
import hashlib
import os

def hash_senha(senha: str) -> str:
    sal = os.urandom(16)
    dk = hashlib.scrypt(senha.encode(), salt=sal, n=2**14, r=8, p=1)
    return sal.hex() + ":" + dk.hex()
''',"MD5 é rápido e quebrado, inadequado para armazenar senhas (CWE-328). A correção usa scrypt com sal aleatório, uma função de derivação lenta.")
r=R("python","insecure-deserialization",502,"Desserializacao insegura de dados nao confiaveis","""    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: yaml.load(...)
""")
add("python",502,r,'''
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.post("/preferencias")
def preferencias():
    prefs = pickle.loads(request.get_data())
    return {"tema": prefs.get("tema")}
''','''
import json
from flask import Flask, request

app = Flask(__name__)

@app.post("/preferencias")
def preferencias():
    prefs = json.loads(request.get_data())
    return {"tema": prefs.get("tema")}
''',"pickle.loads em corpo de requisição permite execução de código arbitrário (CWE-502). A correção usa JSON, que só produz tipos de dados simples.")
add("python",502,r,'''
import yaml

def carregar_config(caminho):
    with open(caminho) as f:
        return yaml.load(f, Loader=yaml.Loader)
''','''
import yaml

def carregar_config(caminho):
    with open(caminho) as f:
        return yaml.safe_load(f)
''',"yaml.load com Loader completo instancia objetos Python arbitrários (CWE-502). yaml.safe_load restringe a tipos básicos.")
r=R("python","ssrf",918,"Requisicao HTTP para URL controlada pelo usuario","""    pattern-either:
      - pattern: requests.$M(request.args.get(...), ...)
      - pattern: |
          $U = request.args.get(...)
          ...
          requests.$M($U, ...)
""")
add("python",918,r,'''
import requests
from flask import Flask, request

app = Flask(__name__)

@app.get("/preview")
def preview():
    url = request.args.get("url")
    r = requests.get(url, timeout=5)
    return r.text[:500]
''','''
import requests
from urllib.parse import urlparse
from flask import Flask, abort, request

app = Flask(__name__)
HOSTS_PERMITIDOS = {"cdn.exemplo.com", "img.exemplo.com"}

@app.get("/preview")
def preview():
    alvo = urlparse(request.args.get("url", ""))
    if alvo.scheme != "https" or alvo.hostname not in HOSTS_PERMITIDOS:
        abort(400)
    r = requests.get(alvo.geturl(), timeout=5, allow_redirects=False)
    return r.text[:500]
''',"O servidor busca qualquer URL enviada, permitindo acessar serviços internos como 169.254.169.254 (CWE-918). A correção valida esquema e host contra uma lista de permissões e desativa redirecionamentos.")

# ---------- JAVASCRIPT ----------
r=R("javascript","sql-injection",89,"SQL concatenado com entrada externa","""    pattern-either:
      - pattern: $DB.query(`...${$X}...`, ...)
      - pattern: $DB.query("..." + $X, ...)
      - pattern: $DB.query(`...${$X}...`)
      - pattern: $DB.query("..." + $X)
""")
add("javascript",89,r,'''
const express = require("express");
const { pool } = require("./db");
const app = express();

app.get("/produtos", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM produtos WHERE categoria = '${req.query.cat}'`);
  res.json(rows);
});
''','''
const express = require("express");
const { pool } = require("./db");
const app = express();

app.get("/produtos", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM produtos WHERE categoria = $1", [req.query.cat]);
  res.json(rows);
});
''',"O template literal injeta a categoria diretamente no SQL (CWE-89). A correção usa placeholder $1 com array de parâmetros do driver pg.")
r=R("javascript","xss-innerhtml",79,"Atribuicao de dado externo a innerHTML","""    patterns:
      - pattern: $EL.innerHTML = $X
      - pattern-not: $EL.innerHTML = "..."
""")
add("javascript",79,r,'''
function mostrarBoasVindas() {
  const nome = new URLSearchParams(location.search).get("nome");
  document.getElementById("saudacao").innerHTML = "Olá, " + nome;
}
''','''
function mostrarBoasVindas() {
  const nome = new URLSearchParams(location.search).get("nome");
  document.getElementById("saudacao").textContent = "Olá, " + nome;
}
''',"Inserir parâmetro da URL via innerHTML permite XSS refletido no DOM (CWE-79). textContent trata o valor como texto puro.")
add("javascript",79,r,'''
function renderComentario(lista, comentario) {
  const li = document.createElement("li");
  li.innerHTML = comentario.texto;
  lista.appendChild(li);
}
''','''
function renderComentario(lista, comentario) {
  const li = document.createElement("li");
  li.textContent = comentario.texto;
  lista.appendChild(li);
}
''',"Comentários armazenados renderizados com innerHTML geram XSS persistente (CWE-79). A correção usa textContent.","holdout")
r=R("javascript","command-injection",78,"child_process.exec com entrada externa","""    patterns:
      - pattern-either:
          - pattern: $CP.exec(`...${$X}...`, ...)
          - pattern: $CP.exec("..." + $X, ...)
          - pattern: exec(`...${$X}...`, ...)
          - pattern: exec("..." + $X, ...)
""")
add("javascript",78,r,'''
const { exec } = require("child_process");

function converter(arquivo, cb) {
  exec(`convert ${arquivo} saida.png`, cb);
}
''','''
const { execFile } = require("child_process");

function converter(arquivo, cb) {
  execFile("convert", ["--", arquivo, "saida.png"], cb);
}
''',"exec interpreta a string em shell, permitindo injeção via nome de arquivo (CWE-78). execFile executa o binário com argumentos separados, sem shell.")
r=R("javascript","path-traversal",22,"Caminho construido com parametro da requisicao","""    pattern-either:
      - pattern: $FS.readFile(path.join($B, req.$P.$N), ...)
      - pattern: res.sendFile(path.join(..., req.$P.$N, ...), ...)
      - pattern: res.sendFile(path.join(..., req.$P.$N, ...))
""")
add("javascript",22,r,'''
const express = require("express");
const path = require("path");
const app = express();

app.get("/anexo", (req, res) => {
  res.sendFile(path.join(__dirname, "anexos", req.query.nome));
});
''','''
const express = require("express");
const path = require("path");
const app = express();
const BASE = path.join(__dirname, "anexos");

app.get("/anexo", (req, res) => {
  const nome = path.basename(String(req.query.nome || ""));
  res.sendFile(nome, { root: BASE, dotfiles: "deny" });
});
''',"path.join aceita '../', permitindo ler arquivos fora da pasta de anexos (CWE-22). A correção usa basename e a opção root do sendFile, que bloqueia travessia.")
r=R("javascript","hardcoded-secret",798,"Segredo literal no codigo","""    patterns:
      - pattern-either:
          - pattern: const $K = "...";
          - pattern: jwt.sign($P, "...", ...)
      - metavariable-regex:
          metavariable: $K
          regex: (?i).*(secret|senha|password|token|key).*
""")
add("javascript",798,r,'''
const jwt = require("jsonwebtoken");
const JWT_SECRET = "cylab-segredo-fixo-123";

function emitirToken(usuario) {
  return jwt.sign({ sub: usuario.id }, JWT_SECRET, { expiresIn: "1h" });
}
''','''
const jwt = require("jsonwebtoken");

function emitirToken(usuario) {
  return jwt.sign({ sub: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
}
''',"O segredo de assinatura JWT fixo no código permite forjar tokens se o fonte vazar (CWE-798). A correção lê o segredo do ambiente.")
r=R("javascript","weak-hash",328,"Hash fraco MD5/SHA1","""    pattern-either:
      - pattern: crypto.createHash("md5")
      - pattern: crypto.createHash("sha1")
""")
add("javascript",328,r,'''
const crypto = require("crypto");

function hashSenha(senha) {
  return crypto.createHash("md5").update(senha).digest("hex");
}
''','''
const crypto = require("crypto");

function hashSenha(senha) {
  const sal = crypto.randomBytes(16);
  const dk = crypto.scryptSync(senha, sal, 64);
  return sal.toString("hex") + ":" + dk.toString("hex");
}
''',"MD5 não é adequado para senhas por ser rápido e sem sal (CWE-328). scryptSync com sal aleatório torna ataques de força bruta caros.")
r=R("javascript","ssrf",918,"fetch/axios em URL vinda da requisicao","""    pattern-either:
      - pattern: fetch(req.query.$U, ...)
      - pattern: fetch(req.query.$U)
      - pattern: axios.get(req.query.$U, ...)
      - pattern: axios.get(req.query.$U)
""")
add("javascript",918,r,'''
const express = require("express");
const axios = require("axios");
const app = express();

app.get("/proxy", async (req, res) => {
  const r = await axios.get(req.query.url);
  res.send(r.data);
});
''','''
const express = require("express");
const axios = require("axios");
const app = express();
const PERMITIDOS = new Set(["api.parceiro.com.br"]);

app.get("/proxy", async (req, res) => {
  let alvo;
  try { alvo = new URL(String(req.query.url)); } catch { return res.sendStatus(400); }
  if (alvo.protocol !== "https:" || !PERMITIDOS.has(alvo.hostname)) return res.sendStatus(400);
  const r = await axios.get(alvo.toString(), { maxRedirects: 0 });
  res.send(r.data);
});
''',"O proxy busca qualquer URL do cliente, expondo a rede interna (CWE-918). A correção valida protocolo e host com lista de permissões e bloqueia redirecionamentos.")

# ---------- TYPESCRIPT ----------
r=R("typescript","sql-injection",89,"Query raw com interpolacao","""    pattern-either:
      - pattern: $DB.query(`...${$X}...`, ...)
      - pattern: $DB.query(`...${$X}...`)
      - pattern: $DB.$queryRawUnsafe(`...${$X}...`)
""")
add("typescript",89,r,'''
import { Pool } from "pg";

export async function saldo(pool: Pool, conta: string): Promise<number> {
  const r = await pool.query(`SELECT saldo FROM contas WHERE numero = '${conta}'`);
  return r.rows[0]?.saldo ?? 0;
}
''','''
import { Pool } from "pg";

export async function saldo(pool: Pool, conta: string): Promise<number> {
  const r = await pool.query("SELECT saldo FROM contas WHERE numero = $1", [conta]);
  return r.rows[0]?.saldo ?? 0;
}
''',"Interpolar o número da conta no SQL permite injeção (CWE-89). A correção usa parâmetro posicional $1.")
r=R("typescript","xss-dangerously-set",79,"dangerouslySetInnerHTML com dado externo","""    pattern-regex: 'dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:'
""")
add("typescript",79,r,'''
import React from "react";

export function Bio({ texto }: { texto: string }) {
  return <div dangerouslySetInnerHTML={{ __html: texto }} />;
}
''','''
import React from "react";

export function Bio({ texto }: { texto: string }) {
  return <div>{texto}</div>;
}
''',"dangerouslySetInnerHTML com texto do usuário desativa o escape do React e gera XSS (CWE-79). Renderizar como filho de texto mantém o escape automático.")
r=R("typescript","insecure-randomness",338,"Math.random para valor de seguranca","""    patterns:
      - pattern: Math.random()
      - pattern-inside: |
          function $F(...) { ... }
      - metavariable-regex:
          metavariable: $F
          regex: (?i).*(token|senha|codigo|otp|secret).*
""")
add("typescript",338,r,'''
export function gerarCodigoOtp(): string {
  return Math.floor(Math.random() * 1_000_000).toString().padStart(6, "0");
}
''','''
import { randomInt } from "crypto";

export function gerarCodigoOtp(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}
''',"Math.random não é criptograficamente seguro e permite prever códigos OTP (CWE-338). crypto.randomInt usa gerador seguro do sistema.","holdout")
r=R("typescript","open-redirect",601,"Redirecionamento para URL da requisicao","""    pattern-either:
      - pattern: $RES.redirect(req.query.$X)
      - pattern: $RES.redirect(req.query.$X as string)
""")
add("typescript",601,r,'''
import express from "express";
const app = express();

app.get("/login/retorno", (req, res) => {
  res.redirect(req.query.next as string);
});
''','''
import express from "express";
const app = express();

app.get("/login/retorno", (req, res) => {
  const destino = String(req.query.next ?? "/");
  const seguro = destino.startsWith("/") && !destino.startsWith("//") ? destino : "/";
  res.redirect(seguro);
});
''',"Redirecionar para qualquer valor de 'next' permite phishing via redirecionamento aberto (CWE-601). A correção aceita apenas caminhos relativos locais.")

# ---------- JAVA ----------
r=R("java","sql-injection",89,"Statement com SQL concatenado","""    pattern-either:
      - pattern: (java.sql.Statement $S).executeQuery("..." + $X + ...)
      - pattern: $S.executeQuery("..." + $X + "...")
      - pattern: $S.executeQuery("..." + $X)
""")
add("java",89,r,'''
import java.sql.*;

public class ClienteDao {
    public ResultSet porCpf(Connection c, String cpf) throws SQLException {
        Statement st = c.createStatement();
        return st.executeQuery("SELECT * FROM clientes WHERE cpf = '" + cpf + "'");
    }
}
''','''
import java.sql.*;

public class ClienteDao {
    public ResultSet porCpf(Connection c, String cpf) throws SQLException {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM clientes WHERE cpf = ?");
        ps.setString(1, cpf);
        return ps.executeQuery();
    }
}
''',"Concatenar o CPF na query do Statement permite injeção de SQL (CWE-89). PreparedStatement com setString separa código e dado.")
r=R("java","command-injection",78,"Runtime.exec com string concatenada","""    pattern: Runtime.getRuntime().exec("..." + $X)
""")
add("java",78,r,'''
public class Dns {
    public Process consultar(String dominio) throws java.io.IOException {
        return Runtime.getRuntime().exec("nslookup " + dominio);
    }
}
''','''
public class Dns {
    public Process consultar(String dominio) throws java.io.IOException {
        if (!dominio.matches("^[A-Za-z0-9.-]{1,253}$")) throw new IllegalArgumentException("dominio invalido");
        return new ProcessBuilder("nslookup", dominio).start();
    }
}
''',"Concatenar entrada em Runtime.exec permite injetar argumentos/comandos (CWE-78). A correção valida o domínio e usa ProcessBuilder com argumentos separados.")
r=R("java","insecure-deserialization",502,"ObjectInputStream.readObject em dados externos","""    pattern: new ObjectInputStream($IN).readObject()
""")
add("java",502,r,'''
import java.io.*;

public class SessaoCodec {
    public Object ler(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }
}
''','''
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;

public class SessaoCodec {
    private static final ObjectMapper M = new ObjectMapper();
    public Sessao ler(InputStream in) throws IOException {
        return M.readValue(in, Sessao.class);
    }
}
''',"Desserialização Java nativa de fluxo não confiável permite cadeias de gadgets e RCE (CWE-502). A correção lê JSON para um tipo concreto com Jackson.")
r=R("java","weak-hash",328,"MessageDigest MD5/SHA-1","""    pattern-either:
      - pattern: MessageDigest.getInstance("MD5")
      - pattern: MessageDigest.getInstance("SHA-1")
""")
add("java",328,r,'''
import java.security.MessageDigest;

public class Hash {
    public static byte[] senha(String s) throws Exception {
        return MessageDigest.getInstance("MD5").digest(s.getBytes("UTF-8"));
    }
}
''','''
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

public class Hash {
    public static byte[] senha(String s, byte[] sal) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(s.toCharArray(), sal, 310000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
''',"MD5 para senhas é inseguro (CWE-328). PBKDF2-HMAC-SHA256 com sal e muitas iterações torna a quebra cara.")
r=R("java","path-traversal",22,"File construido com parametro HTTP","""    pattern: new File($BASE, $REQ.getParameter(...))
""")
add("java",22,r,'''
import java.io.File;
import javax.servlet.http.*;

public class Download extends HttpServlet {
    protected File alvo(HttpServletRequest req) {
        return new File("/srv/arquivos", req.getParameter("nome"));
    }
}
''','''
import java.io.File;
import java.nio.file.*;
import javax.servlet.http.*;

public class Download extends HttpServlet {
    private static final Path BASE = Paths.get("/srv/arquivos").toAbsolutePath().normalize();
    protected File alvo(HttpServletRequest req) {
        String nome = req.getParameter("nome");
        Path p = BASE.resolve(nome).normalize();
        if (!p.startsWith(BASE)) throw new SecurityException("caminho invalido");
        return p.toFile();
    }
}
''',"Usar o parâmetro direto em new File permite '../' (CWE-22). A correção normaliza o caminho e verifica se continua dentro do diretório base.","holdout")

# ---------- PHP ----------
r=R("php","sql-injection",89,"mysqli_query com variavel superglobal","""    pattern-either:
      - pattern: mysqli_query($C, "..." . $_GET[$K] . "...")
      - pattern: mysqli_query($C, "..." . $_POST[$K] . "...")
""")
add("php",89,r,'''
<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "loja");
$res = mysqli_query($conn, "SELECT * FROM itens WHERE id = '" . $_GET['id'] . "'");
''','''
<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "loja");
$st = mysqli_prepare($conn, "SELECT * FROM itens WHERE id = ?");
mysqli_stmt_bind_param($st, "i", $_GET['id']);
mysqli_stmt_execute($st);
$res = mysqli_stmt_get_result($st);
''',"Concatenar $_GET na query permite injeção de SQL (CWE-89). A correção usa prepared statement com bind de parâmetro inteiro.")
r=R("php","xss-echo",79,"echo de superglobal sem escape","""    pattern-either:
      - pattern: echo $_GET[$K];
      - pattern: echo "..." . $_GET[$K] . "...";
      - pattern: echo "..." . $_GET[$K];
""")
add("php",79,r,'''
<?php
echo "<p>Resultados para: " . $_GET['q'] . "</p>";
''','''
<?php
echo "<p>Resultados para: " . htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";
''',"Ecoar o termo de busca sem escape gera XSS refletido (CWE-79). htmlspecialchars com ENT_QUOTES codifica caracteres HTML.")
r=R("php","command-injection",78,"shell_exec/system com entrada externa","""    pattern-either:
      - pattern: shell_exec("..." . $_GET[$K])
      - pattern: system("..." . $_GET[$K])
""")
add("php",78,r,'''
<?php
$saida = shell_exec("whois " . $_GET['dominio']);
echo $saida;
''','''
<?php
$dominio = $_GET['dominio'] ?? '';
if (!preg_match('/^[A-Za-z0-9.-]{1,253}$/', $dominio)) { http_response_code(400); exit; }
$saida = shell_exec("whois " . escapeshellarg($dominio));
echo htmlspecialchars($saida ?? '', ENT_QUOTES, 'UTF-8');
''',"Concatenar parâmetro em shell_exec permite injetar comandos (CWE-78). A correção valida o domínio e usa escapeshellarg.")
r=R("php","insecure-deserialization",502,"unserialize de entrada do usuario","""    pattern-either:
      - pattern: unserialize($_COOKIE[$K])
      - pattern: unserialize($_POST[$K])
""")
add("php",502,r,'''
<?php
$carrinho = unserialize($_COOKIE['carrinho']);
''','''
<?php
$carrinho = json_decode($_COOKIE['carrinho'] ?? '[]', true, 8, JSON_THROW_ON_ERROR);
''',"unserialize em cookie controlado pelo cliente permite injeção de objetos PHP (CWE-502). json_decode produz apenas arrays e escalares.")

# ---------- C# ----------
r=R("csharp","sql-injection",89,"SqlCommand com SQL concatenado","""    pattern: new SqlCommand("..." + $X + "...", $C)
""")
add("csharp",89,r,'''
using System.Data.SqlClient;

public class Repo {
    public SqlDataReader Buscar(SqlConnection c, string nome) {
        var cmd = new SqlCommand("SELECT * FROM Fornecedores WHERE Nome = '" + nome + "'", c);
        return cmd.ExecuteReader();
    }
}
''','''
using System.Data.SqlClient;

public class Repo {
    public SqlDataReader Buscar(SqlConnection c, string nome) {
        var cmd = new SqlCommand("SELECT * FROM Fornecedores WHERE Nome = @nome", c);
        cmd.Parameters.AddWithValue("@nome", nome);
        return cmd.ExecuteReader();
    }
}
''',"Concatenar o nome no SqlCommand permite injeção de SQL (CWE-89). A correção usa parâmetro nomeado @nome.")
r=R("csharp","insecure-deserialization",502,"BinaryFormatter.Deserialize","""    pattern: new BinaryFormatter().Deserialize($S)
""")
add("csharp",502,r,'''
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class Cache {
    public object Ler(Stream s) {
        return new BinaryFormatter().Deserialize(s);
    }
}
''','''
using System.IO;
using System.Text.Json;

public class Cache {
    public Item Ler(Stream s) {
        return JsonSerializer.Deserialize<Item>(s);
    }
}
''',"BinaryFormatter é inseguro e permite execução remota de código com dados maliciosos (CWE-502). A correção usa System.Text.Json para um tipo concreto.")

# ---------- C ----------
r=R("c","buffer-overflow-strcpy",120,"strcpy/gets sem limite de tamanho","""    pattern-either:
      - pattern: strcpy($D, $S);
      - pattern: gets($B);
""")
add("c",120,r,'''
#include <string.h>

void copiar_nome(char *destino, const char *entrada) {
    char buf[32];
    strcpy(buf, entrada);
    strcpy(destino, buf);
}
''','''
#include <stdio.h>

void copiar_nome(char *destino, size_t tam, const char *entrada) {
    char buf[32];
    snprintf(buf, sizeof buf, "%s", entrada);
    snprintf(destino, tam, "%s", buf);
}
''',"strcpy copia sem verificar tamanho e estoura o buffer de 32 bytes (CWE-120). snprintf limita a escrita ao tamanho do destino.")
r=R("c","format-string",134,"printf com string de formato controlada","""    patterns:
      - pattern: printf($X);
      - pattern-not: printf("...");
""")
add("c",134,r,'''
#include <stdio.h>

void logar(const char *msg) {
    printf(msg);
}
''','''
#include <stdio.h>

void logar(const char *msg) {
    printf("%s", msg);
}
''',"Passar a mensagem como formato permite '%n' e leitura de memória (CWE-134). A correção usa formato literal %s fixo.")
r=R("c","command-injection",78,"system com buffer montado","""    patterns:
      - pattern: system($CMD);
      - pattern-not: system("...");
""")
add("c",78,r,'''
#include <stdio.h>
#include <stdlib.h>

int remover(const char *arquivo) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -f %s", arquivo);
    return system(cmd);
}
''','''
#include <unistd.h>

int remover(const char *arquivo) {
    return unlink(arquivo);
}
''',"Montar comando para system com nome externo permite injeção de shell (CWE-78). A correção usa a chamada unlink diretamente, sem shell.","holdout")

# ---------- BASH ----------
r=R("bash","eval-injection",95,"eval com variavel externa","""    pattern: eval "...$X..."
""")
add("bash",95,r,'''
#!/usr/bin/env bash
campo="$1"
eval "echo \\$$campo"
''','''
#!/usr/bin/env bash
campo="$1"
[[ "$campo" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "nome invalido" >&2; exit 1; }
echo "${!campo}"
''',"eval executa o argumento como código shell (CWE-95). A correção valida o nome e usa expansão indireta ${!campo}.")
r=R("bash","curl-pipe-shell",494,"Download executado sem verificacao de integridade","""    pattern: curl ... | bash
""")
add("bash",494,r,'''
#!/usr/bin/env bash
set -euo pipefail
curl -fsSL https://ferramentas.exemplo.com/instalar.sh | bash
''','''
#!/usr/bin/env bash
set -euo pipefail
SHA="3f1c0d6e9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e"
curl -fsSL -o /tmp/instalar.sh https://ferramentas.exemplo.com/instalar.sh
echo "${SHA}  /tmp/instalar.sh" | sha256sum -c -
bash /tmp/instalar.sh
''',"Executar script baixado diretamente sem checar integridade permite execução de código adulterado (CWE-494). A correção baixa, verifica SHA-256 e só então executa.")

for i,p in enumerate(P,1):
    p["id"]=f"cylab-v0.1-{i:04d}"
os.makedirs("rules",exist_ok=True)
for rid,y in RULES.items():
    open(f"rules/{rid}.yaml","w").write(y)
K=["id","lang","cwe","source","license","opengrep_rule","before","after","explanation_pt","split"]
with open("data/cylab-v0.1.jsonl","w") as f:
    for p in P: f.write(json.dumps({k:p[k] for k in K},ensure_ascii=False)+"\n")
print(len(P),"pairs",len(RULES),"rules")
