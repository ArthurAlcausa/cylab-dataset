# ---------- C# CWE-22
B='''using System.IO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    [Authorize]
    [Route("contratos")]
    public class ContratosController : Controller
    {
        private const string Raiz = "/srv/portal/contratos";

        private string Cliente() => User.Identity?.Name ?? "anonimo";

        private static bool ExtensaoValida(string nome) =>
            nome.EndsWith(".pdf") || nome.EndsWith(".txt");

        [HttpGet("baixar")]
        public IActionResult Baixar(string arquivo)
        {
            if (string.IsNullOrWhiteSpace(arquivo) || !ExtensaoValida(arquivo))
            {
                return BadRequest("arquivo invalido");
            }
            var caminho = Path.Combine(Raiz, Cliente(), arquivo);
            if (!System.IO.File.Exists(caminho))
            {
                return NotFound();
            }
            var bytes = File.ReadAllBytes(caminho);
            return File(bytes, "application/octet-stream", arquivo);
        }
    }
}
'''
A=B.replace('''            var caminho = Path.Combine(Raiz, Cliente(), arquivo);''','''            var seguro = Path.GetFileName(arquivo);
            var caminho = Path.Combine(Raiz, Cliente(), seguro);''').replace('return File(bytes, "application/octet-stream", arquivo);','return File(bytes, "application/octet-stream", seguro);')
add('csharp','22','cylab.csharp.path-combine-file','r001',B,A,'O parâmetro arquivo é combinado ao diretório do cliente com Path.Combine e lido do disco; valores com ../ ou caminhos absolutos escapam da pasta e expõem arquivos de outros clientes (CWE-22). A correção reduz a entrada ao nome do arquivo com Path.GetFileName antes de montar o caminho.')

# ---------- C# CWE-502
B='''using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    [ApiController]
    [Route("api/rascunhos")]
    public class RascunhosController : ControllerBase
    {
        private readonly IRascunhoRepositorio _repo;

        public RascunhosController(IRascunhoRepositorio repo)
        {
            _repo = repo;
        }

        [HttpPost("importar")]
        public async Task<IActionResult> Importar(Stream corpo)
        {
            if (corpo == null || !corpo.CanRead)
            {
                return BadRequest();
            }
            var formatter = new BinaryFormatter();
            var rascunho = (Rascunho)formatter.Deserialize(corpo);
            await _repo.SalvarAsync(rascunho);
            return Ok(new { rascunho.Id });
        }
    }

    public class Rascunho { public int Id { get; set; } public string Texto { get; set; } }
    public interface IRascunhoRepositorio { Task SalvarAsync(Rascunho r); }
}
'''
A=B.replace('''            if (corpo == null || !corpo.CanRead)
            {
                return BadRequest();
            }
            var formatter = new BinaryFormatter();
            var rascunho = (Rascunho)formatter.Deserialize(corpo);''','''            var rascunho = await JsonSerializer.DeserializeAsync<Rascunho>(corpo);
            if (rascunho == null || rascunho.Texto?.Length > 20000)
            {
                return BadRequest();
            }''').replace('using System.Runtime.Serialization.Formatters.Binary;','using System.Text.Json;')
add('csharp','502','cylab.csharp.binaryformatter','r001',B,A,'O corpo da requisição é desserializado com BinaryFormatter, que instancia tipos arbitrários e permite execução remota de código via gadgets (CWE-502). A correção usa System.Text.Json tipado para Rascunho e valida o resultado.')

# ---------- C# CWE-79
B='''using System.Linq;
using Microsoft.AspNetCore.Mvc;

namespace Loja.Controllers
{
    public class AvaliacoesController : Controller
    {
        private readonly IAvaliacaoServico _servico;

        public AvaliacoesController(IAvaliacaoServico servico)
        {
            _servico = servico;
        }

        private static string Estrelas(int nota) => new string('*', nota);

        [HttpGet("/avaliacoes")]
        public IActionResult Listar(string produto)
        {
            var itens = _servico.PorProduto(produto).Take(20).ToList();
            var lista = string.Concat(itens.Select(a => "<li>" + Estrelas(a.Nota) + "</li>"));
            var titulo = "<h1>Avaliacoes de " + produto + "</h1>";
            var html = titulo + "<ul>" + lista + "</ul>";
            return Content(html, "text/html");
        }
    }

    public record Avaliacao(int Nota);
    public interface IAvaliacaoServico { System.Collections.Generic.IEnumerable<Avaliacao> PorProduto(string p); }
}
'''
A=B.replace('var titulo = "<h1>Avaliacoes de " + produto + "</h1>";','var titulo = "<h1>Avaliacoes de " + WebUtility.HtmlEncode(produto) + "</h1>";').replace('var lista = string.Concat(itens.Select(a => "<li>" + Estrelas(a.Nota) + "</li>"));','var lista = string.Empty;\n            foreach (var a in itens) { lista += "<li>" + WebUtility.HtmlEncode(Estrelas(a.Nota)) + "</li>"; }').replace('using System.Linq;','using System.Linq;\nusing System.Net;')
add('csharp','79','cylab.csharp.html-content-interp','r001',B,A,'O nome do produto recebido na query é concatenado ao HTML retornado por Content(..., "text/html") sem codificação, permitindo XSS refletido (CWE-79). A correção codifica o valor com WebUtility.HtmlEncode.')

# ---------- C# CWE-918
B='''using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Integracoes.Controllers
{
    [ApiController]
    [Route("api/webhooks")]
    public class WebhookTesteController : ControllerBase
    {
        private readonly IHttpClientFactory _fabrica;

        public WebhookTesteController(IHttpClientFactory fabrica)
        {
            _fabrica = fabrica;
        }

        private static string Resumir(string corpo) =>
            corpo.Length > 200 ? corpo.Substring(0, 200) : corpo;

        [HttpGet("testar")]
        public async Task<IActionResult> Testar(string destino)
        {
            if (string.IsNullOrEmpty(destino))
            {
                return BadRequest();
            }
            var cliente = _fabrica.CreateClient();
            cliente.Timeout = TimeSpan.FromSeconds(5);
            var resp = await cliente.GetAsync(destino);
            var corpo = await resp.Content.ReadAsStringAsync();
            return Ok(new { status = (int)resp.StatusCode, amostra = Resumir(corpo) });
        }
    }
}
'''
A=B.replace('''            var resp = await cliente.GetAsync(destino);''','''            var baseUri = new Uri("https://hooks.parceiro.com.br/");
            var alvo = new Uri(baseUri, Uri.EscapeDataString(destino));
            var resp = await cliente.GetAsync(alvo);''')
add('csharp','918','cylab.csharp.httpclient-user-url','r001',B,A,'O endpoint faz GET em qualquer URL informada pelo usuário, permitindo atingir serviços internos e metadados de nuvem (SSRF, CWE-918). A correção fixa a base https do parceiro e só aceita o valor do usuário como segmento de caminho escapado com Uri.EscapeDataString.')

# ---------- C# CWE-601
B='''using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    public class ContaController : Controller
    {
        private readonly SignInManager<IdentityUser> _signIn;

        public ContaController(SignInManager<IdentityUser> signIn)
        {
            _signIn = signIn;
        }

        [HttpGet]
        public IActionResult Entrar() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Entrar(string email, string senha, string retorno)
        {
            var r = await _signIn.PasswordSignInAsync(email, senha, false, true);
            if (!r.Succeeded)
            {
                ModelState.AddModelError("", "credenciais invalidas");
                return View();
            }
            if (string.IsNullOrEmpty(retorno))
            {
                return RedirectToAction("Index", "Home");
            }
            return Redirect(retorno);
        }
    }
}
'''
A=B.replace('''            if (string.IsNullOrEmpty(retorno))
            {
                return RedirectToAction("Index", "Home");
            }
            return Redirect(retorno);''','''            if (string.IsNullOrEmpty(retorno) || !Url.IsLocalUrl(retorno))
            {
                return RedirectToAction("Index", "Home");
            }
            return LocalRedirect(retorno);''')
add('csharp','601','cylab.csharp.mvc-redirect-return','r001',B,A,'Após o login, o controlador redireciona para o parâmetro retorno sem validação, permitindo redirecionamento aberto para sites de phishing (CWE-601). A correção verifica Url.IsLocalUrl e usa LocalRedirect, que só aceita URLs locais.')

# ---------- C# CWE-78
B='''using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers
{
    [Authorize(Roles = "operador")]
    [Route("ops/backup")]
    public class BackupController : Controller
    {
        private const string DirBackups = "/var/backups/app";

        private static string LerSaida(Process p)
        {
            var saida = p.StandardOutput.ReadToEnd();
            p.WaitForExit(30000);
            return saida;
        }

        [HttpPost("compactar")]
        public IActionResult Compactar(string pasta)
        {
            if (string.IsNullOrWhiteSpace(pasta))
            {
                return BadRequest("pasta obrigatoria");
            }
            var args = "-c \\"tar czf " + DirBackups + "/bkp.tgz " + pasta + "\\"";
            var proc = Process.Start("/bin/sh", args);
            var log = proc == null ? "" : LerSaida(proc);
            return Ok(new { log });
        }
    }
}
'''
A=B.replace('''            var args = "-c \\"tar czf " + DirBackups + "/bkp.tgz " + pasta + "\\"";
            var proc = Process.Start("/bin/sh", args);''','''            var psi = new ProcessStartInfo("tar") { RedirectStandardOutput = true, UseShellExecute = false };
            psi.ArgumentList.Add("czf");
            psi.ArgumentList.Add(DirBackups + "/bkp.tgz");
            psi.ArgumentList.Add("--");
            psi.ArgumentList.Add(pasta);
            var proc = Process.Start(psi);''')
add('csharp','78','cylab.csharp.process-start-shell','r001',B,A,'A pasta informada pelo operador é concatenada em um comando passado a /bin/sh -c, permitindo injetar comandos adicionais com ; ou $( ) (CWE-78). A correção chama tar diretamente, sem shell, passando cada argumento por ProcessStartInfo.ArgumentList e usando -- para encerrar opções.')
