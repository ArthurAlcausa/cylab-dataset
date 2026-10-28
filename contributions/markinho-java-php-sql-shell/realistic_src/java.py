P=[]
def add(lang,cwe,rule,slug_n,before,after,expl): P.append(dict(lang=lang,cwe=cwe,rule=rule,n=slug_n,before=before,after=after,expl=expl))

# ---------- JAVA CWE-78
JB='''import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DiagnosticoRedeServlet extends HttpServlet {
    private static final int MAX_LINHAS = 50;

    private String lerSaida(Process proc) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String linha;
            int n = 0;
            while ((linha = br.readLine()) != null && n++ < MAX_LINHAS) {
                sb.append(linha).append('\\n');
            }
        }
        return sb.toString();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String host = req.getParameter("host");
        if (host == null || host.isEmpty()) {
            resp.sendError(400, "host obrigatorio");
            return;
        }
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 3 " + host);
        resp.setContentType("text/plain");
        resp.getWriter().write(lerSaida(proc));
    }
}
'''
JA=JB.replace('''        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping -c 3 " + host);''','''        if (!host.matches("^[A-Za-z0-9.-]{1,253}$")) {
            resp.sendError(400, "host invalido");
            return;
        }
        ProcessBuilder pb = new ProcessBuilder(List.of("ping", "-c", "3", host));
        pb.redirectErrorStream(true);
        Process proc = pb.start();''').replace('import java.io.InputStreamReader;\n','import java.io.InputStreamReader;\nimport java.util.List;\n')
add('java','78','cylab.java.runtime-exec-concat','r001',JB,JA,'O servlet concatena o parâmetro host em uma linha de comando passada a Runtime.exec, permitindo injeção de argumentos e comandos do sistema operacional (CWE-78). A correção valida o host com uma allowlist de caracteres e usa ProcessBuilder com lista de argumentos, sem interpretação da string como linha de comando.')

# ---------- JAVA CWE-22
JB='''import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadFaturaServlet extends HttpServlet {
    private static final String BASE_FATURAS = "/srv/app/faturas";

    private boolean usuarioAutenticado(HttpServletRequest req) {
        return req.getSession(false) != null
            && req.getSession(false).getAttribute("clienteId") != null;
    }

    private void enviarPdf(File arquivo, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/pdf");
        resp.setHeader("Content-Disposition", "attachment; filename=fatura.pdf");
        try (OutputStream out = resp.getOutputStream()) {
            Files.copy(arquivo.toPath(), out);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!usuarioAutenticado(req)) {
            resp.sendError(401);
            return;
        }
        String nome = req.getParameter("arquivo");
        File fatura = new File(BASE_FATURAS + "/" + nome);
        if (!fatura.exists()) {
            resp.sendError(404);
            return;
        }
        enviarPdf(fatura, resp);
    }
}
'''
JA=JB.replace('''        File fatura = new File(BASE_FATURAS + "/" + nome);''','''        if (nome == null || !nome.matches("^[A-Za-z0-9_-]{1,64}\\\\.pdf$")) {
            resp.sendError(400, "nome de arquivo invalido");
            return;
        }
        Path base = Paths.get(BASE_FATURAS).toAbsolutePath().normalize();
        Path alvo = base.resolve(nome).normalize();
        if (!alvo.startsWith(base)) {
            resp.sendError(403);
            return;
        }
        File fatura = alvo.toFile();''').replace('import java.nio.file.Files;\n','import java.nio.file.Files;\nimport java.nio.file.Path;\nimport java.nio.file.Paths;\n')
add('java','22','cylab.java.file-from-parameter','r001',JB,JA,'O nome do arquivo vem do parâmetro da requisição e é concatenado ao diretório base em new File, permitindo sequências ../ para ler arquivos fora da pasta de faturas (CWE-22). A correção valida o nome com allowlist, normaliza o caminho e confirma que ele permanece dentro do diretório base.')

# ---------- JAVA CWE-502
JB='''import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ImportarPreferenciasServlet extends HttpServlet {
    private final Map<String, Map<String, String>> repositorio = new HashMap<>();

    private String clienteAtual(HttpServletRequest req) {
        Object id = req.getSession().getAttribute("clienteId");
        return id == null ? null : id.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> lerPreferencias(InputStream corpo) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(corpo)) {
            return (Map<String, String>) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("formato desconhecido", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cliente = clienteAtual(req);
        if (cliente == null) {
            resp.sendError(401);
            return;
        }
        Map<String, String> prefs = lerPreferencias(req.getInputStream());
        repositorio.put(cliente, prefs);
        resp.setStatus(204);
    }
}
'''
JA=JB.replace('''    @SuppressWarnings("unchecked")
    private Map<String, String> lerPreferencias(InputStream corpo) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(corpo)) {
            return (Map<String, String>) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("formato desconhecido", e);
        }
    }''','''    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Map<String, String> lerPreferencias(InputStream corpo) throws IOException {
        Map<String, String> prefs = MAPPER.readValue(corpo, new TypeReference<Map<String, String>>() {});
        if (prefs.size() > 100) {
            throw new IOException("preferencias demais");
        }
        return prefs;
    }''').replace('import java.io.ObjectInputStream;\n','').replace('import java.util.HashMap;\n','import java.util.HashMap;\nimport com.fasterxml.jackson.core.type.TypeReference;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n')
add('java','502','cylab.java.objectinputstream','r001',JB,JA,'O corpo da requisição é desserializado com ObjectInputStream, o que permite a um atacante enviar cadeias de gadgets e executar código durante readObject (CWE-502). A correção troca a serialização nativa Java por JSON tipado com Jackson para um Map<String,String> e limita o tamanho.')

# ---------- JAVA CWE-79
JB='''import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BuscaProdutosServlet extends HttpServlet {
    private final CatalogoService catalogo = new CatalogoService();

    private void cabecalho(PrintWriter out) {
        out.println("<!doctype html><html><head><meta charset='utf-8'>");
        out.println("<title>Busca</title></head><body>");
    }

    private void rodape(PrintWriter out) {
        out.println("</body></html>");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String termo = req.getParameter("q");
        if (termo == null) {
            termo = "";
        }
        List<String> resultados = catalogo.buscar(termo);
        resp.setContentType("text/html; charset=UTF-8");
        PrintWriter out = resp.getWriter();
        cabecalho(out);
        out.println("<h1>Resultados para " + termo + "</h1>");
        out.printf("<p>%d itens</p>%n", resultados.size());
        rodape(out);
    }

    static class CatalogoService {
        List<String> buscar(String termo) {
            return List.of();
        }
    }
}
'''
JA=JB.replace('out.println("<h1>Resultados para " + termo + "</h1>");','out.println("<h1>Resultados para " + Encode.forHtml(termo) + "</h1>");').replace('import java.util.List;\n','import java.util.List;\nimport org.owasp.encoder.Encode;\n')
add('java','79','cylab.java.servlet-writer-param','r001',JB,JA,'O termo de busca da query string é escrito diretamente no HTML da resposta, permitindo XSS refletido (CWE-79). A correção codifica o termo com Encode.forHtml do OWASP Java Encoder antes de inseri-lo na página.')

# ---------- JAVA CWE-918
JB='''import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreviewImagemServlet extends HttpServlet {
    private static final int LIMITE_BYTES = 2 * 1024 * 1024;

    private byte[] lerLimitado(InputStream in) throws IOException {
        byte[] dados = in.readNBytes(LIMITE_BYTES + 1);
        if (dados.length > LIMITE_BYTES) {
            throw new IOException("imagem grande demais");
        }
        return dados;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String endereco = req.getParameter("url");
        if (endereco == null) {
            resp.sendError(400);
            return;
        }
        URL url = new URL(endereco);
        byte[] imagem;
        try (InputStream in = url.openStream()) {
            imagem = lerLimitado(in);
        }
        resp.setContentType("image/png");
        resp.getOutputStream().write(imagem);
    }
}
'''
JA=JB.replace('''        URL url = new URL(endereco);''','''        URL url = new URL(endereco);
        if (!"https".equals(url.getProtocol()) || !HOSTS_PERMITIDOS.contains(url.getHost())) {
            resp.sendError(403, "origem nao permitida");
            return;
        }''').replace('''    private static final int LIMITE_BYTES''','''    private static final Set<String> HOSTS_PERMITIDOS = Set.of("cdn.exemplo.com.br", "img.exemplo.com.br");
    private static final int LIMITE_BYTES''').replace('import java.net.URL;\n','import java.net.URL;\nimport java.util.Set;\n')
add('java','918','cylab.java.url-from-parameter','r001',JB,JA,'O servlet abre qualquer URL recebida no parâmetro, permitindo que o servidor seja usado para acessar serviços internos ou metadados de nuvem (SSRF, CWE-918). A correção exige HTTPS e um host presente em uma allowlist antes de abrir a conexão.')

# ---------- JAVA CWE-90
JB='''import java.util.ArrayList;
import java.util.List;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class DiretorioColaboradores {
    private static final String BASE = "ou=pessoas,dc=empresa,dc=com";
    private final DirContext ctx;

    public DiretorioColaboradores(DirContext ctx) {
        this.ctx = ctx;
    }

    private SearchControls controles() {
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setReturningAttributes(new String[] {"cn", "mail", "departmentNumber"});
        sc.setCountLimit(25);
        return sc;
    }

    public List<String> buscarPorLogin(String login) throws NamingException {
        String filtro = "(&(objectClass=person)(uid=" + login + "))";
        NamingEnumeration<SearchResult> res = ctx.search(BASE, filtro, controles());
        List<String> nomes = new ArrayList<>();
        while (res.hasMore()) {
            nomes.add(res.next().getNameInNamespace());
        }
        res.close();
        return nomes;
    }
}
'''
JA=JB.replace('''        String filtro = "(&(objectClass=person)(uid=" + login + "))";
        NamingEnumeration<SearchResult> res = ctx.search(BASE, filtro, controles());''','''        String filtro = "(&(objectClass=person)(uid={0}))";
        Object[] args = new Object[] {login};
        NamingEnumeration<SearchResult> res = ctx.search(BASE, filtro, args, controles());''')
add('java','90','cylab.java.ldap-filter-concat','r001',JB,JA,'O login é concatenado ao filtro LDAP, permitindo que caracteres como *, ( e ) alterem a lógica da busca e exponham outros registros (injeção LDAP, CWE-90). A correção usa o filtro parametrizado {0} com argumentos separados, que o JNDI escapa automaticamente.')
