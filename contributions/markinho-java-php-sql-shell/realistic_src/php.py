# ---------- PHP CWE-79
B='''<?php
declare(strict_types=1);

session_start();

function carregarPedido(PDO $pdo, int $id): ?array
{
    $st = $pdo->prepare('SELECT id, cliente, total FROM pedidos WHERE id = ?');
    $st->execute([$id]);
    $linha = $st->fetch(PDO::FETCH_ASSOC);
    return $linha === false ? null : $linha;
}

function formatarTotal(float $valor): string
{
    return 'R$ ' . number_format($valor, 2, ',', '.');
}

$pdo = new PDO('sqlite:/var/app/loja.db');
$id = (int) ($_GET['id'] ?? 0);
$pedido = carregarPedido($pdo, $id);
$obs = $_GET['obs'] ?? '';

header('Content-Type: text/html; charset=utf-8');
if ($pedido === null) {
    http_response_code(404);
    echo '<p>Pedido nao encontrado</p>';
    exit;
}
echo '<h2>Pedido #' . $pedido['id'] . '</h2>';
echo '<p>Total: ' . formatarTotal((float) $pedido['total']) . '</p>';
echo '<p>Observacao: ' . $obs . '</p>';
'''
A=B.replace("$obs = $_GET['obs'] ?? '';","$obs = htmlspecialchars($_GET['obs'] ?? '', ENT_QUOTES, 'UTF-8');")
add('php','79','cylab.php.echo-superglobal','r001',B,A,'O campo obs da query string é ecoado no HTML sem escape, permitindo XSS refletido (CWE-79). A correção aplica htmlspecialchars com ENT_QUOTES e UTF-8 antes de imprimir o valor.')

# ---------- PHP CWE-22 include
B='''<?php
declare(strict_types=1);

const DIR_RELATORIOS = __DIR__ . '/relatorios';

function exigirAdmin(): void
{
    session_start();
    if (($_SESSION['papel'] ?? '') !== 'admin') {
        http_response_code(403);
        exit('acesso negado');
    }
}

function renderizarLayout(string $titulo, callable $conteudo): void
{
    echo '<html><head><title>' . htmlspecialchars($titulo) . '</title></head><body>';
    $conteudo();
    echo '</body></html>';
}

exigirAdmin();
$modulo = $_GET['modulo'] ?? 'vendas';
$arquivo = DIR_RELATORIOS . '/' . $modulo . '.php';

if (!is_file($arquivo)) {
    http_response_code(404);
    exit('relatorio inexistente');
}

renderizarLayout('Relatorio', function () use ($arquivo) {
    include $arquivo;
});
'''
A=B.replace("""$modulo = $_GET['modulo'] ?? 'vendas';""","""$modulo = $_GET['modulo'] ?? 'vendas';
$permitidos = ['vendas', 'estoque', 'financeiro'];
if (!in_array($modulo, $permitidos, true)) {
    http_response_code(400);
    exit('modulo invalido');
}""")
add('php','22','cylab.php.file-superglobal','r001',B,A,'O nome do módulo vem de $_GET e é usado para montar o caminho passado a include, permitindo ../ para incluir arquivos arbitrários (path traversal / inclusão local, CWE-22). A correção restringe o módulo a uma allowlist fixa com in_array estrito antes de montar o caminho.')

# ---------- PHP CWE-502
B='''<?php
declare(strict_types=1);

final class Carrinho
{
    public array $itens = [];

    public function total(): float
    {
        $soma = 0.0;
        foreach ($this->itens as $item) {
            $soma += $item['preco'] * $item['qtd'];
        }
        return $soma;
    }
}

function restaurarCarrinho(): Carrinho
{
    if (empty($_COOKIE['carrinho'])) {
        return new Carrinho();
    }
    $bruto = base64_decode($_COOKIE['carrinho']);
    $obj = unserialize($bruto);
    return $obj instanceof Carrinho ? $obj : new Carrinho();
}

$carrinho = restaurarCarrinho();
header('Content-Type: application/json');
echo json_encode([
    'itens' => count($carrinho->itens),
    'total' => $carrinho->total(),
]);
'''
A=B.replace('''    $bruto = base64_decode($_COOKIE['carrinho']);
    $obj = unserialize($bruto);
    return $obj instanceof Carrinho ? $obj : new Carrinho();''','''    $dados = json_decode($_COOKIE['carrinho'], true);
    $c = new Carrinho();
    if (is_array($dados)) {
        foreach ($dados as $item) {
            $c->itens[] = ['preco' => (float) ($item['preco'] ?? 0), 'qtd' => (int) ($item['qtd'] ?? 0)];
        }
    }
    return $c;''')
add('php','502','cylab.php.unserialize-input','r001',B,A,'O cookie do carrinho é passado a unserialize, permitindo que o cliente injete objetos arbitrários e acione métodos mágicos (__wakeup/__destruct) em cadeias POP (CWE-502). A correção usa json_decode para um array simples e reconstrói o objeto com campos tipados.')

# ---------- PHP CWE-918
B='''<?php
declare(strict_types=1);

function responderJson(int $status, array $corpo): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($corpo);
    exit;
}

function extrairTitulo(string $html): string
{
    if (preg_match('/<title>(.*?)<\\/title>/is', $html, $m)) {
        return trim(html_entity_decode($m[1]));
    }
    return '';
}

$url = $_POST['url'] ?? '';
if ($url === '') {
    responderJson(400, ['erro' => 'url obrigatoria']);
}

$ctx = stream_context_create(['http' => ['timeout' => 5]]);
$html = file_get_contents($url, false, $ctx);
if ($html === false) {
    responderJson(502, ['erro' => 'falha ao buscar']);
}

responderJson(200, ['titulo' => extrairTitulo($html)]);
'''
A=B.replace('''$ctx = stream_context_create''','''$partes = parse_url($url);
$hostsOk = ['blog.exemplo.com.br', 'noticias.exemplo.com.br'];
if (!in_array($partes['host'] ?? '', $hostsOk, true)) {
    responderJson(403, ['erro' => 'host nao permitido']);
}
if (($partes['scheme'] ?? '') !== 'https') {
    responderJson(403, ['erro' => 'apenas https']);
}

$ctx = stream_context_create''')
add('php','918','cylab.php.fetch-user-url','r001',B,A,'O endpoint de pré-visualização busca com file_get_contents qualquer URL enviada no POST, inclusive file:// e endereços internos (SSRF, CWE-918). A correção analisa a URL e só prossegue para hosts de uma allowlist com esquema https.')

# ---------- PHP CWE-78
B='''<?php
declare(strict_types=1);

const DIR_UPLOADS = '/var/app/uploads';

function autenticado(): bool
{
    session_start();
    return isset($_SESSION['usuario_id']);
}

function gerarMiniatura(string $origem, string $destino, int $largura): ?string
{
    $cmd = 'convert ' . $origem . ' -resize ' . $largura . 'x ' . $destino . ' 2>&1';
    return shell_exec($cmd);
}

if (!autenticado()) {
    http_response_code(401);
    exit;
}

$nome = $_POST['imagem'] ?? '';
$largura = (int) ($_POST['largura'] ?? 200);
$origem = DIR_UPLOADS . '/' . $nome;
$destino = DIR_UPLOADS . '/thumb_' . $nome;

$erro = gerarMiniatura($origem, $destino, $largura);
header('Content-Type: application/json');
echo json_encode(['ok' => $erro === null || $erro === '', 'saida' => $erro]);
'''
A=B.replace('''    $cmd = 'convert ' . $origem . ' -resize ' . $largura . 'x ' . $destino . ' 2>&1';''','''    $cmd = 'convert ' . escapeshellarg($origem) . ' -resize ' . (int) $largura . 'x '
        . escapeshellarg($destino) . ' 2>&1';''').replace("""$nome = $_POST['imagem'] ?? '';""","""$nome = basename($_POST['imagem'] ?? '');""")
add('php','78','cylab.php.shell-concat','r001',B,A,'O nome da imagem enviado no POST é concatenado em uma linha de comando executada por shell_exec, permitindo injetar comandos com ; ou $( ) (CWE-78). A correção reduz o nome com basename e escapa cada argumento com escapeshellarg.')

# ---------- PHP CWE-95
B='''<?php
declare(strict_types=1);

function calcularFrete(string $formula, float $peso, float $distancia): float
{
    $expr = str_replace(['peso', 'distancia'], [(string) $peso, (string) $distancia], $formula);
    return (float) eval('return ' . $expr . ';');
}

function respostaJson(array $dados): void
{
    header('Content-Type: application/json');
    echo json_encode($dados);
}

$formula = $_POST['formula'] ?? 'peso * 1.5';
$peso = (float) ($_POST['peso'] ?? 0);
$distancia = (float) ($_POST['distancia'] ?? 0);

if ($peso <= 0 || $distancia <= 0) {
    http_response_code(400);
    respostaJson(['erro' => 'peso e distancia devem ser positivos']);
    exit;
}

$valor = calcularFrete($formula, $peso, $distancia);
respostaJson([
    'frete' => round($valor, 2),
    'moeda' => 'BRL',
]);
'''
A=B.replace('''function calcularFrete(string $formula, float $peso, float $distancia): float
{
    $expr = str_replace(['peso', 'distancia'], [(string) $peso, (string) $distancia], $formula);
    return (float) eval('return ' . $expr . ';');
}''','''const TABELAS_FRETE = [
    'padrao' => ['por_kg' => 1.5, 'por_km' => 0.10],
    'expresso' => ['por_kg' => 2.8, 'por_km' => 0.25],
];

function calcularFrete(string $tabela, float $peso, float $distancia): float
{
    $t = TABELAS_FRETE[$tabela] ?? TABELAS_FRETE['padrao'];
    return $peso * $t['por_kg'] + $distancia * $t['por_km'];
}''').replace("""$formula = $_POST['formula'] ?? 'peso * 1.5';""","""$formula = $_POST['tabela'] ?? 'padrao';""")
add('php','95','cylab.php.eval-user-code','r001',B,A,'A fórmula de frete enviada pelo cliente é avaliada com eval, permitindo execução de código PHP arbitrário (injeção de código, CWE-95). A correção elimina o eval e usa tabelas de frete fixas no servidor, selecionadas por chave.')
