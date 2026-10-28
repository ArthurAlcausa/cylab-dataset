P=[]
P.append(("CWE-78","cylab.cpp.std-system-gold",r'''#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

struct Host {
    std::string name;
    int attempts;
};

static std::vector<Host> parseHosts(int argc, char** argv)
{
    std::vector<Host> hosts;
    for (int i = 1; i < argc; ++i)
        hosts.push_back({argv[i], 3});
    return hosts;
}

static bool probe(const Host& h)
{
    std::string cmd = "ping -c " + std::to_string(h.attempts) + " " + h.name + " > /dev/null";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

int main(int argc, char** argv)
{
    auto hosts = parseHosts(argc, argv);
    if (hosts.empty()) {
        std::cerr << "uso: " << argv[0] << " <host>...\n";
        return 1;
    }
    int down = 0;
    for (const auto& h : hosts) {
        bool ok = probe(h);
        std::cout << h.name << (ok ? " OK" : " FORA") << '\n';
        if (!ok)
            ++down;
    }
    return down == 0 ? 0 : 2;
}
''',[('#include <cstdlib>','#include <cstdlib>\n#include <fcntl.h>\n#include <sys/wait.h>\n#include <unistd.h>'),
('''    std::string cmd = "ping -c " + std::to_string(h.attempts) + " " + h.name + " > /dev/null";
    int rc = std::system(cmd.c_str());
    return rc == 0;''','''    if (h.name.empty() || h.name[0] == '-')
        return false;
    std::string count = std::to_string(h.attempts);
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
            dup2(devnull, STDOUT_FILENO);
        execlp("ping", "ping", "-c", count.c_str(), h.name.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;''')],
"O nome do host vindo de argv é concatenado num comando passado a std::system, permitindo injeção de comandos via ';' ou '$()' (CWE-78). A correção rejeita nomes iniciados por '-' e executa o ping com fork/execlp, passando o host como argumento isolado sem shell."))

P.append(("CWE-120","cylab.cpp.cstr-copy-unbounded-gold",r'''#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

struct Contact {
    char name[32];
    char email[48];
    char note[64];
};

static void fill(Contact& c, const std::string& name, const std::string& email, const std::string& note)
{
    std::strcpy(c.name, name.c_str());
    std::strcpy(c.email, email.c_str());
    std::strcpy(c.note, note.c_str());
    std::strcat(c.note, " (importado)");
}

static void print(const Contact& c)
{
    std::cout << c.name << " <" << c.email << "> " << c.note << '\n';
}

int main()
{
    std::string line;
    while (std::getline(std::cin, line)) {
        auto p1 = line.find(';');
        auto p2 = line.find(';', p1 == std::string::npos ? p1 : p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos)
            continue;
        Contact c{};
        fill(c, line.substr(0, p1), line.substr(p1 + 1, p2 - p1 - 1), line.substr(p2 + 1));
        print(c);
    }
    return 0;
}
''',[('''    std::strcpy(c.name, name.c_str());
    std::strcpy(c.email, email.c_str());
    std::strcpy(c.note, note.c_str());
    std::strcat(c.note, " (importado)");''','''    std::snprintf(c.name, sizeof c.name, "%s", name.c_str());
    std::snprintf(c.email, sizeof c.email, "%s", email.c_str());
    std::snprintf(c.note, sizeof c.note, "%s (importado)", note.c_str());''')],
"Campos de cada linha CSV são copiados com std::strcpy/std::strcat para arrays fixos sem verificar comprimento, causando estouro de buffer com entradas longas (CWE-120). A correção usa std::snprintf limitado a sizeof de cada campo, truncando com segurança."))

P.append(("CWE-134","cylab.cpp.printf-cstr-gold",r'''#include <cstdio>
#include <fstream>
#include <map>
#include <string>

class Translator {
public:
    explicit Translator(const std::string& file)
    {
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line)) {
            auto eq = line.find('=');
            if (eq != std::string::npos)
                table_[line.substr(0, eq)] = line.substr(eq + 1);
        }
    }

    std::string get(const std::string& key) const
    {
        auto it = table_.find(key);
        return it == table_.end() ? key : it->second;
    }

private:
    std::map<std::string, std::string> table_;
};

int main(int argc, char** argv)
{
    const char* lang = argc > 1 ? argv[1] : "pt_BR.lang";
    Translator tr(lang);
    std::string greeting = tr.get("greeting");
    std::string bye = tr.get("bye");
    std::printf(greeting.c_str());
    std::printf("\n");
    std::fprintf(stderr, bye.c_str());
    return 0;
}
''',[('''    std::printf(greeting.c_str());
    std::printf("\\n");
    std::fprintf(stderr, bye.c_str());''','''    std::printf("%s\\n", greeting.c_str());
    std::fprintf(stderr, "%s", bye.c_str());''')],
"Textos de tradução carregados de um arquivo indicado pelo usuário são usados como string de formato em printf/fprintf, permitindo leitura ou escrita de memória via %x/%n (CWE-134). A correção usa formato literal \"%s\" e passa o texto como argumento."))

P.append(("CWE-22","cylab.cpp.ofstream-concat-path-gold",r'''#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

static const std::string kUploadDir = "/srv/uploads/";

struct Upload {
    std::string filename;
    std::string body;
};

static bool readUpload(std::istream& in, Upload& up)
{
    if (!std::getline(in, up.filename))
        return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    up.body = ss.str();
    return !up.filename.empty();
}

static bool store(const Upload& up)
{
    std::ofstream out(kUploadDir + up.filename, std::ios::binary);
    if (!out)
        return false;
    out.write(up.body.data(), static_cast<std::streamsize>(up.body.size()));
    return static_cast<bool>(out);
}

int main()
{
    Upload up;
    if (!readUpload(std::cin, up)) {
        std::cerr << "entrada invalida\n";
        return 1;
    }
    if (!store(up)) {
        std::cerr << "falha ao gravar " << up.filename << '\n';
        return 2;
    }
    std::cout << "gravado: " << up.filename << '\n';
    return 0;
}
''',[('#include <fstream>','#include <filesystem>\n#include <fstream>'),('static const std::string kUploadDir = "/srv/uploads/";','namespace fs = std::filesystem;\nstatic const fs::path kUploadDir = "/srv/uploads";'),
('''    std::ofstream out(kUploadDir + up.filename, std::ios::binary);''','''    fs::path name = fs::path(up.filename).filename();
    if (name.empty() || name == "." || name == ".." || name.string() != up.filename)
        return false;
    fs::path target = kUploadDir / name;
    std::ofstream out(target, std::ios::binary);''')],
"O nome do arquivo enviado pelo cliente é concatenado ao diretório de upload, então valores como '../../etc/cron.d/x' gravam fora da pasta (CWE-22). A correção aceita apenas um nome simples (sem separadores, '.' ou '..') e monta o caminho com std::filesystem."))

P.append(("CWE-22","cylab.cpp.ifstream-concat-gold",r'''#include <fstream>
#include <iostream>
#include <string>

class TemplateStore {
public:
    explicit TemplateStore(std::string root) : root_(std::move(root)) {}

    bool render(const std::string& name, const std::string& user, std::ostream& out) const
    {
        std::ifstream in(root_ + name);
        if (!in)
            return false;
        std::string line;
        while (std::getline(in, line)) {
            auto pos = line.find("{{user}}");
            if (pos != std::string::npos)
                line.replace(pos, 8, user);
            out << line << '\n';
        }
        return true;
    }

private:
    std::string root_;
};

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "uso: " << argv[0] << " <template> <usuario>\n";
        return 1;
    }
    TemplateStore store("/opt/app/templates/");
    if (!store.render(argv[1], argv[2], std::cout)) {
        std::cerr << "template nao encontrado\n";
        return 2;
    }
    return 0;
}
''',[('#include <fstream>','#include <filesystem>\n#include <fstream>'),
('''        std::ifstream in(root_ + name);
        if (!in)
            return false;''','''        namespace fs = std::filesystem;
        std::error_code ec;
        fs::path base = fs::weakly_canonical(root_, ec);
        fs::path full = fs::weakly_canonical(fs::path(root_) / name, ec);
        if (ec)
            return false;
        auto rel = full.lexically_relative(base);
        if (rel.empty() || *rel.begin() == "..")
            return false;
        std::ifstream in(full);
        if (!in)
            return false;''')],
"O nome do template vem de argv e é concatenado à raiz, permitindo ler arquivos arbitrários com '../' (CWE-22). A correção canonicaliza o caminho e confirma que ele permanece dentro do diretório de templates antes de abrir."))

P.append(("CWE-190","cylab.cpp.new-array-mul-gold",r'''#include <cstdint>
#include <fstream>
#include <iostream>

struct Pixel {
    std::uint8_t r, g, b;
};

struct Header {
    std::uint32_t width;
    std::uint32_t height;
};

static bool readHeader(std::istream& in, Header& h)
{
    in.read(reinterpret_cast<char*>(&h), sizeof h);
    return static_cast<bool>(in);
}

static Pixel* loadImage(std::istream& in, const Header& h)
{
    Pixel* px = new Pixel[h.width * h.height];
    in.read(reinterpret_cast<char*>(px), static_cast<std::streamsize>(sizeof(Pixel)) * h.width * h.height);
    return px;
}

int main(int argc, char** argv)
{
    std::ifstream in(argc > 1 ? argv[1] : "img.raw", std::ios::binary);
    Header h{};
    if (!readHeader(in, h)) {
        std::cerr << "cabecalho invalido\n";
        return 1;
    }
    Pixel* px = loadImage(in, h);
    unsigned long sum = 0;
    for (std::uint64_t i = 0; i < std::uint64_t(h.width) * h.height; ++i)
        sum += px[i].r;
    std::cout << "media R: " << (h.width ? sum / (std::uint64_t(h.width) * h.height) : 0) << '\n';
    delete[] px;
    return 0;
}
''',[('#include <iostream>','#include <iostream>\n#include <vector>'),
('''static Pixel* loadImage(std::istream& in, const Header& h)
{
    Pixel* px = new Pixel[h.width * h.height];
    in.read(reinterpret_cast<char*>(px), static_cast<std::streamsize>(sizeof(Pixel)) * h.width * h.height);
    return px;
}''','''static bool loadImage(std::istream& in, const Header& h, std::vector<Pixel>& px)
{
    constexpr std::uint64_t kMaxPixels = 64ull * 1024 * 1024;
    std::uint64_t count = std::uint64_t(h.width) * h.height;
    if (count == 0 || count > kMaxPixels)
        return false;
    px.resize(static_cast<std::size_t>(count));
    in.read(reinterpret_cast<char*>(px.data()), static_cast<std::streamsize>(count * sizeof(Pixel)));
    return static_cast<bool>(in);
}'''),('''    Pixel* px = loadImage(in, h);''','''    std::vector<Pixel> px;
    if (!loadImage(in, h, px)) {
        std::cerr << "dimensoes invalidas\\n";
        return 2;
    }'''),('''    delete[] px;
''','')],
"Largura e altura vêm do arquivo e são multiplicadas em 32 bits dentro de new[], podendo dar overflow e alocar um array pequeno que depois é lido e percorrido com o tamanho real (CWE-190). A correção calcula em 64 bits, impõe limite máximo e usa std::vector."))

P.append(("CWE-798","cylab.cpp.hardcoded-key-literal-gold",r'''#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

namespace billing {

const std::string api_key = "sk_live_9f8a7c6b5d4e3f21";
const std::string endpoint = "https://api.pagamentos.example/v1/charges";

struct Charge {
    std::string customer;
    long cents;
};

std::map<std::string, std::string> buildHeaders()
{
    return {
        {"Authorization", "Bearer " + api_key},
        {"Content-Type", "application/json"},
    };
}

std::string toJson(const Charge& c)
{
    return "{\"customer\":\"" + c.customer + "\",\"amount\":" + std::to_string(c.cents) + "}";
}

}  // namespace billing

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "uso: " << argv[0] << " <cliente> <centavos>\n";
        return 1;
    }
    billing::Charge c{argv[1], std::atol(argv[2])};
    for (const auto& kv : billing::buildHeaders())
        std::cout << kv.first << ": " << (kv.first == "Authorization" ? "***" : kv.second) << '\n';
    std::cout << "POST " << billing::endpoint << '\n' << billing::toJson(c) << '\n';
    return 0;
}
''',[('#include <string>','#include <stdexcept>\n#include <string>'),
('''const std::string api_key = "sk_live_9f8a7c6b5d4e3f21";''','''std::string loadApiKey()
{
    const char* v = std::getenv("BILLING_API_KEY");
    if (!v || !*v)
        throw std::runtime_error("BILLING_API_KEY ausente");
    return v;
}'''),('''{"Authorization", "Bearer " + api_key},''','''{"Authorization", "Bearer " + loadApiKey()},''')],
"A chave de API de produção está embutida no código-fonte, ficando exposta a quem acessa o binário ou o repositório e impossível de rotacionar sem recompilar (CWE-798). A correção lê a chave da variável de ambiente BILLING_API_KEY e falha se ela não existir."))

P.append(("CWE-327","cylab.cpp.openssl-weak-algo-gold",r'''#include <openssl/evp.h>
#include <iostream>
#include <string>
#include <vector>

class FileCipher {
public:
    FileCipher(const unsigned char* key, const unsigned char* iv) : key_(key), iv_(iv) {}

    std::vector<unsigned char> encrypt(const std::string& plain) const
    {
        std::vector<unsigned char> out(plain.size() + 32);
        int len = 0, total = 0;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, key_, iv_);
        EVP_EncryptUpdate(ctx, out.data(), &len,
                          reinterpret_cast<const unsigned char*>(plain.data()), static_cast<int>(plain.size()));
        total = len;
        EVP_EncryptFinal_ex(ctx, out.data() + total, &len);
        total += len;
        EVP_CIPHER_CTX_free(ctx);
        out.resize(static_cast<std::size_t>(total));
        return out;
    }

private:
    const unsigned char* key_;
    const unsigned char* iv_;
};

int main()
{
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    std::string data((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    FileCipher fc(key, iv);
    auto enc = fc.encrypt(data);
    std::cout.write(reinterpret_cast<const char*>(enc.data()), static_cast<std::streamsize>(enc.size()));
    return 0;
}
''',[('#include <openssl/evp.h>','#include <openssl/evp.h>\n#include <openssl/rand.h>'),
('''        EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, key_, iv_);''','''        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_, iv_);'''),
('''        total += len;
        EVP_CIPHER_CTX_free(ctx);''','''        total += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + total);
        total += 16;
        EVP_CIPHER_CTX_free(ctx);'''),
('''    unsigned char iv[16] = {0};''','''    unsigned char iv[12];
    if (RAND_bytes(key, sizeof key) != 1 || RAND_bytes(iv, sizeof iv) != 1)
        return 1;''')],
"A cifragem usa 3DES em modo CBC (EVP_des_ede3_cbc), algoritmo obsoleto com bloco de 64 bits e sem autenticação, além de chave e IV fixos (CWE-327). A correção adota AES-256-GCM com IV de 12 bytes aleatório, anexa a tag de autenticação e gera a chave com RAND_bytes."))

P.append(("CWE-338","cylab.cpp.rand-token-gold",r'''#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <unordered_map>

class ResetService {
public:
    ResetService() { std::srand(static_cast<unsigned>(std::time(nullptr))); }

    std::string issue(const std::string& email)
    {
        static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        std::string code;
        for (int i = 0; i < 10; ++i)
            code += alphabet[std::rand() % (sizeof(alphabet) - 1)];
        pending_[email] = code;
        return code;
    }

    bool redeem(const std::string& email, const std::string& code)
    {
        auto it = pending_.find(email);
        if (it == pending_.end() || it->second != code)
            return false;
        pending_.erase(it);
        return true;
    }

private:
    std::unordered_map<std::string, std::string> pending_;
};

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "uso: " << argv[0] << " <email>\n";
        return 1;
    }
    ResetService svc;
    std::string code = svc.issue(argv[1]);
    std::cout << "codigo enviado para " << argv[1] << ": " << code << '\n';
    return 0;
}
''',[('#include <cstdlib>\n#include <ctime>\n','#include <random>\n'),
('''    ResetService() { std::srand(static_cast<unsigned>(std::time(nullptr))); }''','''    ResetService() = default;'''),
('''        std::string code;
        for (int i = 0; i < 10; ++i)
            code += alphabet[std::rand() % (sizeof(alphabet) - 1)];''','''        std::random_device rd;
        std::uniform_int_distribution<std::size_t> pick(0, sizeof(alphabet) - 2);
        std::string code;
        for (int i = 0; i < 10; ++i)
            code += alphabet[pick(rd)];''')],
"Códigos de redefinição de senha são gerados com std::rand() semeado pelo horário, tornando-os previsíveis para um atacante (CWE-338). A correção usa std::random_device (fonte do SO) com distribuição uniforme, eliminando também o viés do módulo."))

P.append(("CWE-416","cylab.cpp.dangling-cstr-gold",r'''#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

static std::string makeLogPath(const std::string& service, int day)
{
    return "/var/log/" + service + "/" + std::to_string(day) + ".log";
}

static std::size_t countLines(const char* path)
{
    FILE* fp = std::fopen(path, "r");
    if (!fp)
        return 0;
    std::size_t n = 0;
    int ch;
    while ((ch = std::fgetc(fp)) != EOF)
        if (ch == '\n')
            ++n;
    std::fclose(fp);
    return n;
}

int main(int argc, char** argv)
{
    std::vector<std::string> services(argv + 1, argv + argc);
    if (services.empty())
        services.push_back("nginx");
    for (const auto& svc : services) {
        for (int day = 1; day <= 7; ++day) {
            const char* path = makeLogPath(svc, day).c_str();
            std::size_t lines = countLines(path);
            if (lines)
                std::cout << svc << " dia " << day << ": " << lines << " linhas\n";
        }
    }
    return 0;
}
''',[('''            const char* path = makeLogPath(svc, day).c_str();
            std::size_t lines = countLines(path);''','''            const std::string path = makeLogPath(svc, day);
            std::size_t lines = countLines(path.c_str());''')],
"O ponteiro retornado por c_str() de uma std::string temporária fica inválido ao fim da expressão; usá-lo depois em countLines é uso após liberação (CWE-416). A correção guarda a string numa variável local e só chama c_str() enquanto ela está viva."))

P.append(("CWE-120","cylab.cpp.memcpy-string-size-gold",r'''#include <cstring>
#include <iostream>
#include <string>

#pragma pack(push, 1)
struct Frame {
    unsigned char opcode;
    char topic[32];
    char payload[128];
};
#pragma pack(pop)

static Frame encode(const std::string& topic, const std::string& payload)
{
    Frame f{};
    f.opcode = 0x10;
    std::memcpy(f.topic, topic.data(), topic.size());
    std::memcpy(f.payload, payload.data(), payload.size());
    return f;
}

static void send(const Frame& f)
{
    std::cout.write(reinterpret_cast<const char*>(&f), sizeof f);
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "uso: " << argv[0] << " <topico>  (payload via stdin)\n";
        return 1;
    }
    std::string topic = argv[1];
    std::string payload;
    std::getline(std::cin, payload);
    Frame f = encode(topic, payload);
    send(f);
    return 0;
}
''',[('#include <cstring>','#include <algorithm>\n#include <cstring>'),
('''    std::memcpy(f.topic, topic.data(), topic.size());
    std::memcpy(f.payload, payload.data(), payload.size());''','''    std::size_t nt = std::min(topic.size(), sizeof f.topic - 1);
    std::size_t np = std::min(payload.size(), sizeof f.payload - 1);
    std::memcpy(f.topic, topic.data(), nt);
    std::memcpy(f.payload, payload.data(), np);''')],
"O memcpy usa o tamanho da std::string de entrada (argv e stdin) para copiar em campos fixos de 32 e 128 bytes, estourando o frame com dados longos (CWE-120). A correção limita a cópia ao menor valor entre o tamanho da string e a capacidade do campo, preservando o terminador."))

P.append(("CWE-134","cylab.cpp.fmt-cstr-sink-gold",r'''#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <syslog.h>

class AuditLog {
public:
    explicit AuditLog(const char* ident) { openlog(ident, LOG_PID, LOG_AUTH); }
    ~AuditLog() { closelog(); }

    void record(const std::string& user, const std::string& action)
    {
        std::string line = "user=" + user + " action=" + action;
        char buf[256];
        std::snprintf(buf, sizeof buf, line.c_str());
        std::cout << buf << '\n';
        syslog(LOG_NOTICE, line.c_str());
    }
};

static std::string currentUser()
{
    const char* u = std::getenv("USER");
    return u ? u : "desconhecido";
}

int main(int argc, char** argv)
{
    AuditLog log("cylab-audit");
    std::string action = argc > 1 ? argv[1] : "noop";
    for (int i = 2; i < argc; ++i) {
        action += ' ';
        action += argv[i];
    }
    log.record(currentUser(), action);
    return 0;
}
''',[('''        std::snprintf(buf, sizeof buf, line.c_str());''','''        std::snprintf(buf, sizeof buf, "%s", line.c_str());'''),('''        syslog(LOG_NOTICE, line.c_str());''','''        syslog(LOG_NOTICE, "%s", line.c_str());''')],
"A linha de auditoria contém USER e argumentos do usuário e é usada como string de formato em snprintf e syslog, permitindo %n/%x controlados pelo atacante (CWE-134). A correção passa o texto como argumento de um formato literal \"%s\"."))
