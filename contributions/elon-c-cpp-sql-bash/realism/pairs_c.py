# Pares C originais (sintetico-cylab). Cada item: (cwe, rule, before, [(old,new)...], explanation_pt)
P=[]
P.append(("CWE-120","cylab.c.strcpy-strcat-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_MAX_LOCAL 128

static const char *config_dir(void)
{
    const char *home = getenv("HOME");
    return home ? home : "/etc";
}

static int build_config_path(char *out, const char *profile)
{
    strcpy(out, config_dir());
    strcat(out, "/.appcfg/");
    strcat(out, profile);
    strcat(out, ".ini");
    return 0;
}

static int load_profile(const char *profile)
{
    char path[PATH_MAX_LOCAL];
    char line[256];
    build_config_path(path, profile);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    while (fgets(line, sizeof line, fp))
        fputs(line, stdout);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "uso: %s <perfil>\n", argv[0]);
        return 1;
    }
    return load_profile(argv[1]) == 0 ? 0 : 2;
}
''',[('''static int build_config_path(char *out, const char *profile)
{
    strcpy(out, config_dir());
    strcat(out, "/.appcfg/");
    strcat(out, profile);
    strcat(out, ".ini");
    return 0;
}''','''static int build_config_path(char *out, size_t cap, const char *profile)
{
    int n = snprintf(out, cap, "%s/.appcfg/%s.ini", config_dir(), profile);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}'''),('''    build_config_path(path, profile);''','''    if (build_config_path(path, sizeof path, profile) != 0) {
        fprintf(stderr, "caminho muito longo\\n");
        return -1;
    }''')],
"O caminho é montado com strcpy/strcat a partir de HOME e do argumento de linha de comando num buffer fixo de 128 bytes, sem checar tamanho, causando estouro de buffer (CWE-120). A correção usa snprintf com a capacidade do destino e rejeita caminhos truncados."))

P.append(("CWE-78","cylab.c.command-injection-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void timestamp(char *buf, size_t n)
{
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, n, "%Y%m%d-%H%M%S", &tmv);
}

static int archive_dir(const char *dir, const char *dest)
{
    char ts[32];
    char cmd[512];
    timestamp(ts, sizeof ts);
    snprintf(cmd, sizeof cmd, "tar -czf %s/backup-%s.tgz %s", dest, ts, dir);
    printf("executando: %s\n", cmd);
    return system(cmd);
}

int main(int argc, char **argv)
{
    const char *dest = getenv("BACKUP_DEST");
    if (argc < 2) {
        fprintf(stderr, "uso: %s <diretorio>\n", argv[0]);
        return 1;
    }
    if (!dest)
        dest = "/var/backups";
    for (int i = 1; i < argc; i++) {
        if (archive_dir(argv[i], dest) != 0)
            fprintf(stderr, "falha ao arquivar %s\n", argv[i]);
    }
    return 0;
}
''',[('#include <time.h>','#include <time.h>\n#include <sys/types.h>\n#include <sys/wait.h>\n#include <unistd.h>'),
('''    char cmd[512];
    timestamp(ts, sizeof ts);
    snprintf(cmd, sizeof cmd, "tar -czf %s/backup-%s.tgz %s", dest, ts, dir);
    printf("executando: %s\\n", cmd);
    return system(cmd);''','''    char out[512];
    int status;
    timestamp(ts, sizeof ts);
    snprintf(out, sizeof out, "%s/backup-%s.tgz", dest, ts);
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execlp("tar", "tar", "-czf", out, "--", dir, (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;''')],
"O diretório vindo de argv e o destino vindo da variável de ambiente são interpolados numa string executada por system(), o que permite injeção de comandos do sistema operacional com ';' ou '$()' (CWE-78). A correção executa o tar via fork/execlp com argumentos separados e '--', sem passar por shell."))

P.append(("CWE-134","cylab.c.printf-nonliteral-gold",r'''#include <stdio.h>
#include <string.h>
#include <syslog.h>

struct log_entry {
    char level[16];
    char message[256];
};

static int parse_line(const char *line, struct log_entry *e)
{
    const char *sep = strchr(line, '|');
    if (!sep || (size_t)(sep - line) >= sizeof e->level)
        return -1;
    memcpy(e->level, line, (size_t)(sep - line));
    e->level[sep - line] = '\0';
    snprintf(e->message, sizeof e->message, "%s", sep + 1);
    e->message[strcspn(e->message, "\n")] = '\0';
    return 0;
}

static void emit(const struct log_entry *e)
{
    if (strcmp(e->level, "ERRO") == 0) {
        fprintf(stderr, e->message);
        syslog(LOG_ERR, e->message);
    } else {
        printf(e->message);
    }
    fputc('\n', stdout);
}

int main(void)
{
    char line[512];
    struct log_entry e;
    openlog("relay", LOG_PID, LOG_USER);
    while (fgets(line, sizeof line, stdin)) {
        if (parse_line(line, &e) == 0)
            emit(&e);
    }
    closelog();
    return 0;
}
''',[('''        fprintf(stderr, e->message);
        syslog(LOG_ERR, e->message);
    } else {
        printf(e->message);''','''        fprintf(stderr, "%s", e->message);
        syslog(LOG_ERR, "%s", e->message);
    } else {
        printf("%s", e->message);''')],
"Mensagens lidas da entrada padrão são passadas como string de formato para fprintf, syslog e printf; um atacante pode usar %n ou %x para ler ou escrever memória (CWE-134). A correção fixa o formato literal \"%s\" e passa a mensagem apenas como argumento."))

P.append(("CWE-120","cylab.c.sprintf-unbounded-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct request {
    const char *host;
    const char *path;
    const char *agent;
};

static size_t build_request(char *buf, const struct request *r)
{
    int n = sprintf(buf,
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Connection: close\r\n\r\n",
                    r->path, r->host, r->agent);
    return (size_t)n;
}

static void dump(const char *buf, size_t len)
{
    write(STDOUT_FILENO, buf, len);
}

int main(int argc, char **argv)
{
    char header[256];
    struct request r;
    if (argc < 3) {
        fprintf(stderr, "uso: %s <host> <caminho>\n", argv[0]);
        return 1;
    }
    r.host = argv[1];
    r.path = argv[2];
    r.agent = getenv("HTTP_AGENT") ? getenv("HTTP_AGENT") : "cylab/1.0";
    size_t len = build_request(header, &r);
    dump(header, len);
    return 0;
}
''',[('''static size_t build_request(char *buf, const struct request *r)
{
    int n = sprintf(buf,''','''static int build_request(char *buf, size_t cap, const struct request *r)
{
    int n = snprintf(buf, cap,'''),('''    return (size_t)n;
}''','''    if (n < 0 || (size_t)n >= cap)
        return -1;
    return n;
}'''),('''    size_t len = build_request(header, &r);
    dump(header, len);''','''    int len = build_request(header, sizeof header, &r);
    if (len < 0) {
        fprintf(stderr, "requisicao excede o buffer\\n");
        return 2;
    }
    dump(header, (size_t)len);''')],
"O cabeçalho HTTP é montado com sprintf num buffer de 256 bytes usando host, caminho (argv) e User-Agent (ambiente) sem limite, permitindo estouro de buffer (CWE-120). A correção usa snprintf com a capacidade e trata truncamento como erro."))

P.append(("CWE-242","cylab.c.gets-call-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct account {
    char owner[32];
    double balance;
};

static void show_menu(void)
{
    puts("1) depositar");
    puts("2) sacar");
    puts("3) sair");
    fputs("> ", stdout);
}

static double read_amount(void)
{
    char buf[32];
    fputs("valor: ", stdout);
    gets(buf);
    return strtod(buf, NULL);
}

int main(void)
{
    struct account acc = { "", 0.0 };
    char opt[8];
    fputs("titular: ", stdout);
    gets(acc.owner);
    for (;;) {
        show_menu();
        gets(opt);
        if (opt[0] == '1')
            acc.balance += read_amount();
        else if (opt[0] == '2')
            acc.balance -= read_amount();
        else
            break;
        printf("%s: saldo %.2f\n", acc.owner, acc.balance);
    }
    return 0;
}
''',[('''static double read_amount(void)''','''static int read_line(char *buf, size_t cap)
{
    if (!fgets(buf, (int)cap, stdin))
        return -1;
    buf[strcspn(buf, "\\n")] = '\\0';
    return 0;
}

static double read_amount(void)'''),('''    gets(buf);
    return''','''    if (read_line(buf, sizeof buf) != 0)
        return 0.0;
    return'''),('''    gets(acc.owner);''','''    if (read_line(acc.owner, sizeof acc.owner) != 0)
        return 1;'''),('''        gets(opt);''','''        if (read_line(opt, sizeof opt) != 0)
            break;''')],
"O programa usa gets() para ler titular, opção e valores, função perigosa que não conhece o tamanho do destino e permite estouro de buffer (CWE-242). A correção substitui por um helper com fgets limitado ao tamanho de cada buffer."))

P.append(("CWE-377","cylab.c.insecure-tempname-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int copy_stream(FILE *in, FILE *out)
{
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n)
            return -1;
    }
    return ferror(in) ? -1 : 0;
}

static int sort_input(void)
{
    char name[L_tmpnam];
    char cmd[256];
    if (!tmpnam(name))
        return -1;
    FILE *tmp = fopen(name, "w");
    if (!tmp)
        return -1;
    if (copy_stream(stdin, tmp) != 0) {
        fclose(tmp);
        return -1;
    }
    fclose(tmp);
    snprintf(cmd, sizeof cmd, "sort -u '%s'", name);
    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;
    copy_stream(p, stdout);
    pclose(p);
    remove(name);
    return 0;
}

int main(void)
{
    return sort_input() == 0 ? 0 : 1;
}
''',[('#include <string.h>','#include <string.h>\n#include <unistd.h>'),
('''    char name[L_tmpnam];
    char cmd[256];
    if (!tmpnam(name))
        return -1;
    FILE *tmp = fopen(name, "w");
    if (!tmp)
        return -1;''','''    char name[] = "/tmp/sortinXXXXXX";
    char cmd[256];
    int fd = mkstemp(name);
    if (fd < 0)
        return -1;
    FILE *tmp = fdopen(fd, "w");
    if (!tmp) {
        close(fd);
        unlink(name);
        return -1;
    }'''),('''    if (copy_stream(stdin, tmp) != 0) {
        fclose(tmp);
        return -1;''','''    if (copy_stream(stdin, tmp) != 0) {
        fclose(tmp);
        unlink(name);
        return -1;''')],
"tmpnam() gera um nome previsível e o arquivo é criado depois com fopen, abrindo janela de corrida para um atacante criar um link simbólico no mesmo caminho (CWE-377). A correção usa mkstemp, que cria e abre o arquivo atomicamente com permissões 0600."))

P.append(("CWE-732","cylab.c.world-writable-mode-gold",r'''#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SPOOL_DIR "/var/spool/cylab"

static int ensure_spool(void)
{
    if (mkdir(SPOOL_DIR, 0777) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }
    return 0;
}

static int write_job(const char *id, const char *payload)
{
    char path[256];
    snprintf(path, sizeof path, "%s/%s.job", SPOOL_DIR, id);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    size_t len = strlen(payload);
    ssize_t w = write(fd, payload, len);
    close(fd);
    return w == (ssize_t)len ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "uso: %s <id> <conteudo>\n", argv[0]);
        return 1;
    }
    if (ensure_spool() != 0)
        return 2;
    return write_job(argv[1], argv[2]) == 0 ? 0 : 3;
}
''',[('mkdir(SPOOL_DIR, 0777)','mkdir(SPOOL_DIR, 0700)'),('O_WRONLY | O_CREAT | O_TRUNC, 0666','O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600')],
"O diretório de spool é criado com modo 0777 e os jobs com 0666, permitindo que qualquer usuário local leia, altere ou substitua arquivos (CWE-732). A correção restringe para 0700/0600 e adiciona O_NOFOLLOW ao abrir o arquivo."))

P.append(("CWE-190","cylab.c.malloc-mul-overflow-gold",r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t id;
    uint32_t flags;
    double value;
} record_t;

static int read_u32(FILE *fp, uint32_t *out)
{
    unsigned char b[4];
    if (fread(b, 1, 4, fp) != 4)
        return -1;
    *out = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return 0;
}

static record_t *load_records(FILE *fp, uint32_t *count)
{
    uint32_t n;
    if (read_u32(fp, &n) != 0)
        return NULL;
    *count = n;
    record_t *recs = malloc(n * sizeof(record_t));
    if (!recs)
        return NULL;
    for (uint32_t i = 0; i < *count; i++) {
        if (fread(&recs[i], sizeof recs[i], 1, fp) != 1) {
            free(recs);
            return NULL;
        }
    }
    return recs;
}

int main(int argc, char **argv)
{
    uint32_t n = 0;
    FILE *fp = fopen(argc > 1 ? argv[1] : "dados.bin", "rb");
    if (!fp)
        return 1;
    record_t *r = load_records(fp, &n);
    fclose(fp);
    if (!r)
        return 2;
    printf("%u registros carregados\n", n);
    free(r);
    return 0;
}
''',[('#include <stdlib.h>','#include <stdlib.h>\n\n#define MAX_RECORDS 1000000u'),
('''    record_t *recs = malloc(n * sizeof(record_t));''','''    if (n == 0 || n > MAX_RECORDS)
        return NULL;
    record_t *recs = calloc(n, sizeof(record_t));''')],
"A contagem de registros vem do arquivo e é multiplicada por sizeof sem verificação; em plataformas de 32 bits o produto pode estourar, alocando menos memória do que o laço escreve (CWE-190). A correção limita a contagem e usa calloc, que verifica overflow na multiplicação."))

P.append(("CWE-338","cylab.c.libc-rand-key-gold",r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOKEN_BYTES 16

static const char HEX[] = "0123456789abcdef";

static void to_hex(const unsigned char *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEX[in[i] >> 4];
        out[2 * i + 1] = HEX[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static int new_session_token(char *out)
{
    unsigned char raw[TOKEN_BYTES];
    for (size_t i = 0; i < sizeof raw; i++)
        raw[i] = (unsigned char)(rand() & 0xff);
    to_hex(raw, sizeof raw, out);
    return 0;
}

int main(int argc, char **argv)
{
    char token[2 * TOKEN_BYTES + 1];
    const char *user = argc > 1 ? argv[1] : "anonimo";
    srand((unsigned)time(NULL));
    if (new_session_token(token) != 0)
        return 1;
    printf("usuario=%s sessao=%s\n", user, token);
    return 0;
}
''',[('#include <time.h>','#include <sys/random.h>'),
('''    for (size_t i = 0; i < sizeof raw; i++)
        raw[i] = (unsigned char)(rand() & 0xff);''','''    if (getrandom(raw, sizeof raw, 0) != (ssize_t)sizeof raw)
        return -1;'''),('''    srand((unsigned)time(NULL));
''','')],
"O token de sessão é derivado de rand() semeado com time(), um gerador previsível; um atacante que estime o horário reproduz os tokens (CWE-338). A correção obtém bytes do CSPRNG do kernel com getrandom()."))

P.append(("CWE-367","cylab.c.access-then-open-gold",r'''#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int stream_file(int fd)
{
    char buf[2048];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        if (write(STDOUT_FILENO, buf, (size_t)n) != n)
            return -1;
    }
    return n < 0 ? -1 : 0;
}

static int show_report(const char *path)
{
    int fd = -1;
    if (access(path, R_OK) == 0) {
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return -1;
    } else {
        fprintf(stderr, "sem permissao para %s\n", path);
        return -1;
    }
    int rc = stream_file(fd);
    close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "uso: %s <relatorio>\n", argv[0]);
        return 1;
    }
    /* binario instalado setuid para ler relatorios do grupo */
    return show_report(argv[1]) == 0 ? 0 : 2;
}
''',[('''    int fd = -1;
    if (access(path, R_OK) == 0) {
        fd = open(path, O_RDONLY);
        if (fd < 0)
            return -1;
    } else {
        fprintf(stderr, "sem permissao para %s\\n", path);
        return -1;
    }''','''    struct stat st;
    uid_t saved = geteuid();
    if (seteuid(getuid()) != 0)
        return -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (seteuid(saved) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "sem permissao para %s\\n", path);
        if (fd >= 0)
            close(fd);
        return -1;
    }''')],
"O programa setuid verifica com access() e depois abre o mesmo caminho; entre as duas chamadas o arquivo pode ser trocado por um link simbólico (TOCTOU, CWE-367). A correção abre o arquivo com os privilégios do usuário real, usa O_NOFOLLOW e valida o descritor com fstat."))

P.append(("CWE-120","cylab.c.scanf-unbounded-s-gold",r'''#include <stdio.h>
#include <string.h>

#define MAX_USERS 8

struct user {
    char login[24];
    char shell[32];
    int uid;
};

static int read_user(FILE *in, struct user *u)
{
    return fscanf(in, "%s %s %d", u->login, u->shell, &u->uid) == 3 ? 0 : -1;
}

static void print_table(const struct user *users, int n)
{
    printf("%-24s %-32s %s\n", "login", "shell", "uid");
    for (int i = 0; i < n; i++)
        printf("%-24s %-32s %d\n", users[i].login, users[i].shell, users[i].uid);
}

int main(int argc, char **argv)
{
    struct user users[MAX_USERS];
    int n = 0;
    FILE *in = argc > 1 ? fopen(argv[1], "r") : stdin;
    if (!in) {
        perror("fopen");
        return 1;
    }
    while (n < MAX_USERS && read_user(in, &users[n]) == 0)
        n++;
    if (in != stdin)
        fclose(in);
    print_table(users, n);
    return 0;
}
''',[('"%s %s %d"','"%23s %31s %d"')],
"fscanf com \"%s\" copia tokens de tamanho arbitrário para login[24] e shell[32], permitindo estouro de buffer a partir de um arquivo de entrada malicioso (CWE-120). A correção define largura máxima em cada conversão (%23s e %31s), reservando espaço para o terminador."))

P.append(("CWE-787","cylab.c.memcpy-len-from-input-gold",r'''#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_PAYLOAD 64

struct packet {
    uint8_t type;
    uint16_t len;
    const uint8_t *data;
};

struct message {
    uint8_t type;
    uint8_t body[MAX_PAYLOAD];
    size_t body_len;
};

static int parse_packet(const uint8_t *raw, size_t raw_len, struct packet *pkt)
{
    if (raw_len < 3)
        return -1;
    pkt->type = raw[0];
    pkt->len = (uint16_t)(raw[1] << 8 | raw[2]);
    pkt->data = raw + 3;
    return 0;
}

static int to_message(const struct packet *pkt, struct message *m)
{
    m->type = pkt->type;
    memcpy(m->body, pkt->data, pkt->len);
    m->body_len = pkt->len;
    return 0;
}

int main(void)
{
    uint8_t raw[1024];
    struct packet pkt;
    struct message msg;
    size_t n = fread(raw, 1, sizeof raw, stdin);
    if (parse_packet(raw, n, &pkt) != 0 || to_message(&pkt, &msg) != 0)
        return 1;
    printf("tipo=%u bytes=%zu\n", msg.type, msg.body_len);
    return 0;
}
''',[('''    if (raw_len < 3)
        return -1;
    pkt->type = raw[0];
    pkt->len = (uint16_t)(raw[1] << 8 | raw[2]);''','''    if (raw_len < 3)
        return -1;
    pkt->type = raw[0];
    pkt->len = (uint16_t)(raw[1] << 8 | raw[2]);
    if ((size_t)pkt->len > raw_len - 3)
        return -1;'''),('''    m->type = pkt->type;
    memcpy(m->body, pkt->data, pkt->len);
    m->body_len = pkt->len;''','''    size_t n = pkt->len;
    if (n > sizeof m->body)
        return -1;
    m->type = pkt->type;
    memcpy(m->body, pkt->data, n);
    m->body_len = n;''')],
"O campo de tamanho do pacote vem da rede e é usado diretamente no memcpy para um corpo de 64 bytes, permitindo escrita fora dos limites (CWE-787). A correção valida o tamanho contra os bytes recebidos e contra a capacidade do destino antes de copiar."))
