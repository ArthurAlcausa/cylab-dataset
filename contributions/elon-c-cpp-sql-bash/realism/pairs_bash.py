P=[]
P.append(("CWE-78","cylab.bash.eval-variable-gold",r'''#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="${LOG_DIR:-/var/log/app}"

usage() {
    echo "uso: $0 <padrao> [dias] [ordenacao]" >&2
    exit 1
}

build_filter() {
    local pattern="$1" days="$2"
    echo "find '$LOG_DIR' -name '*.log' -mtime -$days -exec grep -h '$pattern' {} +"
}

main() {
    [[ $# -ge 1 ]] || usage
    local pattern="$1"
    local days="${2:-7}"
    local sort_opt="${3:-}"
    local cmd
    cmd="$(build_filter "$pattern" "$days")"
    if [[ -n "$sort_opt" ]]; then
        cmd="$cmd | sort $sort_opt"
    fi
    echo "executando busca em $LOG_DIR" >&2
    eval "$cmd" | head -n 200
}

main "$@"
''',[('''build_filter() {
    local pattern="$1" days="$2"
    echo "find '$LOG_DIR' -name '*.log' -mtime -$days -exec grep -h '$pattern' {} +"
}''','''search_logs() {
    local pattern="$1" days="$2"
    find "$LOG_DIR" -name '*.log' -mtime "-$days" -exec grep -h -e "$pattern" -- {} +
}'''),('''    local cmd
    cmd="$(build_filter "$pattern" "$days")"
    if [[ -n "$sort_opt" ]]; then
        cmd="$cmd | sort $sort_opt"
    fi
    echo "executando busca em $LOG_DIR" >&2
    eval "$cmd" | head -n 200''','''    [[ "$days" =~ ^[0-9]+$ ]] || usage
    echo "executando busca em $LOG_DIR" >&2
    case "$sort_opt" in
        "") search_logs "$pattern" "$days" | head -n 200 ;;
        -r|-n|-u) search_logs "$pattern" "$days" | sort "$sort_opt" | head -n 200 ;;
        *) usage ;;
    esac''')],
"O script monta uma linha de comando como texto com padrão, dias e opção de ordenação vindos de argv e a executa com eval, então aspas ou ';' no padrão injetam comandos (CWE-78). A correção chama find/grep diretamente com argumentos entre aspas, valida dias como número e aceita apenas opções de sort conhecidas."))

P.append(("CWE-494","cylab.bash.curl-pipe-shell-gold",r'''#!/usr/bin/env bash
set -euo pipefail

TOOL_VERSION="${TOOL_VERSION:-2.4.1}"
INSTALL_URL="https://get.ferramenta.example/install.sh"
PREFIX="${PREFIX:-/usr/local}"

log() { printf '[setup] %s\n' "$*" >&2; }

check_deps() {
    for bin in curl tar; do
        command -v "$bin" >/dev/null || { log "faltando: $bin"; exit 1; }
    done
}

install_tool() {
    log "instalando ferramenta $TOOL_VERSION em $PREFIX"
    curl -fsSL "$INSTALL_URL?v=$TOOL_VERSION" | sudo bash -s -- --prefix "$PREFIX"
}

post_install() {
    if command -v ferramenta >/dev/null; then
        log "versao instalada: $(ferramenta --version)"
    else
        log "instalacao nao encontrada no PATH"
        return 1
    fi
}

check_deps
install_tool
post_install
log "concluido"
''',[('''PREFIX="${PREFIX:-/usr/local}"''','''INSTALL_SHA256="${INSTALL_SHA256:?defina o sha256 publicado do instalador}"
PREFIX="${PREFIX:-/usr/local}"'''),('''    for bin in curl tar; do''','''    for bin in curl tar sha256sum; do'''),
('''    log "instalando ferramenta $TOOL_VERSION em $PREFIX"
    curl -fsSL "$INSTALL_URL?v=$TOOL_VERSION" | sudo bash -s -- --prefix "$PREFIX"''','''    local tmp
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' RETURN
    log "baixando instalador $TOOL_VERSION"
    curl -fsSL --proto '=https' -o "$tmp" "$INSTALL_URL?v=$TOOL_VERSION"
    echo "$INSTALL_SHA256  $tmp" | sha256sum -c - >/dev/null || { log "checksum invalido"; return 1; }
    log "instalando em $PREFIX"
    sudo bash "$tmp" --prefix "$PREFIX"''')],
"O instalador é baixado e enviado direto para 'sudo bash' sem nenhuma verificação de integridade; um servidor comprometido ou MITM executa código como root (CWE-494). A correção salva o script em arquivo temporário, confere o SHA-256 publicado e só então o executa."))

P.append(("CWE-377","cylab.bash.predictable-tmp-gold",r'''#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${1:-inventario}"
REPORT_TO="${REPORT_TO:-ops@empresa.example}"

collect_sizes() {
    psql -At -d "$DB_NAME" -c "select relname, pg_total_relation_size(oid) from pg_class where relkind='r' order by 2 desc limit 20"
}

format_report() {
    awk -F'|' '{ printf "%-40s %10.1f MB\n", $1, $2/1048576 }'
}

main() {
    echo "coletando tamanhos de $DB_NAME" >&2
    collect_sizes > /tmp/db_sizes.txt
    format_report < /tmp/db_sizes.txt > /tmp/db_report_$$.txt
    {
        echo "Relatorio de tabelas - $DB_NAME - $(date +%F)"
        echo
        cat /tmp/db_report_$$.txt
    } | mail -s "tamanho das tabelas $DB_NAME" "$REPORT_TO"
    rm -f /tmp/db_sizes.txt /tmp/db_report_$$.txt
}

main
''',[('''    echo "coletando tamanhos de $DB_NAME" >&2
    collect_sizes > /tmp/db_sizes.txt
    format_report < /tmp/db_sizes.txt > /tmp/db_report_$$.txt''','''    local workdir
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT
    echo "coletando tamanhos de $DB_NAME" >&2
    collect_sizes > "$workdir/sizes.txt"
    format_report < "$workdir/sizes.txt" > "$workdir/report.txt"'''),('''        cat /tmp/db_report_$$.txt''','''        cat "$workdir/report.txt"'''),('''    rm -f /tmp/db_sizes.txt /tmp/db_report_$$.txt
''','')],
"Os arquivos intermediários usam nomes fixos ou baseados no PID em /tmp, que outro usuário local pode prever e pré-criar como link simbólico para sobrescrever arquivos (CWE-377). A correção cria um diretório privado com mktemp -d e o remove via trap."))

P.append(("CWE-732","cylab.bash.chmod-world-writable-gold",r'''#!/usr/bin/env bash
set -euo pipefail

APP_USER="${APP_USER:-www-data}"
RELEASE_DIR="/srv/app/releases/$(date +%Y%m%d%H%M%S)"
SHARED_DIR="/srv/app/shared"
ARTIFACT="${1:?uso: deploy.sh <artefato.tgz>}"

prepare_dirs() {
    mkdir -p "$RELEASE_DIR" "$SHARED_DIR/uploads" "$SHARED_DIR/cache"
    chmod -R 777 "$SHARED_DIR"
}

unpack() {
    tar -xzf "$ARTIFACT" -C "$RELEASE_DIR"
    ln -sfn "$SHARED_DIR/uploads" "$RELEASE_DIR/public/uploads"
    ln -sfn "$SHARED_DIR/cache" "$RELEASE_DIR/var/cache"
}

activate() {
    ln -sfn "$RELEASE_DIR" /srv/app/current
    systemctl reload php-fpm
}

echo "deploy de $ARTIFACT"
prepare_dirs
unpack
activate
echo "release ativa: $RELEASE_DIR"
''',[('''    chmod -R 777 "$SHARED_DIR"''','''    chown -R "root:$APP_USER" "$SHARED_DIR"
    chmod 750 "$SHARED_DIR"
    chmod 770 "$SHARED_DIR/uploads" "$SHARED_DIR/cache"''')],
"O diretório compartilhado da aplicação recebe chmod -R 777, permitindo que qualquer usuário local altere uploads e cache, podendo plantar código executado pelo PHP (CWE-732). A correção atribui dono root e grupo do serviço, com permissões 750/770."))

P.append(("CWE-798","cylab.bash.hardcoded-secret-var-gold",r'''#!/usr/bin/env bash
set -euo pipefail

S3_BUCKET="s3://backups-empresa/postgres"
export AWS_ACCESS_KEY_ID="AKIAEXEMPLO1234"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMIexemploSECRETkey9"
PGPASSWORD_DB="Pg#Prod2026!"

dump_db() {
    local db="$1" out="$2"
    PGPASSWORD="$PGPASSWORD_DB" pg_dump -h db.interno -U backup -Fc "$db" > "$out"
}

upload() {
    local file="$1"
    aws s3 cp "$file" "$S3_BUCKET/$(basename "$file")" --only-show-errors
}

main() {
    local workdir db file
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT
    for db in "$@"; do
        file="$workdir/${db}-$(date +%F).dump"
        echo "backup de $db"
        dump_db "$db" "$file"
        upload "$file"
    done
}

main "${@:-app}"
''',[('''export AWS_ACCESS_KEY_ID="AKIAEXEMPLO1234"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMIexemploSECRETkey9"
PGPASSWORD_DB="Pg#Prod2026!"''','''# credenciais AWS via perfil/instance role; senha do banco via ~/.pgpass (0600)
export AWS_PROFILE="${AWS_PROFILE:-backup}"'''),('''    PGPASSWORD="$PGPASSWORD_DB" pg_dump''','''    pg_dump''')],
"Chaves AWS e a senha do PostgreSQL estão escritas em texto claro no script, vazando para qualquer pessoa com acesso ao repositório ou ao servidor (CWE-798). A correção remove os segredos do código e usa perfil AWS/role da instância e o arquivo ~/.pgpass com permissão restrita."))

P.append(("CWE-214","cylab.bash.password-on-cmdline-gold",r'''#!/usr/bin/env bash
set -euo pipefail

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_USER="${DB_USER:-backup}"
DB_PASS="$(cat /etc/backup/db.pass)"
DEST="${DEST:-/var/backups/mysql}"
KEEP_DAYS=14

list_databases() {
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -N -e 'SHOW DATABASES' \
        | grep -Ev '^(information_schema|performance_schema|sys)$'
}

dump_one() {
    local db="$1"
    mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" --single-transaction "$db" \
        | gzip > "$DEST/${db}-$(date +%F).sql.gz"
}

rotate() {
    find "$DEST" -name '*.sql.gz' -mtime +"$KEEP_DAYS" -delete
}

mkdir -p "$DEST"
for db in $(list_databases); do
    echo "dump: $db"
    dump_one "$db"
done
rotate
''',[('''DB_PASS="$(cat /etc/backup/db.pass)"''','''DEFAULTS_FILE="${DEFAULTS_FILE:-/etc/backup/my.cnf}"  # [client] password=..., modo 0600'''),
('''    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -N''','''    mysql --defaults-extra-file="$DEFAULTS_FILE" -h "$DB_HOST" -u "$DB_USER" -N'''),
('''    mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" --single-transaction''','''    mysqldump --defaults-extra-file="$DEFAULTS_FILE" -h "$DB_HOST" -u "$DB_USER" --single-transaction'''),
('''mkdir -p "$DEST"''','''[[ "$(stat -c %a "$DEFAULTS_FILE")" == 600 ]] || { echo "permissao insegura em $DEFAULTS_FILE" >&2; exit 1; }
mkdir -p "$DEST"''')],
"A senha do MySQL é passada com -p na linha de comando de mysql e mysqldump, ficando visível para qualquer usuário via ps ou /proc/<pid>/cmdline (CWE-214). A correção usa --defaults-extra-file com um arquivo de opções 0600, verificado antes da execução."))

P.append(("CWE-295","cylab.bash.tls-insecure-flag-gold",r'''#!/usr/bin/env bash
set -euo pipefail

API="${API:-https://monitor.interno.example/api/v2}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/monitor/token}"
INTERVAL="${INTERVAL:-60}"

api_get() {
    local path="$1"
    curl -sS -k -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "$API$path"
}

check_alerts() {
    local body count
    body="$(api_get /alerts?state=firing)"
    count="$(jq 'length' <<<"$body")"
    if (( count > 0 )); then
        jq -r '.[] | "\(.severity)\t\(.name)\t\(.since)"' <<<"$body"
    fi
    return "$(( count > 0 ))"
}

main() {
    while true; do
        if ! check_alerts; then
            notify-send "monitor" "alertas ativos" || true
        fi
        sleep "$INTERVAL"
    done
}

main
''',[('''TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/monitor/token}"''','''TOKEN_FILE="${TOKEN_FILE:-$HOME/.config/monitor/token}"
CA_BUNDLE="${CA_BUNDLE:-/etc/ssl/certs/ca-interna.pem}"'''),('''    curl -sS -k -H''','''    curl -sS --cacert "$CA_BUNDLE" -H''')],
"O curl é chamado com -k, desativando a validação do certificado TLS, de modo que um atacante na rede pode se passar pela API e capturar o token Bearer (CWE-295). A correção remove -k e confia explicitamente na CA interna via --cacert."))

P.append(("CWE-78","cylab.bash.sh-c-interpolated-gold",r'''#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_ROOT="/mnt/arquivo"
RUN_AS="${RUN_AS:-arquivista}"

usage() {
    echo "uso: $0 <projeto> <rotulo>" >&2
    exit 1
}

archive_project() {
    local project="$1" label="$2"
    local src="/srv/projetos/$project"
    local dest="$ARCHIVE_ROOT/$project-$label.tar.zst"
    [[ -d "$src" ]] || { echo "projeto inexistente: $project" >&2; return 1; }
    sudo -u "$RUN_AS" sh -c "tar --zstd -cf $dest -C /srv/projetos $project && sha256sum $dest > $dest.sha256"
}

main() {
    [[ $# -eq 2 ]] || usage
    archive_project "$1" "$2"
    echo "arquivado: $1 ($2)"
}

main "$@"
''',[('''    [[ -d "$src" ]] || { echo "projeto inexistente: $project" >&2; return 1; }
    sudo -u "$RUN_AS" sh -c "tar --zstd -cf $dest -C /srv/projetos $project && sha256sum $dest > $dest.sha256"''','''    [[ "$project" =~ ^[A-Za-z0-9._-]+$ && "$label" =~ ^[A-Za-z0-9._-]+$ ]] || usage
    [[ -d "$src" ]] || { echo "projeto inexistente: $project" >&2; return 1; }
    sudo -u "$RUN_AS" tar --zstd -cf "$dest" -C /srv/projetos -- "$project"
    sha256sum "$dest" | sudo -u "$RUN_AS" tee "$dest.sha256" >/dev/null''')],
"Projeto e rótulo vindos de argv são interpolados numa string passada a 'sh -c' executada como outro usuário, permitindo injeção de comandos com ';' ou '$()' (CWE-78). A correção valida os nomes com lista de caracteres permitidos e chama tar e sha256sum diretamente com argumentos entre aspas."))

P.append(("CWE-494","cylab.bash.source-remote-script-gold",r'''#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="${1:-staging}"
LIB_URL="https://raw.repo.example/infra/lib/${ENV_NAME}.sh"

# carrega funcoes comuns (deploy_service, healthcheck, rollback)
source <(curl -fsSL "$LIB_URL")

SERVICES=(api worker scheduler)

deploy_all() {
    local svc
    for svc in "${SERVICES[@]}"; do
        echo "==> $svc"
        if ! deploy_service "$svc" "$ENV_NAME"; then
            echo "falha em $svc, revertendo" >&2
            rollback "$svc" "$ENV_NAME"
            return 1
        fi
        healthcheck "$svc" "$ENV_NAME"
    done
}

case "$ENV_NAME" in
    staging|production) ;;
    *) echo "ambiente invalido: $ENV_NAME" >&2; exit 1 ;;
esac

deploy_all
echo "deploy concluido em $ENV_NAME"
''',[('''LIB_URL="https://raw.repo.example/infra/lib/${ENV_NAME}.sh"

# carrega funcoes comuns (deploy_service, healthcheck, rollback)
source <(curl -fsSL "$LIB_URL")
''','''LIB_DIR="${LIB_DIR:-/opt/infra/lib}"   # versionado e instalado pelo pacote infra-lib
LIB_FILE="$LIB_DIR/${ENV_NAME}.sh"
'''),('''    *) echo "ambiente invalido: $ENV_NAME" >&2; exit 1 ;;
esac
''','''    *) echo "ambiente invalido: $ENV_NAME" >&2; exit 1 ;;
esac

[[ -f "$LIB_FILE" && ! -L "$LIB_FILE" && "$(stat -c %U "$LIB_FILE")" == root ]] \\
    || { echo "biblioteca ausente ou nao confiavel: $LIB_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$LIB_FILE"
''')],
"O script executa via source um arquivo baixado na hora da internet, sem verificar integridade, e ainda antes de validar o ambiente; quem controlar o repositório ou a rede executa código no pipeline (CWE-494). A correção carrega a biblioteca de um caminho local instalado por pacote, conferindo dono root e que não é link simbólico."))

P.append(("CWE-312","cylab.bash.secret-echo-to-file-gold",r'''#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/srv/app}"
VAULT_PATH="secret/data/app/prod"

fetch() {
    vault kv get -field="$1" "$VAULT_PATH"
}

render_env() {
    local DB_PASSWORD API_TOKEN
    DB_PASSWORD="$(fetch db_password)"
    API_TOKEN="$(fetch api_token)"
    echo "APP_ENV=production" > "$APP_DIR/.env"
    echo "DB_HOST=db.interno" >> "$APP_DIR/.env"
    echo "DB_PASSWORD=$DB_PASSWORD" >> "$APP_DIR/.env"
    echo "API_TOKEN=$API_TOKEN" >> "$APP_DIR/.env"
}

restart_app() {
    systemctl restart app.service
    systemctl --no-pager status app.service | head -n 5
}

main() {
    vault token lookup >/dev/null || { echo "faça login no vault" >&2; exit 1; }
    render_env
    restart_app
}

main
''',[('''    echo "APP_ENV=production" > "$APP_DIR/.env"
    echo "DB_HOST=db.interno" >> "$APP_DIR/.env"
    echo "DB_PASSWORD=$DB_PASSWORD" >> "$APP_DIR/.env"
    echo "API_TOKEN=$API_TOKEN" >> "$APP_DIR/.env"''','''    local tmp
    tmp="$(umask 077; mktemp "$APP_DIR/.env.XXXXXX")"
    printf '%s\\n' "APP_ENV=production" "DB_HOST=db.interno" \\
        "DB_PASSWORD=${DB_PASSWORD}" "API_TOKEN=${API_TOKEN}" > "$tmp"
    chown root:app "$tmp"
    chmod 640 "$tmp"
    mv -f "$tmp" "$APP_DIR/.env"''')],
"Segredos obtidos do Vault são gravados com echo em .env criado com a umask padrão (normalmente legível por todos), deixando senha e token em texto claro acessíveis a outros usuários (CWE-312). A correção grava num arquivo temporário criado com umask 077, ajusta dono e modo 640 e o move atomicamente."))

P.append(("CWE-250","cylab.bash.sudoers-nopasswd-all-gold",r'''#!/usr/bin/env bash
set -euo pipefail

DEPLOY_USER="${1:?uso: $0 <usuario-deploy>}"
SUDOERS_FILE="/etc/sudoers.d/90-deploy"

create_user() {
    if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$DEPLOY_USER"
        echo "usuario $DEPLOY_USER criado"
    fi
}

install_key() {
    local home
    home="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
    install -d -m 700 -o "$DEPLOY_USER" "$home/.ssh"
    install -m 600 -o "$DEPLOY_USER" /root/deploy_key.pub "$home/.ssh/authorized_keys"
}

grant_sudo() {
    echo "$DEPLOY_USER ALL=(ALL) NOPASSWD: ALL" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE"
}

[[ $EUID -eq 0 ]] || { echo "execute como root" >&2; exit 1; }
create_user
install_key
grant_sudo
echo "provisionamento concluido"
''',[('''    echo "$DEPLOY_USER ALL=(ALL) NOPASSWD: ALL" > "$SUDOERS_FILE"''','''    {
        echo "Cmnd_Alias DEPLOY_CMDS = /usr/bin/systemctl restart app.service, /usr/bin/systemctl reload nginx"
        echo "$DEPLOY_USER ALL=(root) NOPASSWD: DEPLOY_CMDS"
    } > "$SUDOERS_FILE"''')],
"O usuário de deploy, acessível por chave SSH automatizada, recebe sudo irrestrito sem senha (NOPASSWD: ALL), de modo que o comprometimento da chave dá root total (CWE-250). A correção limita o sudo a uma lista explícita de comandos necessários ao deploy."))

P.append(("CWE-88","cylab.bash.unquoted-rm-var-gold",r'''#!/usr/bin/env bash
set -uo pipefail

BUILD_ROOT="${BUILD_ROOT:-}"
KEEP="${KEEP:-3}"

list_old_builds() {
    ls -1dt "$BUILD_ROOT"/build-* 2>/dev/null | tail -n +"$((KEEP + 1))"
}

clean_workspace() {
    local ws="$1"
    echo "limpando $ws"
    rm -rf $ws/
}

prune() {
    local dir
    for dir in $(list_old_builds); do
        clean_workspace "$dir"
    done
}

main() {
    local target="${1:-}"
    if [[ -n "$target" ]]; then
        clean_workspace "$BUILD_ROOT/$target"
    else
        prune
    fi
    echo "espaco livre: $(df -h "${BUILD_ROOT:-/}" | awk 'NR==2{print $4}')"
}

main "$@"
''',[('''BUILD_ROOT="${BUILD_ROOT:-}"''','''BUILD_ROOT="${BUILD_ROOT:?defina BUILD_ROOT}"'''),
('''    local ws="$1"
    echo "limpando $ws"
    rm -rf $ws/''','''    local ws="$1"
    [[ -n "$ws" && "$ws" == "$BUILD_ROOT"/build-* && -d "$ws" && ! -L "$ws" ]] \\
        || { echo "recusando remover: '$ws'" >&2; return 1; }
    echo "limpando $ws"
    rm -rf -- "$ws"'''),
('''    local dir
    for dir in $(list_old_builds); do
        clean_workspace "$dir"
    done''','''    local dir
    while IFS= read -r dir; do
        clean_workspace "$dir"
    done < <(list_old_builds)'''),('''    echo "espaco livre: $(df -h "${BUILD_ROOT:-/}"''','''    echo "espaco livre: $(df -h "$BUILD_ROOT"''')],
"rm -rf recebe a variável sem aspas: espaços dividem o caminho em vários argumentos, nomes iniciados em '-' viram opções e, com BUILD_ROOT vazio, o alvo pode virar '/' (CWE-88). A correção exige BUILD_ROOT, valida o caminho dentro da raiz de builds, usa '--' e aspas e itera com read em vez de divisão de palavras."))
