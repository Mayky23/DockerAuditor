#!/usr/bin/env bash
# DockerAuditor - Auditoría forense y de seguridad de entornos Docker.
#
# Recopila evidencias del daemon, contenedores, imágenes, redes, volúmenes y
# plugins, detecta configuraciones inseguras y genera un informe acompañado de
# hashes SHA-256 que permiten verificar la integridad de las evidencias.
#
# Al arrancar comprueba que todas las dependencias están instaladas y ofrece
# instalar las herramientas opcionales que falten (Checkov, Hadolint y Trivy).
#
# Uso: ./DockerAuditor.sh   (no tiene opciones: lo necesario se pregunta al inicio)
#
# Códigos de salida:
#   0    auditoría completada sin avisos
#   1    error fatal: no se pudo realizar la auditoría
#   2    auditoría completada con avisos: algún paso falló y el informe puede estar incompleto
#   130  auditoría interrumpida por el usuario

if [ -z "${BASH_VERSION:-}" ]; then
    echo "Error: ejecute DockerAuditor con Bash (./DockerAuditor.sh o bash DockerAuditor.sh)." >&2
    exit 1
fi
if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] < 404 )); then
    echo "Error: DockerAuditor necesita Bash 4.4 o superior (versión actual: ${BASH_VERSION})." >&2
    exit 1
fi

set -uo pipefail
umask 077

# --- Configuración -----------------------------------------------------------

readonly VERSION="3.1"
readonly LOG_TAIL=1000        # líneas de log que se guardan por contenedor
readonly EVENTS_SINCE="24h"   # antigüedad de los eventos del daemon que se recopilan
readonly SEARCH_DEPTH=3       # profundidad al buscar Dockerfile/compose en el proyecto
readonly TOTAL_STEPS=11
readonly RULE="================================================================="
readonly SEP=$'\x1f'          # separador interno de campos (no aparece en los datos)
readonly SEVERITIES=(CRITICO ALTO MEDIO BAJO INFO)

# Herramientas opcionales que el script puede instalar (sin root) en TOOLS_DIR.
# Las descargas se verifican con estos SHA-256 antes de usarlas.
readonly TOOLS_DIR="${XDG_DATA_HOME:-${HOME:-.}/.local/share}/dockerauditor"
readonly HADOLINT_VERSION="2.15.1"
readonly TRIVY_VERSION="0.75.0"
declare -rA TOOL_SHA256=(
    [hadolint-x86_64]="c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507"
    [hadolint-arm64]="f6198ef8090f404dbb771abfee086eb8c48ac177f30da7fd3510aca35b344b5d"
    [trivy-x86_64]="c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"
    [trivy-arm64]="a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3"
)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P) || SCRIPT_DIR=$PWD
readonly SCRIPT_DIR
# Utilidades del sistema que usa el script además de docker.
readonly REQUIRED_UTILS=(tar gzip find sort grep sed cut paste tr head tail xargs stat date uname id cat cp mv rm mkdir rmdir chmod ln mktemp dirname)
# Nombres de variables que suelen contener secretos.
readonly SECRET_WORDS='PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL'
readonly SECRET_NAME_RE="(${SECRET_WORDS}|(^|_)PASS(\$|_))"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    readonly C_RED=$'\e[31m' C_YEL=$'\e[33m' C_GRN=$'\e[32m' C_BLU=$'\e[1;34m' C_BOLD=$'\e[1m' C_RST=$'\e[0m'
else
    readonly C_RED="" C_YEL="" C_GRN="" C_BLU="" C_BOLD="" C_RST=""
fi

# Plantillas de "docker inspect". Los textos que controla quien crea el
# contenedor se piden en JSON para que ocupen una sola línea y no puedan
# inyectar claves falsas en el análisis.
# shellcheck disable=SC2016  # las plantillas Go usan "$" y no deben expandirse
readonly CONTAINER_FMT='name={{json .Name}}
image={{json .Config.Image}}
status={{json .State.Status}}
created={{json .Created}}
started={{json .State.StartedAt}}
user={{json .Config.User}}
cmd={{json .Path}}{{range .Args}} {{json .}}{{end}}
privileged={{.HostConfig.Privileged}}
netmode={{json .HostConfig.NetworkMode}}
pidmode={{json .HostConfig.PidMode}}
ipcmode={{json .HostConfig.IpcMode}}
utsmode={{json .HostConfig.UTSMode}}
usernsmode={{json .HostConfig.UsernsMode}}
readonly={{.HostConfig.ReadonlyRootfs}}
memory={{.HostConfig.Memory}}
nanocpus={{.HostConfig.NanoCpus}}
cpuquota={{.HostConfig.CpuQuota}}
pidslimit={{.HostConfig.PidsLimit}}
logdriver={{json .HostConfig.LogConfig.Type}}
{{range .HostConfig.CapAdd}}cap={{json .}}
{{end}}{{range .HostConfig.SecurityOpt}}secopt={{json .}}
{{end}}{{range .HostConfig.Devices}}device={{json .PathOnHost}}
{{end}}{{range .Mounts}}mount={{.Type}} {{.RW}}
msrc={{json .Source}}
mdst={{json .Destination}}
{{end}}{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}port={{$p}} {{json .HostIp}} {{json .HostPort}}
{{end}}{{end}}{{range .Config.Env}}env={{json (index (split . "=") 0)}}
{{end}}'

readonly IMAGE_FMT='tags={{json .RepoTags}}
created={{json .Created}}
size={{.Size}}'

readonly DAEMON_FMT='version={{.ServerVersion}}
secopts={{range .SecurityOptions}}{{.}} {{end}}
live={{.LiveRestoreEnabled}}
logdriver={{.LoggingDriver}}
debug={{.Debug}}
insecure={{if .RegistryConfig}}{{range .RegistryConfig.IndexConfigs}}{{if not .Secure}}{{.Name}} {{end}}{{end}}{{range .RegistryConfig.InsecureRegistryCIDRs}}{{.}} {{end}}{{end}}'

# --- Estado global -----------------------------------------------------------

DOCKER=(docker)
SHA_CMD=()
DOCKER_CTX="" DOCKER_ENDPOINT="" SOCKET_PATH=""
OUTPUT_DIR="" PROJECT_DIR="" AUDIT_NAME="" AUDIT_DIR="" EV="" REPORT="" TMP_DIR=""
HOST_NAME="" START_UTC="" START_LOCAL=""
SERVER_VERSION="" SECURITY_OPTIONS="" DAEMON_RAW="" ROOTLESS=0 USERNS_REMAP=0 TCP_INSECURE=0
END_UTC="" ARCHIVE="" ARCHIVE_HASH=""
HAVE_CHECKOV=0 HAVE_HADOLINT=0 HAVE_TRIVY=0
STEP=0 SECTION=0
WARNINGS=() FINDINGS=()
CONTAINER_IDS=() IMAGE_IDS=() DOCKERFILES=() COMPOSE_FILES=()
NETWORKS_TOTAL=0 VOLUMES_TOTAL=0 PLUGINS_TOTAL=0
declare -A CSTATE=() IMAGE_TAGS=()

# --- Utilidades --------------------------------------------------------------

say()  { printf '%s\n' "$@"; }
ok()   { printf '  %s✔%s %s\n' "$C_GRN" "$C_RST" "$*"; }
fail() { printf '  %s✖%s %s\n' "$C_RED" "$C_RST" "$*"; }
note() { printf '  %s! %s%s\n' "$C_YEL" "$*" "$C_RST"; }
step() {
    STEP=$((STEP + 1))
    printf '\n%s[%d/%d]%s %s\n' "$C_BLU" "$STEP" "$TOTAL_STEPS" "$C_RST" "$*"
}
die() {
    printf '%sError:%s %s\n' "$C_RED" "$C_RST" "$*" >&2
    exit 1
}
# Registra un fallo no fatal: se muestra, se anota en el informe y hace que el
# script termine con código 2.
warn() {
    WARNINGS+=("$*")
    printf '  %s! %s%s\n' "$C_YEL" "$*" "$C_RST" >&2
    if [[ -n $REPORT ]]; then
        printf '[AVISO] %s\n' "$*" >> "$REPORT"
    fi
}

# Ejecuta docker (con sudo si hace falta) sin heredar la entrada estándar.
dk() { "${DOCKER[@]}" "$@" < /dev/null; }

# collect FICHERO COMANDO...: guarda la salida (stdout y stderr) del comando en FICHERO.
collect() {
    local file=$1
    shift
    "$@" > "$file" 2>&1 && return 0
    local rc=$? cmd="$*"
    warn "Falló «${cmd/#dk /docker }» (código $rc); ver ${file#"$AUDIT_DIR"/}"
    return "$rc"
}

rpt() { printf '%s\n' "$@" >> "$REPORT"; }
rpt_file() { cat -- "$1" >> "$REPORT"; }
section() {
    SECTION=$((SECTION + 1))
    rpt "" "$RULE" "${SECTION}. $1" "$RULE"
}

# Rellena con espacios hasta ANCHO columnas contando caracteres y no bytes,
# para que las etiquetas con tildes queden alineadas.
pad() {
    local LC_ALL=C
    local s=$1 width=$2
    local chars=${s//[$'\x80'-$'\xbf']/}
    printf '%-*s' $((width + ${#s} - ${#chars})) "$s"
}
kv() { printf '%s %s\n' "$(pad "$1" 26)" "$2"; }

count_lines() { grep -c '' -- "$1" 2>/dev/null || true; }
join_by() {
    local sep=$1 out="" item
    shift
    for item in "$@"; do out+=${out:+$sep}$item; done
    printf '%s' "$out"
}
safe_name() {
    local s=${1//[^A-Za-z0-9._-]/_}
    printf '%s' "${s:0:80}"
}
short_id() {
    local id=${1#sha256:}
    printf '%s' "${id:0:12}"
}
json_str() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/\\r}
    s=${s//$'\n'/\\n}
    printf '"%s"' "$s"
}
file_hash() {
    local out
    out=$("${SHA_CMD[@]}" < "$1") || return 1
    printf '%s' "${out%% *}"
}
is_secret_name() {
    local name=${1^^}
    [[ $name == *_FILE ]] && return 1
    [[ $name =~ $SECRET_NAME_RE ]]
}
# Indica si una referencia de imagen no fija la versión (sin etiqueta o ":latest").
image_unpinned() {
    local ref=$1
    [[ $ref == *@sha256:* || $ref == sha256:* || $ref == *'$'* || $ref == scratch ]] && return 1
    [[ $ref =~ ^[0-9a-f]{12,64}$ ]] && return 1
    ref=${ref##*/}
    [[ $ref != *:* || $ref == *:latest ]]
}

# add_finding SEVERIDAD OBJETO DESCRIPCIÓN RECOMENDACIÓN
add_finding() {
    local f="$1${SEP}$2${SEP}$3${SEP}$4"
    f=${f//$'\n'/ }
    f=${f//$'\r'/ }
    f=${f//$'\t'/ }
    FINDINGS+=("$f")
}
sev_label() {
    case $1 in
        CRITICO) printf 'CRÍTICO' ;;
        *) printf '%s' "$1" ;;
    esac
}
count_sev() {
    local n=0 f
    for f in "${FINDINGS[@]}"; do
        [[ ${f%%"$SEP"*} == "$1" ]] && n=$((n + 1))
    done
    printf '%d' "$n"
}
findings_breakdown() {
    local sev parts=()
    for sev in "${SEVERITIES[@]}"; do parts+=("$(sev_label "$sev") $(count_sev "$sev")"); done
    join_by " · " "${parts[@]}"
}

# ask VARIABLE PREGUNTA: lee una línea de la entrada (vacía si no hay entrada).
ask() {
    local reply=""
    if [[ -t 0 ]]; then
        read -e -r -p "$2" reply || reply=""
    else
        read -r reply || true
        printf '%s%s\n' "$2" "$reply"
    fi
    printf -v "$1" '%s' "$reply"
}
expand_path() {
    local p=$1
    # shellcheck disable=SC2088  # se compara la tilde literal escrita por el usuario
    case $p in
        "~") p=$HOME ;;
        "~/"*) p=$HOME/${p#"~/"} ;;
    esac
    printf '%s' "$p"
}

cleanup() {
    if [[ -n $TMP_DIR && -d $TMP_DIR ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}
interrupted() {
    printf '\n%sAuditoría interrumpida.%s' "$C_YEL" "$C_RST" >&2
    if [[ -n $AUDIT_DIR ]]; then
        printf ' Evidencias parciales (sin hashes) en: %s' "$AUDIT_DIR" >&2
    fi
    printf '\n' >&2
    exit 130
}

print_banner() {
    cat <<'EOF'
   ____             _                  _             _ _ _
  |  _ \  ___   ___| | _____ _ __     / \  _   _  __| (_) |_ ___  _ __
  | | | |/ _ \ / __| |/ / _ \ '__|   / _ \| | | |/ _` | | __/ _ \| '__|
  | |_| | (_) | (__|   <  __/ |     / ___ \ |_| | (_| | | || (_) | |
  |____/ \___/ \___|_|\_\___|_|    /_/   \_\__,_|\__,_|_|\__\___/|_|

EOF
    printf -- '---- By: MARH ----------------------------------------------- v%s ----\n\n' "$VERSION"
}

# --- Preparación -------------------------------------------------------------

# Decide cómo invocar docker: directamente si el usuario tiene acceso al daemon
# y con sudo solo si no lo tiene. sudo descarta DOCKER_HOST y los contextos del
# usuario, así que no se usa cuando están configurados.
setup_docker_access() {
    command -v docker > /dev/null 2>&1 || die "No se encontró el cliente «docker». Instale Docker y vuelva a intentarlo."

    local err ctx
    if err=$(docker info --format '{{.ServerVersion}}' 2>&1 < /dev/null); then
        DOCKER=(docker)
    else
        err=$(sed '/^[[:space:]]*$/d' <<< "$err")
        [[ ${err,,} == *"permission denied"* ]] || die "No se puede conectar con el daemon de Docker: $err"
        if (( EUID == 0 )) || ! command -v sudo > /dev/null 2>&1; then
            die "Sin permiso para acceder al daemon de Docker: $err"
        fi
        ctx=$(docker context show 2>/dev/null < /dev/null || true)
        if [[ -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} || ( -n $ctx && $ctx != default ) ]]; then
            die "Sin permiso para acceder al daemon configurado (DOCKER_HOST o contexto «${ctx}»). sudo lo ignoraría y auditaría otro daemon; ejecute el script con un usuario con acceso."
        fi
        say "El usuario $(id -un) no tiene acceso al socket de Docker: se usará sudo."
        sudo -v || die "No se pudieron obtener privilegios con sudo."
        err=$(sudo docker info --format '{{.ServerVersion}}' 2>&1 < /dev/null) \
            || die "Tampoco con sudo se puede conectar con el daemon de Docker: $err"
        DOCKER=(sudo docker)
    fi

    if [[ ${DOCKER[0]} == docker && -n ${DOCKER_HOST:-} ]]; then
        DOCKER_CTX="(variable DOCKER_HOST)"
        DOCKER_ENDPOINT=$DOCKER_HOST
    else
        DOCKER_CTX=$(dk context show 2>/dev/null || printf 'default')
        DOCKER_ENDPOINT=$(dk context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null \
            || printf 'unix:///var/run/docker.sock')
    fi
    if [[ $DOCKER_ENDPOINT == unix://* ]]; then
        SOCKET_PATH=${DOCKER_ENDPOINT#unix://}
    fi
    ok "Daemon de Docker accesible$([[ ${DOCKER[0]} == sudo ]] && echo " (con sudo)") en $DOCKER_ENDPOINT"
}

# --- Dependencias -------------------------------------------------------------

# Comprueba todas las dependencias. Si falta alguna obligatoria se detiene; si
# faltan herramientas opcionales, ofrece instalarlas (solo en una terminal).
check_dependencies() {
    say "Comprobando dependencias..."
    PATH="$TOOLS_DIR/bin:$PATH"

    local fatal=0 version cmd missing_utils=()
    if command -v docker > /dev/null 2>&1; then
        version=$(docker version --format '{{.Client.Version}}' 2>/dev/null < /dev/null || true)
        ok "Docker (cliente ${version:-desconocido})"
    else
        fail "Docker: no está instalado. Sin Docker no hay nada que auditar; instálelo siguiendo https://docs.docker.com/engine/install/"
        fatal=1
    fi
    if command -v sha256sum > /dev/null 2>&1; then
        SHA_CMD=(sha256sum)
    elif command -v shasum > /dev/null 2>&1; then
        SHA_CMD=(shasum -a 256)
    fi
    for cmd in "${REQUIRED_UTILS[@]}"; do
        command -v "$cmd" > /dev/null 2>&1 || missing_utils+=("$cmd")
    done
    (( ${#SHA_CMD[@]} )) || missing_utils+=(sha256sum)
    if (( ${#missing_utils[@]} )); then
        fail "Faltan utilidades del sistema: ${missing_utils[*]} (instálelas con el gestor de paquetes de su distribución)"
        fatal=1
    else
        ok "Bash ${BASH_VERSION%%(*}, sha256sum, tar y utilidades del sistema"
    fi
    (( fatal )) && die "Faltan dependencias obligatorias."

    local tool missing=()
    for tool in checkov hadolint trivy; do
        if command -v "$tool" > /dev/null 2>&1; then
            ok "$(tool_label "$tool") $(tool_version "$tool")"
        else
            note "$(tool_label "$tool"): no instalado (opcional: $(tool_purpose "$tool"))"
            missing+=("$tool")
        fi
    done

    if (( ${#missing[@]} )); then
        if [[ -t 0 ]]; then
            local answer labels=()
            for tool in "${missing[@]}"; do labels+=("$(tool_label "$tool")"); done
            ask answer "¿Instalar ahora $(join_by ", " "${labels[@]}") en $TOOLS_DIR? [S/n]: "
            case ${answer,,} in
                n | no) say "  Se continúa sin ellas." ;;
                *) install_tools "${missing[@]}" ;;
            esac
        else
            say "  Ejecute el script en una terminal para que ofrezca instalarlas."
        fi
    fi

    command -v checkov > /dev/null 2>&1 && HAVE_CHECKOV=1
    command -v hadolint > /dev/null 2>&1 && HAVE_HADOLINT=1
    command -v trivy > /dev/null 2>&1 && HAVE_TRIVY=1
    return 0
}

tool_label() {
    case $1 in
        checkov) printf 'Checkov' ;;
        hadolint) printf 'Hadolint' ;;
        trivy) printf 'Trivy' ;;
    esac
}
tool_purpose() {
    case $1 in
        checkov | hadolint) printf 'buenas prácticas en Dockerfile' ;;
        trivy) printf 'vulnerabilidades de las imágenes' ;;
    esac
}

install_tools() {
    local tool
    if ! mkdir -p -- "$TOOLS_DIR/bin"; then
        note "No se pudo crear $TOOLS_DIR: se continúa sin instalar nada."
        return
    fi
    for tool in "$@"; do
        say "  Instalando $(tool_label "$tool")..."
        if "install_$tool"; then
            ok "$(tool_label "$tool") $(tool_version "$tool") instalado"
        else
            note "No se pudo instalar $(tool_label "$tool"); la auditoría continuará sin él."
        fi
    done
}

arch_name() {
    case $(uname -m) in
        x86_64 | amd64) printf 'x86_64' ;;
        aarch64 | arm64) printf 'arm64' ;;
        *) return 1 ;;
    esac
}

download() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL --retry 2 -o "$2" "$1"
    elif command -v wget > /dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        say "    Se necesita curl o wget para descargar."
        return 1
    fi
}

# fetch_verified URL DESTINO SHA256: descarga el fichero y lo descarta si su hash no coincide.
fetch_verified() {
    local url=$1 dest=$2 expected=$3 actual
    if ! download "$url" "$dest"; then
        say "    No se pudo descargar $url"
        rm -f -- "$dest"
        return 1
    fi
    actual=$(file_hash "$dest")
    if [[ $actual != "$expected" ]]; then
        say "    El SHA-256 de la descarga no coincide (esperado $expected, obtenido $actual): se descarta."
        rm -f -- "$dest"
        return 1
    fi
}

install_hadolint() {
    local arch tmp="$TOOLS_DIR/bin/.hadolint.tmp"
    arch=$(arch_name) || { say "    Arquitectura $(uname -m) no soportada: instale Hadolint manualmente."; return 1; }
    fetch_verified "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-${arch}" \
        "$tmp" "${TOOL_SHA256[hadolint-$arch]}" || return 1
    chmod 755 -- "$tmp" && mv -f -- "$tmp" "$TOOLS_DIR/bin/hadolint"
}

install_trivy() {
    local arch asset tmp rc=1
    arch=$(arch_name) || { say "    Arquitectura $(uname -m) no soportada: instale Trivy manualmente."; return 1; }
    asset="trivy_${TRIVY_VERSION}_Linux-$([[ $arch == x86_64 ]] && echo 64bit || echo ARM64).tar.gz"
    tmp=$(mktemp -d "$TOOLS_DIR/.trivy.XXXXXX") || return 1
    if fetch_verified "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${asset}" \
        "$tmp/$asset" "${TOOL_SHA256[trivy-$arch]}" \
        && tar --no-same-owner -xzf "$tmp/$asset" -C "$tmp" trivy \
        && chmod 755 -- "$tmp/trivy" && mv -f -- "$tmp/trivy" "$TOOLS_DIR/bin/trivy"; then
        rc=0
    fi
    rm -rf -- "$tmp"
    return "$rc"
}

# Instala Checkov en un entorno virtual propio para no tocar el Python del sistema.
install_checkov() {
    local log="$TOOLS_DIR/instalacion_checkov.log" req="$SCRIPT_DIR/requirements.txt"
    local -a packages=(-r "$req")
    [[ -f $req ]] || packages=("checkov>=3.2,<4")
    if ! command -v python3 > /dev/null 2>&1 \
        || ! python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        say "    Checkov necesita Python 3.9 o superior con el módulo venv (Debian/Ubuntu: sudo apt install python3-venv)."
        return 1
    fi
    say "    Creando un entorno virtual con Checkov (puede tardar unos minutos)..."
    if python3 -m venv "$TOOLS_DIR/venv" > "$log" 2>&1 \
        && "$TOOLS_DIR/venv/bin/pip" install --disable-pip-version-check "${packages[@]}" >> "$log" 2>&1 < /dev/null; then
        ln -sf -- "$TOOLS_DIR/venv/bin/checkov" "$TOOLS_DIR/bin/checkov"
    else
        say "    Falló la instalación; detalles en $log"
        return 1
    fi
}

tool_version() {
    local v
    v=$("$1" --version 2>/dev/null < /dev/null | head -n 1)
    printf '%s' "${v##* }"
}
tools_summary() {
    local t parts=() have
    for t in checkov hadolint trivy; do
        case $t in
            checkov) have=$HAVE_CHECKOV ;;
            hadolint) have=$HAVE_HADOLINT ;;
            trivy) have=$HAVE_TRIVY ;;
        esac
        if (( have )); then parts+=("$t $(tool_version "$t")"); else parts+=("$t (no instalado)"); fi
    done
    join_by ", " "${parts[@]}"
}

choose_directories() {
    local answer
    ask answer "Directorio donde guardar el informe [Enter = $PWD]: "
    OUTPUT_DIR=$(expand_path "${answer:-$PWD}")
    [[ -d $OUTPUT_DIR ]] || die "El directorio «$OUTPUT_DIR» no existe."
    OUTPUT_DIR=$(cd -- "$OUTPUT_DIR" && pwd -P) || die "No se puede acceder a «$OUTPUT_DIR»."
    [[ -w $OUTPUT_DIR ]] || die "No tiene permiso de escritura en «$OUTPUT_DIR»."

    ask answer "Directorio del proyecto con Dockerfile/compose a analizar [Enter = $PWD, n = omitir]: "
    case ${answer,,} in
        n | no) PROJECT_DIR="" ;;
        *)
            PROJECT_DIR=$(expand_path "${answer:-$PWD}")
            [[ -d $PROJECT_DIR ]] || die "El directorio «$PROJECT_DIR» no existe."
            PROJECT_DIR=$(cd -- "$PROJECT_DIR" && pwd -P) || die "No se puede acceder a «$PROJECT_DIR»."
            ;;
    esac
}

prepare_output() {
    HOST_NAME=$(uname -n)
    START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    START_LOCAL=$(date '+%Y-%m-%d %H:%M:%S %Z')
    AUDIT_NAME="docker_audit_$(safe_name "$HOST_NAME")_${START_UTC//[-:]/}"
    AUDIT_DIR="$OUTPUT_DIR/$AUDIT_NAME"
    EV="$AUDIT_DIR/evidencias"
    mkdir -- "$AUDIT_DIR" || die "No se pudo crear el directorio «$AUDIT_DIR»."
    mkdir -p -- "$EV"/{sistema,contenedores,imagenes,redes,volumenes,plugins,analisis_estatico} \
        || die "No se pudo crear la estructura de evidencias en «$AUDIT_DIR»."
    TMP_DIR="$AUDIT_DIR/.tmp"
    mkdir -- "$TMP_DIR" || die "No se pudo crear «$TMP_DIR»."
    : > "$AUDIT_DIR/informe.txt" || die "No se pudo escribir en «$AUDIT_DIR»."
    REPORT="$AUDIT_DIR/informe.txt"
}

write_header() {
    {
        say "$RULE"
        say "  DockerAuditor $VERSION - Auditoría forense de Docker"
        say "$RULE"
        kv "Inicio (UTC):" "$START_UTC"
        kv "Inicio (hora local):" "$START_LOCAL"
        kv "Equipo:" "$HOST_NAME ($(uname -srm))"
        kv "Usuario:" "$(id -un) (uid=$(id -u))"
        kv "Acceso a Docker:" "${DOCKER[*]}"
        kv "Contexto Docker:" "$DOCKER_CTX"
        kv "Endpoint del daemon:" "$DOCKER_ENDPOINT"
        kv "Directorio de trabajo:" "$PWD"
        kv "Proyecto analizado:" "${PROJECT_DIR:-(omitido)}"
        kv "Herramientas opcionales:" "$(tools_summary)"
    } >> "$REPORT"
}

# --- Daemon y host -------------------------------------------------------------

audit_general() {
    step "Información general del daemon de Docker"
    section "INFORMACIÓN GENERAL"
    local sys="$EV/sistema"
    collect "$sys/docker_version.txt" dk version
    collect "$sys/docker_version.json" dk version --format '{{json .}}'
    collect "$sys/docker_info.txt" dk info
    collect "$sys/docker_info.json" dk info --format '{{json .}}'
    rpt_file "$sys/docker_version.txt"
    rpt ""
    rpt_file "$sys/docker_info.txt"

    local raw line
    raw=$(dk info --format "$DAEMON_FMT" 2>/dev/null) || warn "No se pudo leer la configuración de seguridad del daemon."
    while IFS= read -r line; do
        case ${line%%=*} in
            version) SERVER_VERSION=${line#*=} ;;
            secopts) SECURITY_OPTIONS=${line#*=} SECURITY_OPTIONS=${SECURITY_OPTIONS% } ;;
        esac
    done <<< "$raw"
    [[ $SECURITY_OPTIONS == *name=rootless* ]] && ROOTLESS=1
    [[ $SECURITY_OPTIONS == *name=userns* ]] && USERNS_REMAP=1
    DAEMON_RAW=$raw
    ok "Docker ${SERVER_VERSION:-desconocido}"
}

audit_daemon() {
    step "Configuración del daemon y del host"
    section "CONFIGURACIÓN DEL DAEMON Y DEL HOST"
    local line live="" logdriver="" debug="" insecure="" cidr filtered=()
    while IFS= read -r line; do
        case ${line%%=*} in
            live) live=${line#*=} ;;
            logdriver) logdriver=${line#*=} ;;
            debug) debug=${line#*=} ;;
            insecure) insecure=${line#*=} ;;
        esac
    done <<< "$DAEMON_RAW"
    for cidr in $insecure; do
        [[ $cidr == 127.0.0.0/8 || $cidr == ::1/128 ]] || filtered+=("$cidr")
    done

    local icc
    icc=$(dk network inspect bridge --format '{{index .Options "com.docker.network.bridge.enable_icc"}}' 2>/dev/null || true)

    {
        kv "Opciones de seguridad:" "${SECURITY_OPTIONS:-ninguna}"
        kv "Modo rootless:" "$( ((ROOTLESS)) && echo sí || echo no)"
        kv "Remapeo de usuarios:" "$( ((USERNS_REMAP)) && echo sí || echo no)"
        kv "live-restore:" "${live:-desconocido}"
        kv "Driver de logs:" "${logdriver:-desconocido}"
        kv "Modo debug:" "${debug:-desconocido}"
        kv "Registros inseguros:" "${filtered[*]:-ninguno}"
        kv "icc en la red bridge:" "${icc:-desconocido}"
    } >> "$REPORT"

    local obj="Daemon Docker"
    # Sin la configuración del daemon no se puede afirmar que falte nada.
    if [[ -n $DAEMON_RAW ]]; then
        if [[ $SECURITY_OPTIONS != *name=seccomp* ]]; then
            add_finding ALTO "$obj" "El daemon no aplica perfiles seccomp a los contenedores." \
                "Use un kernel con seccomp y no desactive el perfil por defecto del daemon."
        fi
        if [[ $SECURITY_OPTIONS != *name=apparmor* && $SECURITY_OPTIONS != *name=selinux* ]]; then
            add_finding BAJO "$obj" "No hay AppArmor ni SELinux activos para confinar los contenedores." \
                "Active AppArmor o SELinux en el host (selinux-enabled en daemon.json si usa SELinux)."
        fi
        if (( !ROOTLESS && !USERNS_REMAP )); then
            add_finding INFO "$obj" "No usa modo rootless ni userns-remap: root dentro de un contenedor es root en el host." \
                "Valore el modo rootless o \"userns-remap\": \"default\" en daemon.json."
        fi
        if [[ $live == false ]]; then
            add_finding INFO "$obj" "live-restore está desactivado: reiniciar el daemon detiene todos los contenedores." \
                "Añada \"live-restore\": true en daemon.json."
        fi
        if [[ $logdriver == none ]]; then
            add_finding MEDIO "$obj" "El driver de logs por defecto es «none»: los contenedores no guardan registros." \
                "Configure un driver de logs (json-file, local, journald o uno centralizado)."
        fi
        if [[ $debug == true ]]; then
            add_finding BAJO "$obj" "El daemon está en modo debug." "Desactive \"debug\" en producción."
        fi
        if (( ${#filtered[@]} )); then
            add_finding MEDIO "$obj" "Hay registros configurados como inseguros (sin TLS): ${filtered[*]}." \
                "Elimine \"insecure-registries\" y use registros con TLS."
        fi
        if [[ $icc == true ]]; then
            add_finding BAJO "$obj" "La red bridge por defecto permite el tráfico entre todos los contenedores (icc)." \
                "Añada \"icc\": false en daemon.json y conecte los contenedores en redes definidas por el usuario."
        fi
    fi

    audit_host

    # Avisos que el propio daemon muestra en "docker info".
    local w
    while IFS= read -r w; do
        w=${w#WARNING: }
        if [[ $w == *"without encryption"* ]]; then
            (( TCP_INSECURE )) || add_finding CRITICO "$obj" "$w" "Desactive el acceso TCP o protéjalo con tlsverify."
        else
            add_finding INFO "$obj" "docker info avisa: $w" "Revise la configuración del host indicada en el aviso."
        fi
    done < <(grep '^WARNING: ' "$EV/sistema/docker_info.txt" 2>/dev/null)

    rpt "" "Eventos del daemon (últimas ${EVENTS_SINCE}, los que el daemon conserva):"
    if collect "$EV/sistema/eventos.txt" dk events --since "$EVENTS_SINCE" --until "$(date +%s)"; then
        rpt "  Total: $(count_lines "$EV/sistema/eventos.txt") (evidencias/sistema/eventos.txt). Últimos 20:"
        tail -n 20 -- "$EV/sistema/eventos.txt" | sed 's/^/    /' >> "$REPORT"
    fi
    collect "$EV/sistema/contextos.txt" dk context ls
    ok "Configuración del daemon revisada"
}

dockerd_cmdlines() {
    local p comm
    for p in /proc/[0-9]*; do
        read -r comm 2>/dev/null < "$p/comm" || continue
        [[ $comm == dockerd ]] || continue
        printf '%s: %s\n' "${p#/proc/}" "$(tr '\0' ' ' 2>/dev/null < "$p/cmdline")"
    done
}

# Comprobaciones que solo tienen sentido si el daemon corre en este equipo.
audit_host() {
    rpt "" "Comprobaciones locales del host:"
    if [[ $(uname -s) != Linux ]]; then
        rpt "  Omitidas: solo se realizan en Linux."
        return
    fi
    if [[ -z $SOCKET_PATH ]]; then
        rpt "  Omitidas: el daemon no se usa a través de un socket local ($DOCKER_ENDPOINT)."
        if [[ $DOCKER_ENDPOINT == tcp://*:2375* ]]; then
            TCP_INSECURE=1
            add_finding CRITICO "Conexión con el daemon" "El cliente se conecta al daemon por TCP en el puerto 2375 (sin TLS)." \
                "Use TLS (puerto 2376 con tlsverify) o SSH (ssh://) para acceder a daemons remotos."
        fi
        return
    fi

    local perms="" owner=""
    if [[ -S $SOCKET_PATH ]]; then
        read -r perms owner < <(stat -c '%a %U:%G' -- "$SOCKET_PATH" 2>/dev/null)
        kv "  Socket del daemon:" "$SOCKET_PATH (permisos ${perms:-?}, ${owner:-?})" >> "$REPORT"
        if [[ $perms =~ ^[0-7]+$ ]] && (( 8#$perms & 2 )); then
            add_finding CRITICO "Socket $SOCKET_PATH" "El socket de Docker es escribible por cualquier usuario (permisos $perms): cualquiera puede obtener root." \
                "Restablezca los permisos: chmod 660 y propietario root:docker."
        fi
    else
        kv "  Socket del daemon:" "$SOCKET_PATH (no está en este equipo)" >> "$REPORT"
    fi

    local group_line members
    group_line=$(getent group docker 2>/dev/null || grep '^docker:' /etc/group 2>/dev/null || true)
    if [[ -n $group_line ]]; then
        members=${group_line##*:}
        kv "  Grupo docker:" "${members:-(ninguno)}" >> "$REPORT"
        if [[ -n $members ]]; then
            add_finding INFO "Grupo docker" "Usuarios con acceso al daemon, equivalente a root en el host: ${members//,/, }." \
                "Limite el grupo docker a los administradores imprescindibles."
        fi
    fi

    local procs
    procs=$(dockerd_cmdlines)
    printf '%s\n' "${procs:-No se encontró ningún proceso dockerd en este equipo.}" > "$EV/sistema/dockerd_procesos.txt"
    if [[ -n $procs ]]; then
        rpt "  Procesos dockerd:"
        local proc_lines
        mapfile -t proc_lines <<< "$procs"
        printf '    %s\n' "${proc_lines[@]}" >> "$REPORT"
    else
        rpt "  Procesos dockerd: ninguno visible (¿Docker Desktop, otro espacio de procesos o daemon remoto?)."
    fi

    local daemon_json=/etc/docker/daemon.json djson=""
    (( ROOTLESS )) && daemon_json="${XDG_CONFIG_HOME:-$HOME/.config}/docker/daemon.json"
    if [[ -r $daemon_json ]]; then
        cp -p -- "$daemon_json" "$EV/sistema/daemon.json"
        djson=$(< "$daemon_json")
        rpt "  Configuración ($daemon_json):"
        sed 's/^/    /' -- "$daemon_json" >> "$REPORT"
    elif [[ -e $daemon_json ]]; then
        rpt "  $daemon_json existe pero no se puede leer."
    else
        rpt "  $daemon_json no existe: el daemon usa la configuración por defecto."
    fi

    local tls_re='"tlsverify"[[:space:]]*:[[:space:]]*true'
    if [[ $procs == *tcp://* || $djson == *'"tcp://'* ]] && ! [[ $procs == *--tlsverify* || $djson =~ $tls_re ]]; then
        TCP_INSECURE=1
        add_finding CRITICO "Daemon Docker" "El daemon acepta conexiones TCP sin autenticación TLS (--tlsverify): control remoto total del host." \
            "Desactive el acceso TCP o configure tlsverify con certificados de cliente."
    fi

    local listen=""
    if command -v ss > /dev/null 2>&1; then
        listen=$(ss -ltn 2>/dev/null || true)
    elif command -v netstat > /dev/null 2>&1; then
        listen=$(netstat -ltn 2>/dev/null || true)
    fi
    if [[ -z $listen ]]; then
        rpt "  Puertos en escucha: no se pudo comprobar (faltan ss y netstat)."
    else
        printf '%s\n' "$listen" > "$EV/sistema/puertos_escucha.txt"
        if grep -qE '[:.]2375[[:space:]]' <<< "$listen" && (( !TCP_INSECURE )); then
            TCP_INSECURE=1
            add_finding CRITICO "Host" "Hay un servicio escuchando en el puerto 2375/tcp, el de la API de Docker sin cifrar." \
                "Compruebe qué proceso usa el puerto y cierre la API sin TLS."
        fi
    fi
}

audit_system_df() {
    step "Uso de disco de Docker"
    section "USO DEL SISTEMA"
    collect "$EV/sistema/system_df.txt" dk system df
    collect "$EV/sistema/system_df_detallado.txt" dk system df -v
    rpt_file "$EV/sistema/system_df.txt"
    ok "Uso de disco registrado"
}

# --- Contenedores --------------------------------------------------------------

audit_containers() {
    step "Contenedores"
    section "CONTENEDORES"
    collect "$EV/contenedores/listado.txt" dk ps -a --no-trunc
    rpt_file "$EV/contenedores/listado.txt"

    local ids id
    if ids=$(dk ps -aq --no-trunc 2>&1); then
        [[ -n $ids ]] && mapfile -t CONTAINER_IDS <<< "$ids"
    else
        warn "No se pudo obtener la lista de contenedores: $ids"
    fi
    rpt "" "Detalle por contenedor (inspect, logs, docker diff y procesos en evidencias/contenedores/):"
    for id in "${CONTAINER_IDS[@]}"; do
        analyze_container "$id"
    done
    ok "Contenedores analizados: ${#CONTAINER_IDS[@]}"
}

analyze_container() {
    local id=$1 short raw
    short=$(short_id "$id")
    if ! raw=$(dk inspect --format "$CONTAINER_FMT" "$id" 2>&1); then
        warn "No se pudo inspeccionar el contenedor $short (¿se eliminó durante la auditoría?): $raw"
        return
    fi

    local name="" image="" status="" created="" started="" user="" cmd="" privileged="" netmode="" pidmode=""
    local ipcmode="" utsmode="" usernsmode="" readonly_fs="" memory="" nanocpus="" cpuquota="" pidslimit="" logdriver=""
    local -a caps=() secopts=() devices=() mounts=() ports=() envs=()
    local line key val mtype="" msrc=""
    while IFS= read -r line; do
        key=${line%%=*}
        val=${line#*=}
        case $key in
            cmd) cmd=$val; continue ;;
            port) ports+=("$val"); continue ;;
            mount) mtype=$val; continue ;;
        esac
        val=${val#\"} val=${val%\"}
        case $key in
            name) name=${val#/} ;;
            image) image=$val ;;
            status) status=$val ;;
            created) created=$val ;;
            started) started=$val ;;
            user) user=$val ;;
            privileged) privileged=$val ;;
            netmode) netmode=$val ;;
            pidmode) pidmode=$val ;;
            ipcmode) ipcmode=$val ;;
            utsmode) utsmode=$val ;;
            usernsmode) usernsmode=$val ;;
            readonly) readonly_fs=$val ;;
            memory) memory=$val ;;
            nanocpus) nanocpus=$val ;;
            cpuquota) cpuquota=$val ;;
            pidslimit) pidslimit=$val ;;
            logdriver) logdriver=$val ;;
            cap) caps+=("$val") ;;
            secopt) secopts+=("$val") ;;
            device) devices+=("$val") ;;
            env) envs+=("$val") ;;
            msrc) msrc=$val ;;
            mdst) mounts+=("${mtype%% *}${SEP}${mtype#* }${SEP}${msrc}${SEP}${val}") ;;
        esac
    done <<< "$raw"

    status=${status:-desconocido}
    [[ $started == 0001-01-01T00:00:00Z ]] && started="nunca"
    CSTATE[$status]=$(( ${CSTATE[$status]:-0} + 1 ))

    # Evidencias del contenedor (solo lectura: no se ejecuta nada dentro de él).
    local cdir diff_count="no disponible"
    cdir="$EV/contenedores/$(safe_name "$name")_$short"
    mkdir -p -- "$cdir"
    collect "$cdir/inspect.json" dk inspect "$id"
    if [[ $logdriver == none ]]; then
        say "El contenedor usa el driver de logs «none»: no hay logs que recopilar." > "$cdir/logs.txt"
    else
        collect "$cdir/logs.txt" dk logs --timestamps --tail "$LOG_TAIL" "$id"
    fi
    if collect "$cdir/diff.txt" dk diff "$id"; then
        diff_count=$(count_lines "$cdir/diff.txt")
    fi
    if [[ $status == running ]]; then
        collect "$cdir/procesos.txt" dk top "$id"
    fi
    local histories
    histories=$(collect_shell_history "$id" "$cdir")

    {
        printf '\n- %s (%s)\n' "$name" "$short"
        kv "    Estado:" "$status"
        kv "    Imagen:" "$image"
        kv "    Creado:" "$created"
        kv "    Iniciado:" "$started"
        kv "    Usuario:" "${user:-root (por defecto)}"
        kv "    Comando:" "$cmd"
        kv "    Historial de shell:" "${histories:-no encontrado}"
        kv "    Cambios en disco:" "$diff_count (docker diff)"
        if [[ $diff_count =~ ^[1-9] ]]; then
            head -n 15 -- "$cdir/diff.txt" | sed 's/^/        /'
            (( diff_count > 15 )) && printf '        ... (%d más en %s)\n' $((diff_count - 15)) "${cdir#"$AUDIT_DIR"/}/diff.txt"
        fi
    } >> "$REPORT"

    check_container
    return 0
}

# collect_shell_history ID DIRECTORIO: copia los historiales de shell del
# contenedor con "docker cp", que no ejecuta nada dentro de él. Busca las rutas
# habituales de root y cualquier *_history que aparezca en docker diff.
collect_shell_history() {
    local id=$1 dir=$2 change path out lines
    local -a found=()
    local -A seen=()
    local -a paths=(/root/.bash_history /root/.ash_history /root/.sh_history /root/.zsh_history)
    if [[ -s $dir/diff.txt ]]; then
        while read -r change path; do
            [[ $change == [AC] && $path == *_history ]] && paths+=("$path")
        done < "$dir/diff.txt"
    fi
    for path in "${paths[@]}"; do
        [[ -n ${seen[$path]:-} ]] && continue
        seen[$path]=1
        mkdir -p -- "$dir/historial"
        out="$dir/historial/$(safe_name "${path#/}")"
        if dk cp "$id:$path" - 2>/dev/null | tar -xOf - > "$out" 2>/dev/null && [[ -s $out ]]; then
            lines=$(count_lines "$out")
            found+=("$path (líneas: $lines)")
        else
            rm -f -- "$out"
        fi
    done
    rmdir -- "$dir/historial" 2>/dev/null
    join_by ", " "${found[@]}"
}

# Evalúa la configuración del contenedor (usa las variables locales de analyze_container).
check_container() {
    local obj="Contenedor $name ($short)"

    if [[ $privileged == true ]]; then
        add_finding CRITICO "$obj" "Se ejecuta en modo privilegiado (--privileged): accede a todos los dispositivos y capacidades del host." \
            "Elimine --privileged y conceda solo las capacidades imprescindibles con --cap-add."
    fi
    if [[ $pidmode == host ]]; then
        add_finding ALTO "$obj" "Comparte el espacio de procesos del host (--pid=host): puede ver y señalizar sus procesos." \
            "Elimine --pid=host."
    fi
    if [[ $netmode == host ]]; then
        add_finding ALTO "$obj" "Usa la red del host (--network=host): sin aislamiento de red y con acceso a servicios locales." \
            "Use una red bridge y publique solo los puertos necesarios."
    fi
    if [[ $ipcmode == host ]]; then
        add_finding MEDIO "$obj" "Comparte la memoria IPC del host (--ipc=host)." "Elimine --ipc=host."
    fi
    if [[ $utsmode == host ]]; then
        add_finding BAJO "$obj" "Comparte el nombre de equipo del host (--uts=host)." "Elimine --uts=host."
    fi
    if [[ $usernsmode == host ]] && (( USERNS_REMAP )); then
        add_finding MEDIO "$obj" "Desactiva el remapeo de usuarios del daemon (--userns=host)." "Elimine --userns=host."
    fi

    local c dangerous=() other=()
    for c in "${caps[@]}"; do
        c=${c^^}
        c=${c#CAP_}
        case $c in
            ALL | SYS_ADMIN | SYS_MODULE | SYS_PTRACE | SYS_RAWIO | SYS_BOOT | DAC_READ_SEARCH | NET_ADMIN | BPF | PERFMON | MAC_ADMIN | MAC_OVERRIDE | SYSLOG)
                dangerous+=("$c") ;;
            *) other+=("$c") ;;
        esac
    done
    if (( ${#dangerous[@]} )); then
        add_finding ALTO "$obj" "Tiene capacidades peligrosas añadidas: $(join_by ", " "${dangerous[@]}")." \
            "Elimine esas capacidades salvo que sean imprescindibles; parta de --cap-drop ALL."
    fi
    if (( ${#other[@]} )); then
        add_finding BAJO "$obj" "Tiene capacidades añadidas: $(join_by ", " "${other[@]}")." \
            "Compruebe que son necesarias; parta de --cap-drop ALL y añada solo las imprescindibles."
    fi
    if (( ${#devices[@]} )); then
        add_finding MEDIO "$obj" "Accede directamente a dispositivos del host: $(join_by ", " "${devices[@]}")." \
            "Elimine --device salvo que sea imprescindible."
    fi

    local s nnp=0
    for s in "${secopts[@]}"; do
        case ${s,,} in
            seccomp=unconfined | seccomp:unconfined)
                add_finding ALTO "$obj" "Se ejecuta sin perfil seccomp (seccomp=unconfined): puede usar cualquier llamada al sistema." \
                    "Elimine seccomp=unconfined o use un perfil seccomp ajustado." ;;
            systempaths=unconfined)
                add_finding ALTO "$obj" "Desenmascara rutas sensibles de /proc y /sys (systempaths=unconfined)." \
                    "Elimine systempaths=unconfined." ;;
            apparmor=unconfined | apparmor:unconfined)
                add_finding MEDIO "$obj" "Se ejecuta sin perfil AppArmor (apparmor=unconfined)." \
                    "Elimine apparmor=unconfined o asigne un perfil AppArmor." ;;
            label=disable | label:disable)
                # Docker lo añade solo con --privileged, --pid=host o --ipc=host, que ya se notifican.
                if [[ $privileged != true && $pidmode != host && $ipcmode != host ]]; then
                    add_finding MEDIO "$obj" "Desactiva el etiquetado SELinux (label=disable)." "Elimine label=disable."
                fi ;;
            no-new-privileges | no-new-privileges=true | no-new-privileges:true)
                nnp=1 ;;
        esac
    done

    local m mt mrw src dst mode p sensitive
    for m in "${mounts[@]}"; do
        IFS=$SEP read -r mt mrw src dst <<< "$m"
        [[ $mt == bind ]] || continue
        mode=$([[ $mrw == true ]] && echo "lectura/escritura" || echo "solo lectura")
        if [[ $src == *docker.sock || $src == *containerd.sock || $src == *podman.sock || $src == *crio.sock \
            || $src == /run || $src == /var/run ]]; then
            add_finding CRITICO "$obj" "Monta el socket del daemon de contenedores ($src → $dst): quien controle el contenedor controla el host." \
                "No monte el socket de Docker; si es imprescindible, use un proxy del socket que limite la API."
            continue
        fi
        if [[ $src == / ]]; then
            add_finding CRITICO "$obj" "Monta el sistema de ficheros raíz del host (/ → $dst, $mode)." \
                "Monte solo los directorios imprescindibles y en solo lectura."
            continue
        fi
        if [[ $mrw != true ]]; then
            case $src in
                /etc/localtime | /etc/timezone | /etc/ssl/certs* | /etc/pki/ca-trust* | /etc/ca-certificates*) continue ;;
            esac
        fi
        sensitive=""
        for p in /etc /proc /sys /boot /dev /root /usr /bin /sbin /lib /lib64 /var/lib/docker /var/lib/containerd /var/lib/kubelet; do
            if [[ $src == "$p" || $src == "$p"/* ]]; then
                sensitive=$p
                break
            fi
        done
        if [[ -n $sensitive ]]; then
            add_finding "$([[ $mrw == true ]] && echo ALTO || echo MEDIO)" "$obj" \
                "Monta una ruta sensible del host ($src → $dst, $mode)." \
                "Evite montar rutas del sistema; si es necesario, hágalo en solo lectura y lo más concretas posible."
        fi
    done

    local u=${user%%:*}
    if [[ -z $u || $u == root || $u == 0 ]]; then
        if (( ROOTLESS || USERNS_REMAP )); then
            add_finding BAJO "$obj" "Se ejecuta como root dentro del contenedor (en el host se mapea a un usuario sin privilegios)." \
                "Defina un usuario sin privilegios (USER en el Dockerfile o --user)."
        else
            add_finding MEDIO "$obj" "Se ejecuta como root: si escapa del contenedor, es root en el host." \
                "Defina un usuario sin privilegios (USER en el Dockerfile o --user)."
        fi
    fi

    local port cport hip hport exposed=() api=0
    for port in "${ports[@]}"; do
        read -r cport hip hport <<< "$port"
        hip=${hip//\"/}
        hport=${hport//\"/}
        if [[ -z $hip || $hip == 0.0.0.0 || $hip == :: || $hip == "[::]" ]]; then
            exposed+=("${hport:-aleatorio}->$cport")
            [[ $cport == 2375/tcp || $cport == 2376/tcp || $hport == 2375 || $hport == 2376 ]] && api=1
        fi
    done
    if (( api )); then
        add_finding ALTO "$obj" "Publica en todas las interfaces un puerto de la API de Docker (2375/2376)." \
            "No exponga la API de Docker; si es necesario, enlácela a una interfaz interna y use TLS."
    fi
    if (( ${#exposed[@]} )); then
        add_finding BAJO "$obj" "Publica puertos en todas las interfaces de red: $(join_by ", " "${exposed[@]}")." \
            "Si no deben ser públicos, enlácelos a una interfaz concreta (p. ej. -p 127.0.0.1:8080:80)."
    fi

    if image_unpinned "$image"; then
        add_finding BAJO "$obj" "Usa una imagen sin versión fija ($image)." \
            "Use una etiqueta de versión concreta o un digest (imagen@sha256:...)."
    fi

    local e secret_envs=()
    for e in "${envs[@]}"; do
        is_secret_name "$e" && secret_envs+=("$e")
    done
    if (( ${#secret_envs[@]} )); then
        add_finding MEDIO "$obj" "Variables de entorno con posibles secretos: $(join_by ", " "${secret_envs[@]}") (el valor no se incluye en el informe, pero sí en inspect.json)." \
            "Use Docker secrets o ficheros montados (variables *_FILE) en lugar de variables de entorno."
    fi

    if [[ $logdriver == none ]]; then
        add_finding MEDIO "$obj" "No guarda logs (--log-driver none): se pierde la trazabilidad." \
            "Use un driver de logs que conserve los registros."
    fi

    local hardening=()
    (( nnp )) || hardening+=("sin no-new-privileges")
    [[ $readonly_fs == true ]] || hardening+=("sistema de ficheros raíz escribible")
    [[ $memory == 0 ]] && hardening+=("sin límite de memoria")
    [[ $nanocpus == 0 && $cpuquota == 0 ]] && hardening+=("sin límite de CPU")
    [[ $pidslimit =~ ^[1-9][0-9]*$ ]] || hardening+=("sin límite de PIDs")
    if (( ${#hardening[@]} )); then
        add_finding BAJO "$obj" "Endurecimiento pendiente: $(join_by ", " "${hardening[@]}")." \
            "Añada --security-opt no-new-privileges, --read-only, --memory, --cpus y --pids-limit."
    fi
    return 0
}

# --- Imágenes, redes, volúmenes y plugins ----------------------------------------

audit_images() {
    step "Imágenes"
    section "IMÁGENES"
    collect "$EV/imagenes/listado.txt" dk images --digests --no-trunc
    rpt_file "$EV/imagenes/listado.txt"

    local ids
    if ids=$(dk images -q --no-trunc 2>&1); then
        [[ -n $ids ]] && mapfile -t IMAGE_IDS < <(sort -u <<< "$ids")
    else
        warn "No se pudo obtener la lista de imágenes: $ids"
    fi

    rpt "" "Detalle por imagen (inspect e historial de construcción en evidencias/imagenes/):"
    local id short idir raw line tags created size
    for id in "${IMAGE_IDS[@]}"; do
        short=$(short_id "$id")
        idir="$EV/imagenes/$short"
        mkdir -p -- "$idir"
        collect "$idir/inspect.json" dk image inspect "$id"
        collect "$idir/historial.txt" dk history --no-trunc "$id"
        tags="" created="" size=""
        if raw=$(dk image inspect --format "$IMAGE_FMT" "$id" 2>&1); then
            while IFS= read -r line; do
                case ${line%%=*} in
                    tags) tags=${line#*=} ;;
                    created) created=${line#*=} ;;
                    size) size=${line#*=} ;;
                esac
            done <<< "$raw"
        else
            warn "No se pudo inspeccionar la imagen $short: $raw"
        fi
        tags=${tags//[\[\]\"]/}
        [[ $tags == null || -z $tags ]] && tags="<sin etiqueta>"
        tags=${tags//,/, }
        IMAGE_TAGS[$id]=$tags
        if [[ $size =~ ^[0-9]+$ ]]; then size="$(( size / 1000000 )) MB"; fi
        rpt "- $short  $tags  (creada: ${created//\"/}, tamaño: ${size:-?})"
    done

    local dangling
    dangling=$(dk images -q --no-trunc -f dangling=true 2>/dev/null | sort -u | grep -c . || true)
    if (( dangling > 0 )); then
        add_finding INFO "Imágenes" "Imágenes huérfanas (dangling) sin etiqueta: $dangling." \
            "Revíselas y, tras preservar las evidencias, elimínelas con docker image prune."
    fi
    ok "Imágenes analizadas: ${#IMAGE_IDS[@]}"
}

audit_networks() {
    step "Redes"
    section "REDES"
    collect "$EV/redes/listado.txt" dk network ls --no-trunc
    rpt_file "$EV/redes/listado.txt"
    local list id name
    if list=$(dk network ls --no-trunc --format '{{.ID}} {{.Name}}' 2>&1); then
        while read -r id name; do
            [[ -n $id ]] || continue
            NETWORKS_TOTAL=$((NETWORKS_TOTAL + 1))
            collect "$EV/redes/$(safe_name "$name")_$(short_id "$id").json" dk network inspect "$id"
        done <<< "$list"
    else
        warn "No se pudo obtener la lista de redes: $list"
    fi
    ok "Redes analizadas: $NETWORKS_TOTAL"
}

audit_volumes() {
    step "Volúmenes"
    section "VOLÚMENES"
    collect "$EV/volumenes/listado.txt" dk volume ls
    rpt_file "$EV/volumenes/listado.txt"
    local list name
    if list=$(dk volume ls -q 2>&1); then
        while IFS= read -r name; do
            [[ -n $name ]] || continue
            VOLUMES_TOTAL=$((VOLUMES_TOTAL + 1))
            collect "$EV/volumenes/$(safe_name "$name").json" dk volume inspect "$name"
        done <<< "$list"
    else
        warn "No se pudo obtener la lista de volúmenes: $list"
    fi
    local dangling
    dangling=$(dk volume ls -q -f dangling=true 2>/dev/null | grep -c . || true)
    if (( dangling > 0 )); then
        add_finding INFO "Volúmenes" "Volúmenes que no usa ningún contenedor: $dangling." \
            "Revise su contenido: pueden contener datos de contenedores ya eliminados."
    fi
    ok "Volúmenes analizados: $VOLUMES_TOTAL"
}

audit_plugins() {
    step "Plugins"
    section "PLUGINS"
    collect "$EV/plugins/listado.txt" dk plugin ls --no-trunc
    rpt_file "$EV/plugins/listado.txt"
    local list id name
    if list=$(dk plugin ls --no-trunc --format '{{.ID}} {{.Name}}' 2>&1); then
        while read -r id name; do
            [[ -n $id ]] || continue
            PLUGINS_TOTAL=$((PLUGINS_TOTAL + 1))
            collect "$EV/plugins/$(safe_name "$name")_$(short_id "$id").json" dk plugin inspect "$id"
        done <<< "$list"
    else
        warn "No se pudo obtener la lista de plugins: $list"
    fi
    ok "Plugins analizados: $PLUGINS_TOTAL"
}

# --- Análisis estático -------------------------------------------------------------

find_project_files() {
    local f
    while IFS= read -r -d '' f; do
        case ${f##*/} in
            *compose*) COMPOSE_FILES+=("$f") ;;
            *) DOCKERFILES+=("$f") ;;
        esac
    done < <(find "$PROJECT_DIR" -maxdepth "$SEARCH_DEPTH" -xdev \
        \( -type d \( -name .git -o -name node_modules -o -name vendor -o -name venv -o -name .venv \
                      -o -name __pycache__ -o -name 'docker_audit_*' \) -prune \) -o \
        \( -type f ! -name '*.dockerignore' \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \
              -o -name '*.dockerfile' -o -name Containerfile -o -name 'Containerfile.*' \
              -o -name compose.yaml -o -name compose.yml -o -name docker-compose.yaml -o -name docker-compose.yml \
              -o -name 'compose.*.yaml' -o -name 'compose.*.yml' \
              -o -name 'docker-compose.*.yaml' -o -name 'docker-compose.*.yml' \) -print0 \) 2>/dev/null | sort -z)
}

# Comprobaciones básicas de un Dockerfile; no requieren herramientas externas.
check_dockerfile() {
    local f=$1 rel=${1#"$PROJECT_DIR"/}
    local obj="Fichero $rel" line n=0 cont=0 instr rest img tok name user="" stages=" "
    local -a toks
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        if (( cont )); then
            [[ $line == *\\ ]] || cont=0
            continue
        fi
        line=${line#"${line%%[![:space:]]*}"}
        [[ -z $line || $line == \#* ]] && continue
        [[ $line == *\\ ]] && cont=1
        instr=${line%%[[:space:]]*}
        instr=${instr^^}
        rest=${line#*[[:space:]]}
        read -ra toks <<< "$rest"
        case $instr in
            FROM)
                user=""
                img=""
                for tok in "${toks[@]}"; do
                    [[ $tok == --* ]] && continue
                    img=$tok
                    break
                done
                [[ ${rest,,} =~ [[:space:]]as[[:space:]]+([^[:space:]]+) ]] && stages+="${BASH_REMATCH[1]} "
                if [[ -n $img && $stages != *" ${img,,} "* ]] && image_unpinned "$img"; then
                    add_finding BAJO "$obj (línea $n)" "La imagen base no fija la versión ($img)." \
                        "Use una etiqueta de versión concreta o un digest."
                fi
                ;;
            USER)
                user=${rest%%[[:space:]]*}
                ;;
            ENV | ARG)
                for tok in "${toks[@]}"; do
                    if [[ $instr == ENV && $rest != *=* ]]; then
                        name=$tok
                    elif [[ $tok == *=* || $instr == ARG ]]; then
                        name=${tok%%=*}
                    else
                        continue
                    fi
                    if is_secret_name "$name"; then
                        add_finding MEDIO "$obj (línea $n)" "Define un posible secreto en $instr ($name): queda guardado en la imagen." \
                            "Use secretos de BuildKit (RUN --mount=type=secret) o variables en tiempo de ejecución."
                    fi
                    [[ $instr == ENV && $rest != *=* ]] && break
                done
                ;;
            ADD)
                if [[ $rest == *http://* || $rest == *https://* ]]; then
                    add_finding BAJO "$obj (línea $n)" "Usa ADD para descargar ficheros remotos." \
                        "Use COPY para ficheros locales y descargue con verificación de checksum (ADD --checksum o RUN curl + sha256sum)."
                fi
                ;;
        esac
    done < "$f"
    user=${user%%:*}
    if [[ -z $user || $user == root || $user == 0 ]]; then
        add_finding MEDIO "$obj" "La imagen final se ejecuta como root (no hay un USER sin privilegios en la última etapa)." \
            "Añada un usuario sin privilegios y la instrucción USER al final del Dockerfile."
    fi
}

# grep_rule FICHERO OBJETO SEVERIDAD REGEX DESCRIPCIÓN RECOMENDACIÓN [REGEX_EXCLUSIÓN]
grep_rule() {
    local file=$1 obj=$2 sev=$3 regex=$4 desc=$5 rec=$6 exclude=${7:-} lines
    lines=$(grep -niE -- "$regex" "$file" 2>/dev/null || true)
    if [[ -n $exclude && -n $lines ]]; then
        lines=$(grep -viE -- "$exclude" <<< "$lines" || true)
    fi
    [[ -n $lines ]] || return 0
    lines=$(cut -d: -f1 <<< "$lines" | paste -sd, -)
    add_finding "$sev" "$obj ($([[ $lines == *,* ]] && echo líneas || echo línea) ${lines//,/, })" "$desc" "$rec"
}

# Comprobaciones heurísticas de un fichero compose (Checkov no analiza compose).
check_compose() {
    local f=$1 rel=${1#"$PROJECT_DIR"/}
    local obj="Fichero $rel" nc='^[^#]*'
    grep_rule "$f" "$obj" CRITICO "${nc}privileged:[[:space:]]*[\"']?true" \
        "Define un servicio privilegiado (privileged: true)." "Elimine privileged y añada solo las capacidades imprescindibles."
    grep_rule "$f" "$obj" CRITICO "${nc}(docker|containerd|podman|crio)\.sock" \
        "Monta el socket del daemon de contenedores." "No monte el socket de Docker en los servicios."
    grep_rule "$f" "$obj" CRITICO "${nc}-[[:space:]]*[\"']?/:" \
        "Monta el sistema de ficheros raíz del host (/)." "Monte solo los directorios imprescindibles."
    grep_rule "$f" "$obj" ALTO "${nc}network_mode:[[:space:]]*[\"']?host" \
        "Usa la red del host (network_mode: host)." "Use redes de compose y publique solo los puertos necesarios."
    grep_rule "$f" "$obj" ALTO "${nc}pid:[[:space:]]*[\"']?host" \
        "Comparte el espacio de procesos del host (pid: host)." "Elimine pid: host."
    grep_rule "$f" "$obj" MEDIO "${nc}ipc:[[:space:]]*[\"']?host" \
        "Comparte la memoria IPC del host (ipc: host)." "Elimine ipc: host."
    grep_rule "$f" "$obj" ALTO "${nc}(seccomp|systempaths)[:=]unconfined" \
        "Desactiva seccomp o desenmascara rutas del sistema (unconfined)." "Elimine la opción unconfined de security_opt."
    grep_rule "$f" "$obj" MEDIO "${nc}apparmor[:=]unconfined" \
        "Desactiva AppArmor (apparmor:unconfined)." "Elimine la opción de security_opt."
    grep_rule "$f" "$obj" MEDIO "${nc}cap_add:" \
        "Añade capacidades (cap_add)." "Compruebe que son imprescindibles; parta de cap_drop: [ALL]."
    grep_rule "$f" "$obj" MEDIO "${nc}devices:" \
        "Da acceso a dispositivos del host (devices)." "Elimine devices salvo que sea imprescindible."
    grep_rule "$f" "$obj" MEDIO "${nc}(${SECRET_WORDS})[a-z0-9_]*[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[^\$[:space:]\"'{]" \
        "Contiene posibles secretos escritos en claro." "Use secrets de compose o variables de un fichero .env no versionado." \
        '_FILE["'"'"']?[[:space:]]*[:=]'

    local line n img
    while IFS= read -r line; do
        n=${line%%:*}
        img=${line#*:}
        img=${img#*image:}
        img=${img%%#*}
        img=${img//[\"\']/}
        img=${img//[[:space:]]/}
        if [[ -n $img ]] && image_unpinned "$img"; then
            add_finding BAJO "$obj (línea $n)" "Usa una imagen sin versión fija ($img)." \
                "Use una etiqueta de versión concreta o un digest."
        fi
    done < <(grep -nE '^[[:space:]]*image:' "$f" 2>/dev/null)
}

run_checkov() {
    rpt "" "--- Checkov (Dockerfile) ---"
    if (( !HAVE_CHECKOV )); then
        rpt "Checkov no está instalado (opcional: pip install -r requirements.txt)."
        return
    fi
    if (( ${#DOCKERFILES[@]} == 0 )); then
        rpt "No hay Dockerfile que analizar."
        return
    fi
    local out="$EV/analisis_estatico/checkov" args=() f rc failed
    mkdir -p -- "$out"
    for f in "${DOCKERFILES[@]}"; do args+=(-f "${f#"$PROJECT_DIR"/}"); done
    # Código 0: sin fallos; 1: hay comprobaciones fallidas; otro: error de Checkov.
    (cd -- "$PROJECT_DIR" && checkov --framework dockerfile --skip-download --compact --quiet \
        -o cli -o json --output-file-path "$out" "${args[@]}") > "$out/checkov.log" 2>&1 < /dev/null
    rc=$?
    if (( rc > 1 )) || [[ ! -s $out/results_json.json ]]; then
        warn "Checkov terminó con error (código $rc); ver ${out#"$AUDIT_DIR"/}/checkov.log"
        return
    fi
    rpt_file "$out/results_cli.txt"
    failed=$(grep -o '"failed": [0-9]*' "$out/results_json.json" | head -n 1 | grep -o '[0-9]*$')
    if (( ${failed:-0} > 0 )); then
        add_finding BAJO "Análisis estático" "Comprobaciones fallidas en Checkov: $failed (detalle en la sección de análisis estático)." \
            "Corrija los puntos indicados por Checkov."
    fi
}

run_hadolint() {
    rpt "" "--- Hadolint ---"
    if (( !HAVE_HADOLINT )); then
        rpt "Hadolint no está instalado (opcional: https://github.com/hadolint/hadolint)."
        return
    fi
    if (( ${#DOCKERFILES[@]} == 0 )); then
        rpt "No hay Dockerfile que analizar."
        return
    fi
    local out="$EV/analisis_estatico/hadolint.txt" f rel rc issues=0
    : > "$out"
    for f in "${DOCKERFILES[@]}"; do
        rel=${f#"$PROJECT_DIR"/}
        printf '### %s\n' "$rel" >> "$out"
        # Código 0: sin avisos; 1: hay avisos; otro: error de Hadolint.
        (cd -- "$PROJECT_DIR" && hadolint --no-color "$rel") >> "$out" 2>&1 < /dev/null
        rc=$?
        (( rc > 1 )) && warn "Hadolint falló con $rel (código $rc); ver ${out#"$AUDIT_DIR"/}"
    done
    issues=$(grep -cE ' (DL|SC)[0-9]+ ' "$out" || true)
    rpt_file "$out"
    if (( issues > 0 )); then
        add_finding BAJO "Análisis estático" "Avisos de buenas prácticas de Hadolint: $issues (detalle en la sección de análisis estático)." \
            "Corrija los puntos indicados por Hadolint."
    fi
}

audit_static() {
    step "Análisis estático de Dockerfile y compose"
    section "ANÁLISIS ESTÁTICO (DOCKERFILE Y COMPOSE)"
    if [[ -z $PROJECT_DIR ]]; then
        rpt "Omitido a petición del usuario."
        ok "Omitido"
        return
    fi
    find_project_files
    rpt "Directorio analizado: $PROJECT_DIR (profundidad máxima: $SEARCH_DEPTH)"
    if (( ${#DOCKERFILES[@]} + ${#COMPOSE_FILES[@]} == 0 )); then
        rpt "No se encontraron Dockerfile ni ficheros compose."
        ok "No hay ficheros que analizar"
        return
    fi

    local f rel copy="$EV/analisis_estatico/ficheros"
    rpt "" "Ficheros analizados (copia en evidencias/analisis_estatico/ficheros/):"
    for f in "${DOCKERFILES[@]}" "${COMPOSE_FILES[@]}"; do
        rel=${f#"$PROJECT_DIR"/}
        mkdir -p -- "$copy/$(dirname -- "$rel")"
        cp -p -- "$f" "$copy/$rel"
        rpt "  $(file_hash "$f")  $rel"
    done

    for f in "${DOCKERFILES[@]}"; do check_dockerfile "$f"; done
    for f in "${COMPOSE_FILES[@]}"; do check_compose "$f"; done
    rpt "" "Las comprobaciones propias de DockerAuditor sobre estos ficheros aparecen en «Hallazgos de seguridad»."
    if (( ${#COMPOSE_FILES[@]} )); then
        rpt "Los ficheros compose solo se revisan con esas reglas propias: Checkov no analiza compose."
    fi
    run_checkov
    run_hadolint
    ok "Ficheros analizados: ${#DOCKERFILES[@]} Dockerfile y ${#COMPOSE_FILES[@]} compose"
}

audit_vulnerabilities() {
    step "Vulnerabilidades de las imágenes (Trivy)"
    section "VULNERABILIDADES DE LAS IMÁGENES (TRIVY)"
    if (( !HAVE_TRIVY )); then
        rpt "Trivy no está instalado: se omite este análisis (opcional: https://trivy.dev)."
        ok "Omitido (Trivy no instalado)"
        return
    fi
    if (( ${#IMAGE_IDS[@]} == 0 )); then
        rpt "No hay imágenes que analizar."
        ok "No hay imágenes"
        return
    fi
    rpt "Severidades analizadas: CRITICAL y HIGH. Detalle en evidencias/imagenes/<id>/trivy.txt" ""

    local id short idir tar crit high
    for id in "${IMAGE_IDS[@]}"; do
        short=$(short_id "$id")
        idir="$EV/imagenes/$short"
        tar="$TMP_DIR/$short.tar"
        say "  Analizando $short (${IMAGE_TAGS[$id]:-})..."
        # Se analiza la copia exportada de la imagen local, no la del registro.
        if ! dk save "$id" > "$tar" 2> "$idir/trivy.log"; then
            warn "No se pudo exportar la imagen $short para Trivy; ver ${idir#"$AUDIT_DIR"/}/trivy.log"
            rm -f -- "$tar"
            continue
        fi
        if trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --format json \
            -o "$idir/trivy.json" --input "$tar" >> "$idir/trivy.log" 2>&1 < /dev/null; then
            trivy convert --quiet --format table -o "$idir/trivy.txt" "$idir/trivy.json" >> "$idir/trivy.log" 2>&1 < /dev/null
            crit=$(grep -c '"Severity": "CRITICAL"' "$idir/trivy.json" || true)
            high=$(grep -c '"Severity": "HIGH"' "$idir/trivy.json" || true)
            rpt "$(pad "$short" 14) CRITICAL: $(pad "$crit" 5) HIGH: $(pad "$high" 5) ${IMAGE_TAGS[$id]:-}"
            if (( crit > 0 )); then
                add_finding ALTO "Imagen $short (${IMAGE_TAGS[$id]:-})" "Vulnerabilidades según Trivy: críticas $crit, altas $high." \
                    "Actualice la imagen base y los paquetes, reconstruya y vuelva a desplegar."
            elif (( high > 0 )); then
                add_finding MEDIO "Imagen $short (${IMAGE_TAGS[$id]:-})" "Vulnerabilidades según Trivy: críticas 0, altas $high." \
                    "Actualice la imagen base y los paquetes, reconstruya y vuelva a desplegar."
            fi
        else
            warn "Trivy falló al analizar la imagen $short; ver ${idir#"$AUDIT_DIR"/}/trivy.log"
        fi
        rm -f -- "$tar"
    done
    ok "Imágenes analizadas con Trivy: ${#IMAGE_IDS[@]}"
}

# --- Resultados ------------------------------------------------------------------

summary_lines() {
    local running=${CSTATE[running]:-0} paused=${CSTATE[paused]:-0} created=${CSTATE[created]:-0}
    local stopped=$(( ${CSTATE[exited]:-0} + ${CSTATE[dead]:-0} ))
    local others=$(( ${#CONTAINER_IDS[@]} - running - paused - created - stopped ))
    local detail="en ejecución: $running, pausados: $paused, detenidos: $stopped, creados: $created"
    (( others > 0 )) && detail+=", otros: $others"
    kv "Docker:" "${SERVER_VERSION:-desconocido}"
    kv "Contenedores:" "${#CONTAINER_IDS[@]} ($detail)"
    kv "Imágenes:" "${#IMAGE_IDS[@]}"
    kv "Redes:" "$NETWORKS_TOTAL"
    kv "Volúmenes:" "$VOLUMES_TOTAL"
    kv "Plugins:" "$PLUGINS_TOTAL"
    kv "Hallazgos:" "${#FINDINGS[@]} ($(findings_breakdown))"
    kv "Avisos de ejecución:" "${#WARNINGS[@]}"
}

write_findings() {
    section "HALLAZGOS DE SEGURIDAD"
    rpt "Total: ${#FINDINGS[@]} ($(findings_breakdown))"
    if (( ${#FINDINGS[@]} == 0 )); then
        rpt "No se detectaron configuraciones inseguras."
        return
    fi
    local sev f s obj desc rec
    for sev in "${SEVERITIES[@]}"; do
        for f in "${FINDINGS[@]}"; do
            IFS=$SEP read -r s obj desc rec <<< "$f"
            [[ $s == "$sev" ]] || continue
            rpt "" "[$(sev_label "$s")] $obj" "    $desc" "    Recomendación: $rec"
        done
    done
}

write_json() {
    local first=1 f s obj desc rec
    {
        printf '{\n'
        printf '  "herramienta": "DockerAuditor",\n'
        printf '  "version": %s,\n' "$(json_str "$VERSION")"
        printf '  "inicio_utc": %s,\n' "$(json_str "$START_UTC")"
        printf '  "fin_utc": %s,\n' "$(json_str "$END_UTC")"
        printf '  "equipo": %s,\n' "$(json_str "$HOST_NAME")"
        printf '  "docker": %s,\n' "$(json_str "$SERVER_VERSION")"
        printf '  "resumen": {"contenedores": %d, "en_ejecucion": %d, "pausados": %d, "imagenes": %d, "redes": %d, "volumenes": %d, "plugins": %d, "avisos": %d},\n' \
            "${#CONTAINER_IDS[@]}" "${CSTATE[running]:-0}" "${CSTATE[paused]:-0}" "${#IMAGE_IDS[@]}" \
            "$NETWORKS_TOTAL" "$VOLUMES_TOTAL" "$PLUGINS_TOTAL" "${#WARNINGS[@]}"
        printf '  "hallazgos": ['
        for f in "${FINDINGS[@]}"; do
            IFS=$SEP read -r s obj desc rec <<< "$f"
            (( first )) || printf ','
            first=0
            printf '\n    {"severidad": %s, "objeto": %s, "descripcion": %s, "recomendacion": %s}' \
                "$(json_str "$s")" "$(json_str "$obj")" "$(json_str "$desc")" "$(json_str "$rec")"
        done
        (( first )) || printf '\n  '
        printf ']\n}\n'
    } > "$AUDIT_DIR/hallazgos.json"
}

finish() {
    step "Generando informe e integridad de las evidencias"
    write_findings

    if (( ${#WARNINGS[@]} )); then
        section "AVISOS DE EJECUCIÓN"
        rpt "Estos pasos fallaron; el informe puede estar incompleto:"
        local w
        for w in "${WARNINGS[@]}"; do rpt "  - $w"; done
    fi

    END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    section "TABLA RESUMEN"
    summary_lines >> "$REPORT"

    section "INTEGRIDAD"
    {
        kv "Fin (UTC):" "$END_UTC"
        say "Los hashes SHA-256 de todos los ficheros están en SHA256SUMS."
        say "Para verificarlos: cd \"$AUDIT_DIR\" && sha256sum -c SHA256SUMS"
    } >> "$REPORT"
    write_json

    # A partir de aquí el informe no puede cambiar: los avisos ya no se escriben en él.
    REPORT=""
    cleanup
    (cd -- "$AUDIT_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 "${SHA_CMD[@]}") \
        > "$AUDIT_DIR/SHA256SUMS" || warn "No se pudieron calcular los hashes de las evidencias."
    ARCHIVE="$OUTPUT_DIR/$AUDIT_NAME.tar.gz"
    ARCHIVE_HASH=""
    if tar -czf "$ARCHIVE" -C "$OUTPUT_DIR" "$AUDIT_NAME"; then
        (cd -- "$OUTPUT_DIR" && "${SHA_CMD[@]}" "$AUDIT_NAME.tar.gz") > "$ARCHIVE.sha256"
        ARCHIVE_HASH=$(file_hash "$ARCHIVE")
    else
        warn "No se pudo crear el archivo $ARCHIVE."
        ARCHIVE=""
    fi
    ok "Informe y hashes generados"
}

print_summary() {
    printf '\n%s================ Resumen de la auditoría ================%s\n' "$C_BOLD" "$C_RST"
    summary_lines
    say "========================================================="

    local sev f s obj desc rec color shown=0 total
    total=$(( $(count_sev CRITICO) + $(count_sev ALTO) ))
    (( total )) && say "" "Hallazgos críticos y altos:"
    for sev in CRITICO ALTO; do
        color=$([[ $sev == CRITICO ]] && echo "$C_RED" || echo "$C_YEL")
        for f in "${FINDINGS[@]}"; do
            IFS=$SEP read -r s obj desc rec <<< "$f"
            [[ $s == "$sev" ]] || continue
            (( shown < 10 )) && printf '  %s[%s]%s %s: %s\n' "$color" "$(sev_label "$s")" "$C_RST" "$obj" "$desc"
            shown=$((shown + 1))
        done
    done
    (( total > 10 )) && say "  ... y $((total - 10)) más en el informe."

    say ""
    kv "Informe:" "$AUDIT_DIR/informe.txt"
    kv "Hallazgos (JSON):" "$AUDIT_DIR/hallazgos.json"
    kv "Evidencias:" "$EV/"
    if [[ -n $ARCHIVE ]]; then
        kv "Archivo comprimido:" "$ARCHIVE"
        kv "SHA-256 del archivo:" "$ARCHIVE_HASH"
    fi
    say ""
    if (( ${#WARNINGS[@]} )); then
        printf '%sLa auditoría terminó con %d avisos: el informe puede estar incompleto (ver la sección «Avisos de ejecución»).%s\n' \
            "$C_YEL" "${#WARNINGS[@]}" "$C_RST"
        return 2
    fi
    printf '%sLa auditoría se completó correctamente.%s\n' "$C_GRN" "$C_RST"
}

main() {
    trap cleanup EXIT
    trap interrupted INT TERM

    print_banner
    if (( $# )); then
        say "Aviso: DockerAuditor no usa opciones ni argumentos; se ignoran: $*" >&2
    fi
    check_dependencies
    setup_docker_access
    choose_directories
    prepare_output
    write_header
    say "" "Iniciando la auditoría en $AUDIT_DIR"

    audit_general
    audit_daemon
    audit_system_df
    audit_containers
    audit_images
    audit_networks
    audit_volumes
    audit_plugins
    audit_static
    audit_vulnerabilities
    finish
    print_summary
}

main "$@"
