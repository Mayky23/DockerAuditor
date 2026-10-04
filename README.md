# 🔎 DockerAuditor

**DockerAuditor** es una herramienta de auditoría forense y de seguridad para entornos Docker, escrita en Bash.

Recopila evidencias del daemon, los contenedores, las imágenes, las redes, los volúmenes y los plugins. Además, detecta configuraciones inseguras y genera un informe legible, un resumen en JSON y hashes SHA-256 que permiten demostrar que las evidencias no se han modificado.

La herramienta **solo lee**: no ejecuta nada dentro de los contenedores ni cambia su estado.

## Qué hace

### Recopilación de evidencias

| Ámbito | Qué se guarda |
| --- | --- |
| Daemon | `docker version`, `docker info` (texto y JSON), uso de disco, contextos, `daemon.json` y eventos de las últimas 24 h |
| Host | Permisos del socket de Docker, miembros del grupo `docker`, procesos `dockerd` y puertos en escucha |
| Contenedores | `inspect` completo, logs con marca de tiempo, cambios en el sistema de ficheros (`docker diff`), procesos en ejecución e historial de shell (`.bash_history`, `.ash_history`…), copiado con `docker cp` |
| Imágenes | `inspect`, historial de construcción (`docker history --no-trunc`) y digests |
| Redes, volúmenes y plugins | Listado e `inspect` de cada uno |

Los identificadores y los comandos se guardan completos (`--no-trunc`).

### Comprobaciones de seguridad

| Severidad | Ejemplos de lo que detecta |
| --- | --- |
| **CRÍTICO** | Contenedores `--privileged`, socket de Docker montado dentro de un contenedor, raíz del host (`/`) montada, socket de Docker escribible por cualquiera, API TCP sin TLS |
| **ALTO** | `--pid=host`, `--network=host`, capacidades peligrosas (`SYS_ADMIN`, `NET_ADMIN`…), `seccomp=unconfined`, rutas sensibles del host montadas con escritura, imágenes con vulnerabilidades críticas |
| **MEDIO** | Contenedores que se ejecutan como root, posibles secretos en variables de entorno (sin mostrar su valor), acceso a dispositivos, AppArmor desactivado, contenedores sin logs |
| **BAJO** | Imágenes sin versión fija (`latest`), puertos publicados en todas las interfaces, falta de límites de memoria, CPU o PIDs, rootfs escribible, `icc` activado |
| **INFO** | Sin modo rootless ni `userns-remap`, imágenes y volúmenes huérfanos, avisos de `docker info` |

### Análisis estático del proyecto

Si se indica un directorio de proyecto, se buscan `Dockerfile`, `Containerfile` y ficheros `compose`. Los ficheros encontrados se copian a las evidencias con su hash y se revisan así:

- **Dockerfile:** reglas propias (usuario root, imagen base sin versión, secretos en `ENV`/`ARG`, `ADD` remoto), además de [Checkov](https://www.checkov.io/) y [Hadolint](https://github.com/hadolint/hadolint) si están instalados.
- **docker-compose:** reglas propias (`privileged`, socket de Docker, `network_mode: host`, `cap_add`, secretos en claro…). Checkov no analiza ficheros compose.

### Vulnerabilidades de las imágenes

Si [Trivy](https://trivy.dev/) está instalado, se analiza cada imagen local buscando vulnerabilidades `CRITICAL` y `HIGH`. Se analiza la copia exportada con `docker save`, no la imagen del registro.

## ⚠️ Requisitos

**Obligatorios**

- Linux con **Bash 4.4** o superior.
- Docker instalado, con el daemon en marcha.
- Acceso al daemon: ser root, pertenecer al grupo `docker` o tener `sudo`. El script solo usa `sudo` si hace falta.
- `sha256sum` (o `shasum`) y `tar`, presentes en cualquier distribución.

**Opcionales**, se usan automáticamente si están instalados:

| Herramienta | Para qué | Instalación |
| --- | --- | --- |
| Checkov | Buenas prácticas en Dockerfile | `pip install -r requirements.txt` |
| Hadolint | Buenas prácticas en Dockerfile | [Releases de Hadolint](https://github.com/hadolint/hadolint/releases) |
| Trivy | Vulnerabilidades de las imágenes | [Instalación de Trivy](https://trivy.dev/) |

## 🛠️ Instalación

```bash
git clone https://github.com/Mayky23/DockerAuditor.git
cd DockerAuditor
```

Para usar Checkov, instálalo preferiblemente en un entorno virtual:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🖥️ Uso

```bash
./DockerAuditor.sh
```

La herramienta no tiene opciones. Al empezar hace dos preguntas:

1. **Directorio donde guardar el informe.** Pulsa Enter para usar el directorio actual. Se admite `~`.
2. **Directorio del proyecto** con Dockerfile o compose que analizar. Pulsa Enter para usar el directorio actual o escribe `n` para omitir este paso.

Si el usuario no tiene acceso al socket de Docker, el script lo indica y pide la contraseña de `sudo`.

Las respuestas también pueden llegar por la entrada estándar, lo que permite automatizar la auditoría (cron, CI…):

```bash
printf '%s\n' /srv/auditorias n | ./DockerAuditor.sh
```

## 📁 Resultado

Cada ejecución crea un directorio con el nombre del equipo y la fecha en UTC, y un archivo comprimido con su hash:

```text
docker_audit_<equipo>_<AAAAMMDDTHHMMSSZ>/
├── informe.txt            Informe completo y legible
├── hallazgos.json         Resumen y hallazgos en JSON
├── SHA256SUMS             Hash SHA-256 de todos los ficheros
└── evidencias/
    ├── sistema/           version, info, daemon.json, eventos, socket, procesos dockerd…
    ├── contenedores/      <nombre>_<id>/ inspect.json, logs.txt, diff.txt, procesos.txt, historial/
    ├── imagenes/          <id>/ inspect.json, historial.txt, trivy.json, trivy.txt
    ├── redes/
    ├── volumenes/
    ├── plugins/
    └── analisis_estatico/ copia de los ficheros analizados y resultados de Checkov y Hadolint
docker_audit_<equipo>_<AAAAMMDDTHHMMSSZ>.tar.gz
docker_audit_<equipo>_<AAAAMMDDTHHMMSSZ>.tar.gz.sha256
```

El informe incluye estas secciones:

- Metadatos de la auditoría: equipo, usuario, hora UTC y local, y endpoint del daemon.
- Una sección por cada ámbito auditado.
- Los hallazgos ordenados por severidad, con su recomendación.
- Una tabla resumen.

En la consola se muestran el progreso, la tabla resumen y los hallazgos críticos y altos.

### Verificar la integridad

```bash
sha256sum -c docker_audit_<equipo>_<fecha>.tar.gz.sha256
cd docker_audit_<equipo>_<fecha> && sha256sum -c SHA256SUMS
```

### Códigos de salida

| Código | Significado |
| --- | --- |
| `0` | Auditoría completada sin avisos |
| `1` | Error fatal: no se pudo auditar (Docker no instalado, daemon parado, sin permisos…) |
| `2` | Auditoría completada con avisos: algún paso falló y el informe lo indica en «Avisos de ejecución» |
| `130` | Auditoría interrumpida con Ctrl+C |

## 🔐 Consideraciones forenses y de seguridad

- **Las evidencias son sensibles.** Los ficheros `inspect.json` contienen las variables de entorno con sus valores, y los logs pueden contener datos personales. Por eso se crean con permisos `700`/`600`. El informe muestra solo el *nombre* de las variables sospechosas, nunca su valor.
- **Mínima huella.** No se usa `docker exec`. `docker cp`, usado para el historial de shell, y `docker save`, usado para Trivy, generan eventos de lectura en el daemon, pero no modifican los contenedores ni las imágenes.
- **sudo y contextos.** `sudo` ignora `DOCKER_HOST` y los contextos de Docker del usuario. Si están configurados y el usuario no tiene acceso, la auditoría se detiene en lugar de auditar otro daemon.
- **Daemons remotos o Docker Desktop.** Las comprobaciones del host (socket, procesos, puertos y `daemon.json`) solo se hacen si el daemon es accesible por un socket local en Linux.
- **Trivy** necesita descargar su base de datos de vulnerabilidades la primera vez y espacio en disco temporal para exportar cada imagen.
- **Reglas de compose.** Las reglas para compose son heurísticas, basadas en patrones: confirma los hallazgos revisando el fichero.

## ⚙️ Ajustes

Al principio de `DockerAuditor.sh` hay tres constantes que se pueden editar:

| Constante | Valor por defecto | Uso |
| --- | --- | --- |
| `LOG_TAIL` | `1000` | Líneas de log que se guardan por contenedor |
| `EVENTS_SINCE` | `24h` | Antigüedad de los eventos del daemon que se recopilan |
| `SEARCH_DEPTH` | `3` | Profundidad al buscar Dockerfile y compose en el proyecto |
