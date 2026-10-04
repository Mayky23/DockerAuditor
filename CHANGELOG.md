# Changelog

Todos los cambios relevantes de DockerAuditor.

## [3.0] - 2026-10-04

### Añadido
- Detección de configuraciones inseguras con cinco niveles de severidad: contenedores privilegiados, socket de Docker montado, namespaces del host, capacidades peligrosas, seccomp/AppArmor desactivados, rutas sensibles montadas, ejecución como root, secretos en variables de entorno, puertos expuestos, imágenes sin versión fija y falta de límites de recursos.
- Revisión del daemon y del host: opciones de seguridad, rootless/userns-remap, `live-restore`, registros inseguros, `icc`, permisos del socket, grupo `docker`, API TCP sin TLS, `daemon.json` y eventos recientes.
- Evidencias por contenedor (`inspect`, logs con marca de tiempo, `docker diff`, procesos e historial de shell copiado con `docker cp`), por imagen (`inspect` e historial de construcción) y por red, volumen y plugin.
- Reglas propias para Dockerfile y docker-compose, e integración opcional con Hadolint y Trivy.
- Directorio de evidencias, resumen `hallazgos.json`, hashes `SHA256SUMS` y archivo `.tar.gz` con su hash.
- Uso de `sudo` solo cuando el usuario no tiene acceso al daemon, sin auditar otro daemon si hay `DOCKER_HOST` o contextos.
- Códigos de salida (0, 1, 2 y 130) y sección «Avisos de ejecución» cuando algún paso falla.
- CI con ShellCheck y una auditoría real en GitHub Actions.

### Corregido
- El script indicaba que la auditoría se había completado aunque Docker estuviera parado, no hubiera permisos o no se pudiera escribir el informe.
- Los contenedores pausados se contaban como activos y los recuentos se pedían varias veces, con resultados que podían no coincidir.
- Checkov: su código de salida 1 (hay fallos) se interpretaba como error, su JSON salía corrupto al mezclarse con los logs, se ejecutaba sobre todo el directorio actual y dejaba `checkov_output.json` en él.
- La tabla resumen quedaba desalineada en las filas con tildes.
- Las rutas con `~` o con barra final no funcionaban.
- El banner tenía caracteres incorrectos.

### Cambiado
- Se eliminan las pausas artificiales (`sleep`) y el `clear` inicial.
- Checkov se limita a los Dockerfile encontrados (`--framework dockerfile`) y no descarga datos externos (`--skip-download`).
- El informe y las evidencias se crean con permisos restringidos (`umask 077`).
- README reescrito; se eliminan las imágenes del repositorio.

## [1.2] - 2025-03-15

### Añadido
- Integración con Checkov.

### Cambiado
- Actualización estética.
- Se dejan de recopilar `inspect`, logs e historiales (recuperado en la 3.0).

## [1.1] - 2025-03-09

### Añadido
- Capturas de pantalla en el README.

## [1.0] - 2025-03-09

### Añadido
- Primera versión: información general, contenedores, imágenes, redes, volúmenes, plugins y tabla resumen.
