#!/bin/bash
# DockerAuditor - Auditoría Forense de Docker
# Este script recopila información detallada del entorno Docker para análisis forense.
# Recopila:
#   - Información general (versiones, info del daemon, uso de disco)
#   - Auditoría de contenedores (inspección, comando de inicio, logs y, en lo posible, historial interno)
#   - Auditoría de imágenes (inspección y historial de construcción)
#   - Auditoría de redes, volúmenes y plugins
#   - Un resumen final en forma de tabla
#
# Uso: ./DockerAuditor.sh
#
# Autor: [Tu Nombre]
# Fecha: [Fecha Actual]

# --- Banner ---
clear
clear
echo "   ____             _                  _             _ _ _      "
echo "  |  _ \  ___   ___| | _____ _ __     / \  _   _  __| (_) |_ ___  _ __ "
echo "  | | | |/ _ \ / __| |/ / _ \ '__|   / _ \| | | |/ _\ | | __/ _ \| __|"
echo "  | |_| | (_) | (__|   <  __/ |     / ___ \ |_| | (_| | | || (_) | |   "
echo "  |____/ \___/ \___|_|\_\___|_|    /_/   \_\__,_|\__,_|_|\__\___/|_|   "
echo ""
echo "---- By: MARH ----------------------------------------------------------"
echo ""


# Función para escribir tanto en pantalla como en el archivo de informe
append_output() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

# Verificar que Docker esté instalado
if ! command -v docker &>/dev/null; then
    echo "Docker no está instalado en este sistema. Abortando."
    exit 1
fi

# Solicitar al usuario la ruta y nombre del archivo de salida
echo "Ingrese la ruta completa y nombre del archivo donde desea guardar el informe (ejemplo: /home/usuario/informe_docker.txt):"
read OUTPUT_FILE

# Inicializar el archivo de informe con banner y fecha
{
echo "============================================="
echo "             DockerAuditor                 "
echo "       Auditoría Forense de Docker         "
echo "============================================="
echo "Fecha: $(date)"
echo "============================================="
} > "$OUTPUT_FILE"

# --- Sección 1: Información General ---
append_output "\n[1] Información General de Docker:"
append_output "-------------------------------------------------"
docker version >> "$OUTPUT_FILE" 2>&1
docker info >> "$OUTPUT_FILE" 2>&1
append_output "-------------------------------------------------"

# Información de uso del sistema Docker
append_output "\n[2] Uso del sistema Docker (docker system df):"
docker system df >> "$OUTPUT_FILE" 2>&1

# --- Sección 2: Auditoría de Contenedores ---
append_output "\n[3] Listado y Auditoría de Contenedores:"
docker ps -a >> "$OUTPUT_FILE" 2>&1
total_containers=$(docker ps -aq | wc -l)
append_output "\nTotal de contenedores: $total_containers"

for container in $(docker ps -aq); do
    append_output "\n-------------------------------------------------"
    append_output "Contenedor ID: $container"
    
    # Inspección completa del contenedor
    append_output "\n* Inspección del contenedor:"
    docker inspect "$container" >> "$OUTPUT_FILE" 2>&1

    # Extraer el comando de inicio (Path y Args)
    container_cmd=$(docker inspect --format '{{.Path}} {{range .Args}} {{.}} {{end}}' "$container" 2>/dev/null)
    append_output "\n* Comando de inicio: $container_cmd"

    # Intento de extraer el historial de comandos interno (si existe)
    append_output "\n* Historial de comandos interno (si existe):"
    if docker exec "$container" test -f /root/.bash_history 2>/dev/null; then
        history=$(docker exec "$container" cat /root/.bash_history 2>/dev/null)
        append_output "Historial (/root/.bash_history):\n$history"
    elif docker exec "$container" test -f /home/$(whoami)/.bash_history 2>/dev/null; then
        history=$(docker exec "$container" cat /home/$(whoami)/.bash_history 2>/dev/null)
        append_output "Historial (/home/$(whoami)/.bash_history):\n$history"
    else
        append_output "No se encontró historial de comandos dentro del contenedor."
    fi

    # Mostrar logs del contenedor (últimas 200 líneas)
    append_output "\n* Logs del contenedor (últimas 200 líneas):"
    docker logs --tail 200 "$container" >> "$OUTPUT_FILE" 2>&1
done

# --- Sección 3: Auditoría de Imágenes ---
append_output "\n[4] Listado y Auditoría de Imágenes:"
docker images >> "$OUTPUT_FILE" 2>&1
total_images=$(docker images -q | sort -u | wc -l)
append_output "\nTotal de imágenes: $total_images"

for image in $(docker images -q | sort -u); do
    append_output "\n-------------------------------------------------"
    append_output "Imagen ID: $image"
    
    # Inspección completa de la imagen
    append_output "\n* Inspección de la imagen:"
    docker inspect "$image" >> "$OUTPUT_FILE" 2>&1
    
    # Historial de la imagen (comandos del Dockerfile)
    append_output "\n* Historial de la imagen (docker history):"
    docker history "$image" >> "$OUTPUT_FILE" 2>&1
done

# --- Sección 4: Auditoría de Redes ---
append_output "\n[5] Listado y Auditoría de Redes Docker:"
docker network ls >> "$OUTPUT_FILE" 2>&1
total_networks=$(docker network ls -q | wc -l)
append_output "\nTotal de redes: $total_networks"

for network in $(docker network ls -q); do
    append_output "\n-------------------------------------------------"
    append_output "Red ID: $network"
    append_output "\n* Inspección de la red:"
    docker network inspect "$network" >> "$OUTPUT_FILE" 2>&1
done

# --- Sección 5: Auditoría de Volúmenes ---
append_output "\n[6] Listado y Auditoría de Volúmenes Docker:"
docker volume ls >> "$OUTPUT_FILE" 2>&1
total_volumes=$(docker volume ls -q | wc -l)
append_output "\nTotal de volúmenes: $total_volumes"

for volume in $(docker volume ls -q); do
    append_output "\n-------------------------------------------------"
    append_output "Volumen: $volume"
    append_output "\n* Inspección del volumen:"
    docker volume inspect "$volume" >> "$OUTPUT_FILE" 2>&1
done

# --- Sección 6: Auditoría de Plugins ---
append_output "\n[7] Listado y Auditoría de Plugins Docker:"
docker plugin ls >> "$OUTPUT_FILE" 2>&1
total_plugins=$(docker plugin ls -q | wc -l)
append_output "\nTotal de plugins: $total_plugins"

for plugin in $(docker plugin ls -q); do
    append_output "\n-------------------------------------------------"
    append_output "Plugin ID: $plugin"
    append_output "\n* Inspección del plugin:"
    docker plugin inspect "$plugin" >> "$OUTPUT_FILE" 2>&1
done

# --- Sección 7: Resumen General ---
append_output "\n\n============================================="
append_output "           Resumen del Entorno Docker        "
append_output "============================================="
printf "%-20s %-40s\n" "Componente" "Detalles" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "--------------------" "----------------------------------------" | tee -a "$OUTPUT_FILE"

docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
printf "%-20s %-40s\n" "Docker Version:" "$docker_version" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "Contenedores:" "Total: $total_containers" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "Imágenes:" "Total: $total_images" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "Redes:" "Total: $total_networks" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "Volúmenes:" "Total: $total_volumes" | tee -a "$OUTPUT_FILE"
printf "%-20s %-40s\n" "Plugins:" "Total: $total_plugins" | tee -a "$OUTPUT_FILE"

append_output "\nLa auditoría se completó. El informe se ha guardado en: $OUTPUT_FILE"
