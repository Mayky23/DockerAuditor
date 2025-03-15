#!/bin/bash
# DockerAuditor - Auditoría Forense de Docker

# --- Banner ---
clear
echo "   ____             _                  _             _ _ _      "
echo "  |  _ \  ___   ___| | _____ _ __     / \  _   _  __| (_) |_ ___  _ __ "
echo "  | | | |/ _ \ / __| |/ / _ \ '__|   / _ \| | | |/ _\ | | __/ _ \| __|"
echo "  | |_| | (_) | (__|   <  __/ |     / ___ \ |_| | (_| | | || (_) | |   "
echo "  |____/ \___/ \___|_|\_\___|_|    /_/   \_\__,_|\__,_|_|\__\___/|_|   "
echo ""
echo "---- By: MARH ----------------------------------------------------------"
echo ""

# Preguntar la ruta donde se guardará el archivo de salida
read -p "Ingrese la ruta completa donde desea guardar el informe (ejemplo: /home/usuario/): " OUTPUT_DIR

# Verificar si la ruta ingresada existe
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: La ruta ingresada no existe. Abortando."
    exit 1
fi

# Generar el nombre del archivo con timestamp
OUTPUT_FILE="${OUTPUT_DIR}/docker_audit_$(date +"%Y%m%d%H%M%S").txt"

# Inicializar el archivo de informe
{
echo "============================================="
echo "             DockerAuditor                 "
echo "       Auditoría Forense de Docker         "
echo "============================================="
echo "Fecha: $(date)"
echo "============================================="
echo ""
} > "$OUTPUT_FILE"

# --- Iniciar auditoría y mostrar proceso en consola ---
echo "Iniciando la auditoría de Docker..."

# Información General
echo "[1] Información General de Docker..."
echo "Obteniendo información general de Docker..."
{
    echo "*****************************"
    echo "1. INFORMACIÓN GENERAL"
    echo "*****************************"
    sudo docker version
    sudo docker info
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Uso del sistema
echo "[2] Uso del sistema Docker..."
echo "Analizando el uso del sistema Docker..."
{
    echo "*****************************"
    echo "2. USO DEL SISTEMA"
    echo "*****************************"
    sudo docker system df
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Auditoría de Contenedores
echo "[3] Analizando contenedores..."
echo "Obteniendo lista de contenedores..."
{
    echo "*****************************"
    echo "3. CONTENEDORES"
    echo "*****************************"
    sudo docker ps -a
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Auditoría de Imágenes
echo "[4] Analizando imágenes..."
echo "Obteniendo lista de imágenes..."
{
    echo "*****************************"
    echo "4. IMÁGENES"
    echo "*****************************"
    sudo docker images
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Auditoría de Redes
echo "[5] Analizando redes..."
echo "Obteniendo lista de redes..."
{
    echo "*****************************"
    echo "5. REDES"
    echo "*****************************"
    sudo docker network ls
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Auditoría de Volúmenes
echo "[6] Analizando volúmenes..."
echo "Obteniendo lista de volúmenes..."
{
    echo "*****************************"
    echo "6. VOLÚMENES"
    echo "*****************************"
    sudo docker volume ls
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# Auditoría de Plugins
echo "[7] Analizando plugins..."
echo "Obteniendo lista de plugins..."
{
    echo "*****************************"
    echo "7. PLUGINS"
    echo "*****************************"
    sudo docker plugin ls
} >> "$OUTPUT_FILE" 2>&1

# Pausa de 2 segundos
sleep 2

# --- Implementación de Checkov ---
echo "[8] Ejecutando Checkov para análisis de seguridad..."
echo "Analizando seguridad con Checkov en configuraciones de Docker..."
# Verificar si existen archivos Dockerfile o docker-compose.yml
if [ ! -f Dockerfile ] && [ ! -f docker-compose.yml ]; then
    {
        echo "*****************************"
        echo "8. CHECKOV"
        echo "*****************************"
        echo "No se encontraron archivos Dockerfile o docker-compose.yml en el directorio actual."
        echo "No se realizó el análisis de seguridad con Checkov."
    } >> "$OUTPUT_FILE"
else
    checkov -d . --output json > checkov_output.json 2>&1
    if [ $? -eq 0 ]; then
        {
            echo "*****************************"
            echo "8. CHECKOV"
            echo "*****************************"
            echo "Análisis de Checkov completado con éxito. Resultados guardados."
        } >> "$OUTPUT_FILE"
    else
        {
            echo "*****************************"
            echo "8. CHECKOV"
            echo "*****************************"
            echo "Error al ejecutar Checkov, pero el análisis continuará."
        } >> "$OUTPUT_FILE"
    fi
    cat checkov_output.json >> "$OUTPUT_FILE"
fi

# Pausa de 2 segundos
sleep 2

# Mostrar solo la tabla resumen en consola
echo ""
echo "================ Resumen de Auditoría ================"
echo "Información General: Docker version: $(sudo docker version --format '{{.Server.Version}}')"
echo "Contenedores: Total: $(sudo docker ps -aq | wc -l), Activos: $(sudo docker ps -q | wc -l), Detenidos: $(( $(sudo docker ps -aq | wc -l) - $(sudo docker ps -q | wc -l) ))"
echo "Imágenes: Total: $(sudo docker images -q | sort -u | wc -l)"
echo "Redes: Total: $(sudo docker network ls -q | wc -l)"
echo "Volúmenes: Total: $(sudo docker volume ls -q | wc -l)"
echo "Plugins: Total: $(sudo docker plugin ls -q | wc -l)"
echo "======================================================"

# Tabla resumen en archivo
{
    echo "***********************************************"
    echo "                  Tabla Resumen               "
    echo "***********************************************"
    printf "%-20s %-40s\n" "Componente" "Detalles"
    printf "%-20s %-40s\n" "--------------------" "----------------------------------------"
    printf "%-20s %-40s\n" "Docker Version:" "$(sudo docker version --format '{{.Server.Version}}')"
    printf "%-20s %-40s\n" "Contenedores:" "Total: $(sudo docker ps -aq | wc -l), Activos: $(sudo docker ps -q | wc -l), Detenidos: $(( $(sudo docker ps -aq | wc -l) - $(sudo docker ps -q | wc -l) ))"
    printf "%-20s %-40s\n" "Imágenes:" "Total: $(sudo docker images -q | sort -u | wc -l)"
    printf "%-20s %-40s\n" "Redes:" "Total: $(sudo docker network ls -q | wc -l)"
    printf "%-20s %-40s\n" "Volúmenes:" "Total: $(sudo docker volume ls -q | wc -l)"
    printf "%-20s %-40s\n" "Plugins:" "Total: $(sudo docker plugin ls -q | wc -l)"
    echo "***********************************************"
    echo "***********************************************"
} >> "$OUTPUT_FILE"

echo ""
echo "La auditoría se completó. El informe se ha guardado en: $OUTPUT_FILE"
