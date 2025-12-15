#!/bin/bash
# Script de lanzamiento mejorado para DScanner
# NOTA: Este script requiere que se ejecute con 'sudo' para el escaneo SYN.

# Configuración
PYTHON_VENV="./venv/bin/python3"
SCRIPT="./script.py"
REQUIREMENTS_FILE="./requirements.txt"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Función para mostrar mensajes de error
error_msg() {
    echo -e "${RED}[X]${NC} $1" >&2
}

# Función para mostrar mensajes de éxito
success_msg() {
    echo -e "${GREEN}[+]${NC} $1"
}

# Función para mostrar mensajes de info
info_msg() {
    echo -e "${CYAN}[*]${NC} $1"
}

# Función para verificar si el entorno virtual existe
check_venv() {
    if [ ! -f "$PYTHON_VENV" ]; then
        error_msg "Entorno virtual no encontrado en ./venv/"
        error_msg "Por favor créalo con: python3 -m venv venv"
        return 1
    else
        success_msg "Entorno virtual encontrado ✓"
        return 0
    fi
}

# Función para verificar dependencias
check_dependencies() {
    info_msg "Verificando dependencias de Python..."
    
    # Verificar si pip está disponible en el venv
    PIP_VENV="./venv/bin/pip"
    if [ ! -f "$PIP_VENV" ]; then
        error_msg "pip no encontrado en el entorno virtual"
        return 1
    fi
    
    # Usar pip check para verificar dependencias
    CHECK_RESULT=$(cd "$(dirname "$PYTHON_VENV")" && "$PIP_VENV" check 2>&1)
    
    if [ $? -eq 0 ]; then
        success_msg "Todas las dependencias están instaladas correctamente ✓"
        return 0
    else
        error_msg "Faltan dependencias o hay conflictos:"
        echo -e "${YELLOW}${CHECK_RESULT}${NC}"
        echo -e "\n${YELLOW}Para instalar/actualizar dependencias:${NC}"
        echo -e "source venv/bin/activate && pip install -r ${REQUIREMENTS_FILE}"
        return 1
    fi
}

# Función para verificar si nmap está instalado en el sistema
check_nmap() {
    if ! command -v nmap &> /dev/null; then
        error_msg "Nmap no está instalado en el sistema"
        echo -e "${YELLOW}Instálalo con:${NC}"
        echo -e "  Debian/Ubuntu: sudo apt-get install nmap"
        echo -e "  RHEL/CentOS/Fedora: sudo dnf install nmap"
        echo -e "  Arch: sudo pacman -S nmap"
        return 1
    else
        success_msg "Nmap está instalado en el sistema ✓"
        return 0
    fi
}

# Función principal de verificación
check_all() {
    echo -e "${CYAN}=== VERIFICACIÓN DE DEPENDENCIAS ===${NC}"
    local EXIT_CODE=0
    
    check_venv || EXIT_CODE=1
    echo ""
    check_dependencies || EXIT_CODE=1
    echo ""
    check_nmap || EXIT_CODE=1
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "\n${GREEN}✓ Todo está configurado correctamente. Puedes ejecutar el escáner.${NC}"
    else
        echo -e "\n${RED}✗ Hay problemas que debes solucionar antes de ejecutar el escáner.${NC}"
    fi
    
    exit $EXIT_CODE
}

# Manejo de argumentos
if [ "$1" == "--check-dependencies" ]; then
    check_all
fi

# Verificaciones previas al escaneo (recomendado pero no obligatorio)
if [ ! -f "$PYTHON_VENV" ]; then
    error_msg "Entorno virtual no encontrado. Usa --check-dependencies para más detalles."
    error_msg "O créalo manualmente: python3 -m venv venv && pip install -r ${REQUIREMENTS_FILE}"
    exit 1
fi

if [ ! -f "$SCRIPT" ]; then
    error_msg "Script principal no encontrado: $SCRIPT"
    exit 1
fi

# Ejecuta el script de python con sudo y le pasa TODOS los argumentos ($@)
info_msg "Iniciando DScanner sobre el objetivo..."
sudo "$PYTHON_VENV" "$SCRIPT" "$@"