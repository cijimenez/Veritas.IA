#!/bin/bash

# Colores para mensajes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Directorio de la aplicación
cd "$HOME/veritas-ia" || { echo -e "${RED}[ERROR] No se pudo acceder al directorio de la aplicación${NC}"; exit 1; }

# Verificar si el puerto 5000 está disponible
if command -v lsof &> /dev/null; then
  if lsof -i:5000 &> /dev/null; then
    echo -e "${RED}[ERROR] El puerto 5000 ya está en uso. Cierra la aplicación que lo está usando e intenta de nuevo.${NC}"
    exit 1
  fi
elif command -v netstat &> /dev/null; then
  if netstat -tuln | grep ":5000 " &> /dev/null; then
    echo -e "${RED}[ERROR] El puerto 5000 ya está en uso. Cierra la aplicación que lo está usando e intenta de nuevo.${NC}"
    exit 1
  fi
fi

# Iniciar la aplicación
echo -e "${GREEN}[+] Iniciando Veritas.ia...${NC}"
python3 app.py

# Capturar señal de interrupción
trap 'echo -e "${GREEN}[+] Deteniendo Veritas.ia...${NC}"; exit 0' INT
