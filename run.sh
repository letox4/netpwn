#!/usr/bin/env bash
# Arranca NetPwn (modo real). Requiere root para los sockets raw;
# netpwn.py se eleva con sudo el solo. Para probar sin red: python3 netpwn.py --demo
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "[*] Creando entorno virtual..."
  python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate
echo "[*] Instalando dependencias..."
pip install -q -r requirements.txt

exec python netpwn.py "$@"
