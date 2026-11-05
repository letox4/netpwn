#!/usr/bin/env python3
"""NetPwn - Suite grafica de auditoria de redes (pentesting) con interfaz web.

Uso:
    python3 netpwn.py            # modo real (requiere Linux + root)
    python3 netpwn.py --demo     # red ficticia, sin root, cualquier SO
    python3 netpwn.py --host 0.0.0.0 --port 8080

En modo real se necesita sudo para los sockets raw; el script re-eleva solo
(si no ya root) conservando el PATH del venv.
"""
import argparse
import os
import sys
from pathlib import Path

__version__ = "1.0.0"

APP_DIR = Path(__file__).resolve().parent / "app"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netpwn",
        description="Suite grafica de auditoria de redes con interfaz web.",
    )
    parser.add_argument("--demo", action="store_true",
                        help="modo demostracion: red ficticia, sin root ni red real")
    parser.add_argument("--host", default="127.0.0.1",
                        help="direccion de escucha (por defecto 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000,
                        help="puerto de escucha (por defecto 8000)")
    parser.add_argument("--version", action="version",
                        version=f"netpwn {__version__}")
    args = parser.parse_args()

    if args.demo:
        os.environ["NETPWN_DEMO"] = "1"
        print("[*] Modo DEMO: red ficticia, modulos ofensivos desactivados.")
    else:
        os.environ.pop("NETPWN_DEMO", None)
        # Modo real: los sockets raw necesitan root. Elevamos conservando
        # el entorno (venv incluido) si aun no lo somos.
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            import subprocess
            print("[*] Se necesita root para los sockets raw; elevando con sudo...")
            sys.exit(subprocess.run(
                ["sudo", "-E", sys.executable, *sys.argv],
            ).returncode)

    sys.path.insert(0, str(APP_DIR))
    os.chdir(APP_DIR)

    import uvicorn

    print(f"[*] Abre http://{args.host}:{args.port} en tu navegador")
    uvicorn.run("main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
