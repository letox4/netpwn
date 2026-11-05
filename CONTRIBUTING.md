# Contribuir a NetPwn

¡Gracias por tu interés! Antes de enviar un PR:

1. **Estilo**: sigue el estilo del código existente (comentarios en español,
   módulos cortos y enfocados, docstrings explicando el "porqué").
2. **Tests**: toda lógica nueva que se pueda probar sin red debe venir con
   tests en `tests/` (mira `test_netutils.py` como referencia).
3. **Limpieza**: si añades un endpoint o módulo que toca el sistema
   (iptables, /proc, sockets raw), debe integrarse con el botón de PÁNICO
   (`core/cleanup.py`) y comportarse bien en modo demo (`core/demo.py` +
   `_DEMO_ALLOWED` en `main.py`).
4. **Seguridad de la herramienta**: no introduzcas dependencias nuevas sin
   justificación; el frontend es vanilla JS a propósito.
5. Verifica: `pytest` en verde y `python3 netpwn.py --demo` funcional.

## Desarrollo

```bash
git clone https://github.com/letox4/netpwn
cd netpwn
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt pytest
pytest
python netpwn.py --demo   # UI completa sin root ni red real
```
