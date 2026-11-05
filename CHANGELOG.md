# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [1.0.0] - 2026-11-05

### Añadido

- Primera release pública.
- Suite completa: descubrimiento ARP, escaneo de puertos (connect/SYN/low
  noise), fingerprint de OS, topología de red, MITM ARP, sniffer, DNS spoof,
  captura de credenciales, HTTP inject + sslstrip-lite, poisoners
  LLMNR/NBT-NS/mDNS, WPAD, mitm6, Wi-Fi (escaneo, deauth, handshakes EAPOL,
  PMKID → hashcat), auditoría de cámaras IP y panel OPSEC.
- **Modo demo** (`netpwn.py --demo`): red ficticia completa para explorar la
  UI sin root, en cualquier sistema operativo.
- **CLI** `netpwn.py` con `--demo`, `--host`, `--port` y `--version`.
- Botón de **PÁNICO** y limpieza automática (atexit + señales) de reglas
  iptables etiquetadas, ip_forward e identidad OPSEC.
- Tests unitarios (`pytest`) y CI de GitHub Actions (tests + smoke del demo).
- Interfaz web bilingüe (inglés/español) sin dependencias frontend.
