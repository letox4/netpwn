# Checklist de pruebas en Kali Linux

Los tests automatizados (CI) y el modo `--demo` cubren la lógica pura y la
interfaz, pero **los módulos ofensivos requieren Linux + root + hardware de
red real**. Esta es la lista completa para validar todo antes de un release.

Entorno recomendado: Kali Linux (VM o bare metal), una interfaz Wi-Fi que
soporte modo monitor (p. ej. con chip Atheros/Realtek RTL8812AU) y una red de
laboratorio propia (tu router casero + un par de dispositivos).

## 1. Arranque y limpieza

- [ ] `./run.sh` arranca y la UI carga en `127.0.0.1:8000`
- [ ] El chequeo de entorno (panel Hosts) muestra root OK y sin restos
- [ ] Botón de PÁNICO: con módulos activos, detiene todo, borra reglas
      `iptables` etiquetadas y restaura `ip_forward`
- [ ] Matar el proceso con `kill -9`: al rearrancar, avisa de reglas huérfanas
      y el PÁNICO las limpia

## 2. Reconocimiento

- [ ] Hosts: el barrido ARP encuentra todos los dispositivos de la red
- [ ] Fingerprint de OS razonable (TTL, vendor) al clicar un host
- [ ] Puertos: connect scan y SYN stealth dan los mismos abiertos
- [ ] Low noise: visiblemente más lento, con jitter
- [ ] Topología: el grafo se dibuja y los nodos tienen evidencia

## 3. MITM y capturas (red de laboratorio)

- [ ] MITM (ARP): la víctima sigue navegando (ip_forward activo) y el sniffer
      ve su tráfico
- [ ] Sniffer con filtro BPF (p. ej. `tcp port 80`)
- [ ] DNS Spoof con mapping: la víctima resuelve la IP indicada
- [ ] Credenciales: HTTP Basic y formulario contra un servidor HTTP propio
      (arranca uno con `python3 -m http.server 80` y un formulario de prueba);
      export JSON y limpiar buffer
- [ ] HTTP Inject: el payload JS aparece en páginas HTTP de la víctima;
      la regla iptables desaparece al detener
- [ ] Poisoners + WPAD: una VM Windows en el mismo segmento pregunta por
      `wpad` y el proxy registra URLs
- [ ] mitm6: solo si hay IPv6 en el segmento; verificar RA y resolución

## 4. Wi-Fi (red propia)

- [ ] Modo monitor entra y sale sin dejar NetworkManager muerto
- [ ] Escaneo encuentra tus APs con canal/señal correctos
- [ ] Deauth dirigido a un cliente de TU AP: el cliente se reconecta
- [ ] Handshake: captura EAPOL completa, marca ✓ y convierte a .22000 con
      `hcxpcapngtool` (requiere `hcxtools`)
- [ ] PMKID: si el AP lo soporta, captura sin cliente
- [ ] `hashcat -m 22000` contra el hash con la contraseña conocida de TU red

## 5. OPSEC

- [ ] Generar y aplicar un perfil cambia hostname y MAC (verificar con
      `hostname` e `ip link`)
- [ ] Restaurar original devuelve los valores de fábrica
- [ ] Renew DHCP re-obtiene IP tras el cambio de MAC

## 6. Cámaras (opcional, con hardware propio)

- [ ] Discovery encuentra una cámara IP real o una API simulada
- [ ] Auditoría ONVIF/RTSP contra una cámara propia con credenciales conocidas

## Regresión rápida (cualquier SO)

- [ ] `pytest` en verde
- [ ] `python3 netpwn.py --demo` arranca sin root y la UI responde
