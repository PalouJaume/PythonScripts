#!/usr/bin/env python3
"""
Herramienta simple para enviar y recibir mensajes UDP entre ordenadores.

Ejemplos:
    # Escuchar en el puerto 5005 (todas las interfaces)
    python3 udp_tool.py recv 5005

    # Escuchar y responder automaticamente (eco)
    python3 udp_tool.py recv 5005 --echo

    # Enviar texto (con comprobaciones previas)
    python3 udp_tool.py send 192.168.1.50 5005 -m "hola"

    # Enviar bytes en hexadecimal y esperar respuesta
    python3 udp_tool.py send 192.168.1.50 5005 -x "DE AD BE EF" --wait
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from datetime import datetime


def stamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def log(tag, msg):
    print(f"[{stamp()}] {tag:4} {msg}")


def dump(addr, data, show_hex):
    body = data.hex(" ") if show_hex else repr(data.decode("utf-8", "replace"))
    log("<--", f"{addr[0]}:{addr[1]} ({len(data)} B) {body}")


def local_ips():
    """IPs propias de este equipo, para detectar envios a uno mismo."""
    found = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except socket.gaierror:
        pass
    return found


def ping(ip, timeout_s=2):
    """Devuelve True/False/None (None = no se pudo determinar)."""
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_s * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_s)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_s + 2)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return None


def preflight(host, port, do_ping=True):
    """Comprueba resolucion, ruta y que el trafico saldra del equipo.

    Devuelve (ip_destino, ip_origen) o termina el programa si no hay ruta.
    """
    # 1. Resolucion de nombre
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        log("ERR", f"no se puede resolver '{host}': {e}")
        sys.exit(1)
    if ip != host:
        log("chk", f"'{host}' resuelve a {ip}")

    # 2. Ruta hacia el destino: connect() en UDP no envia nada, solo fija la ruta
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((ip, port))
        src_ip = probe.getsockname()[0]
    except OSError as e:
        log("ERR", f"no hay ruta hacia {ip}: {e}")
        sys.exit(1)
    finally:
        probe.close()
    log("chk", f"ruta OK: saldra por la interfaz {src_ip}")

    # 3. El paquete sale realmente del equipo?
    if ip.startswith("127.") or src_ip.startswith("127."):
        log("WARN", "destino de loopback: el paquete NO sale del equipo "
                    "(en Wireshark captura en 'lo' / 'lo0')")
    elif ip in local_ips() or ip == src_ip:
        log("WARN", f"{ip} es una IP de este mismo equipo: el paquete no "
                    "cruza la red fisica")
    else:
        log("chk", f"destino externo: el paquete saldra por la red hacia {ip}")

    # 4. Alcanzabilidad (informativa: muchos equipos filtran ICMP)
    if do_ping:
        res = ping(ip)
        if res is True:
            log("chk", f"{ip} responde a ping")
        elif res is False:
            log("WARN", f"{ip} no responde a ping (puede estar filtrado "
                        "por firewall; el envio UDP continua)")
        else:
            log("WARN", "no se pudo ejecutar ping, se omite la comprobacion")

    return ip, src_ip


def receive(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.bind, args.port))
    except OSError as e:
        log("ERR", f"no se puede escuchar en {args.bind}:{args.port}: {e}")
        sys.exit(1)
    log("chk", f"escuchando en {args.bind}:{args.port} (Ctrl+C para salir)")

    try:
        while True:
            data, addr = sock.recvfrom(args.bufsize)
            dump(addr, data, args.hexdump)
            if args.echo:
                sock.sendto(data, addr)
    except KeyboardInterrupt:
        print("\nFin.")
    finally:
        sock.close()


def send(args):
    if args.hexpayload:
        try:
            payload = bytes.fromhex(args.hexpayload.replace(" ", "").replace("0x", ""))
        except ValueError as e:
            log("ERR", f"payload hex invalido: {e}")
            sys.exit(1)
    else:
        payload = args.message.encode("utf-8")

    ip = args.host
    if not args.no_check:
        ip, _ = preflight(args.host, args.port, do_ping=not args.no_ping)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.bind_port:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.bind_port))
    if args.broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    else:
        # Socket conectado: permite recibir errores ICMP del destino
        sock.connect((ip, args.port))
    sock.settimeout(args.timeout)

    for k in range(args.count):
        try:
            if args.broadcast:
                sent = sock.sendto(payload, (ip, args.port))
            else:
                sent = sock.send(payload)
        except OSError as e:
            # p.ej. host inalcanzable tras fallar el ARP, o ICMP previo
            log("ERR", f"fallo al enviar: {e}")
            sock.close()
            sys.exit(1)

        if sent != len(payload):
            log("WARN", f"enviados {sent} de {len(payload)} B")
        else:
            log("-->", f"{ip}:{args.port} ({sent} B) #{k + 1}")

        if args.wait or not args.broadcast:
            sock.settimeout(args.timeout if args.wait else 0.05)
            try:
                data, addr = sock.recvfrom(args.bufsize)
                dump(addr, data, args.hexdump)
            except ConnectionRefusedError:
                # ICMP port unreachable: el paquete salio y llego al host
                log("chk", f"{ip} contesto ICMP port unreachable: el paquete "
                           f"llego al host, pero nadie escucha en el puerto {args.port}")
            except OSError as e:
                if args.wait and isinstance(e, socket.timeout):
                    log("WARN", f"sin respuesta en {args.timeout}s")
                elif not isinstance(e, socket.timeout):
                    log("WARN", f"error de red tras el envio: {e}")

        if k + 1 < args.count:
            time.sleep(args.interval)

    sock.close()


def main():
    p = argparse.ArgumentParser(description="Enviar/recibir mensajes UDP")
    p.add_argument("--bufsize", type=int, default=65535, help="tamano max de datagrama")
    p.add_argument("--hexdump", action="store_true", help="mostrar recibidos en hex")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recv", help="escuchar en un puerto")
    r.add_argument("port", type=int)
    r.add_argument("--bind", default="0.0.0.0", help="interfaz local")
    r.add_argument("--echo", action="store_true", help="devolver lo recibido")
    r.set_defaults(func=receive)

    s = sub.add_parser("send", help="enviar a un host:puerto")
    s.add_argument("host")
    s.add_argument("port", type=int)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("-m", "--message", help="payload como texto")
    g.add_argument("-x", "--hexpayload", help="payload en hex, ej: 'DE AD BE EF'")
    s.add_argument("-n", "--count", type=int, default=1, help="numero de envios")
    s.add_argument("-i", "--interval", type=float, default=1.0, help="segundos entre envios")
    s.add_argument("--wait", action="store_true", help="esperar respuesta tras cada envio")
    s.add_argument("--timeout", type=float, default=2.0, help="timeout de la respuesta")
    s.add_argument("--bind-port", type=int, help="puerto local fijo de origen")
    s.add_argument("--broadcast", action="store_true", help="permitir broadcast")
    s.add_argument("--no-ping", action="store_true", help="omitir el ping previo")
    s.add_argument("--no-check", action="store_true", help="omitir todas las comprobaciones")
    s.set_defaults(func=send)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())