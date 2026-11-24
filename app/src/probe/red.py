"""Interfaces del probe y regla de alcance."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import socket
import struct

PERMITIR_GATEWAY = os.environ.get("PERMITIR_GATEWAY", "false").lower() == "true"


def _ip_de(iface: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        datos = fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                            struct.pack("256s", iface[:15].encode()))
        return socket.inet_ntoa(datos[20:24])
    except OSError:
        return None
    finally:
        s.close()


def _hex_a_ip(h: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(h, 16)))


def interfaces() -> list[dict]:
    """Subredes conectadas (de /proc/net/route) y gateway de cada interfaz."""
    rutas: dict[str, dict] = {}
    with open("/proc/net/route") as f:
        next(f)
        for linea in f:
            c = linea.split()
            iface, destino, mascara = c[0], c[1], c[7]
            if iface == "lo" or destino == "00000000":
                continue
            red = ipaddress.IPv4Network(f"{_hex_a_ip(destino)}/{_hex_a_ip(mascara)}")
            rutas.setdefault(iface, {})["subred"] = red
    salida = []
    for iface, r in sorted(rutas.items()):
        red: ipaddress.IPv4Network = r["subred"]
        salida.append({
            "iface": iface,
            "ip": _ip_de(iface),
            "subred": str(red),
            # Docker asigna .1 como gateway de cada red bridge.
            "gateway": str(red.network_address + 1),
        })
    return salida


def verificar_alcance(ip: str, ifaces: list[dict], permitir_gateway: bool | None = None) -> str | None:
    """None si la IP está permitida; si no, el motivo."""
    if permitir_gateway is None:
        permitir_gateway = PERMITIR_GATEWAY
    try:
        dir_ip = ipaddress.IPv4Address(ip)
    except ValueError:
        return f"{ip} no es IPv4"
    if dir_ip.is_loopback:
        return "loopback no permitido"
    for i in ifaces:
        if dir_ip in ipaddress.IPv4Network(i["subred"]):
            if not permitir_gateway and ip == i["gateway"]:
                return f"{ip} es el gateway de {i['subred']} (el host); habilitar PERMITIR_GATEWAY"
            if ip == i["ip"]:
                return "es el propio probe"
            return None
    return f"{ip} está fuera de las redes internas conectadas"


def leer_arp() -> dict[str, str]:
    """IPs con entrada ARP completa (flag 0x2) → MAC."""
    vecinos = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for linea in f:
                c = linea.split()
                if len(c) >= 4 and int(c[2], 16) & 0x2 and c[3] != "00:00:00:00:00:00":
                    vecinos[c[0]] = c[3]
    except OSError:
        pass
    return vecinos
