"""
probe — el único componente que llega a la red interna.

Escucha SOLO en un socket Unix (/run/probe/probe.sock); no abre puertos TCP,
así que los contenedores con los que comparte red no pueden hablarle.

Regla de alcance: solo se conecta a IPs dentro de las subredes de sus propias
interfaces (las redes Docker a las que se unió en docker-compose.yml). Nunca a
Internet, nunca a loopback y, salvo PERMITIR_GATEWAY=true, nunca al gateway de
cada red (que es el propio host).
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from comun import HOST_RE, ErrorPrueba, Protocolo
from probe.pruebas import PRUEBAS, mapear
from probe.red import PERMITIR_GATEWAY, interfaces, verificar_alcance

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# ── API (solo por socket Unix) ──────────────────────────────────────────────

@app.get("/estado")
def estado():
    return {
        "hostname": socket.gethostname(),
        "interfaces": interfaces(),
        "permitir_gateway": PERMITIR_GATEWAY,
    }


class Prueba(BaseModel):
    host: str = Field(pattern=HOST_RE, max_length=253)
    puerto: int = Field(ge=1, le=65535)
    protocolo: Protocolo = "tcp"
    timeout: float = Field(3.0, ge=0.5, le=10.0)


def _cabecera_http(sock, host: str) -> dict:
    sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: security-probe\r\n"
                 "Connection: close\r\n\r\n".encode())
    datos = b""
    while len(datos) < 8192 and b"\r\n\r\n" not in datos:
        trozo = sock.recv(2048)
        if not trozo:
            break
        datos += trozo
    lineas = datos.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    cabeceras = {}
    for l in lineas[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            cabeceras[k.strip().lower()] = v.strip()[:200]
    return {
        "linea_estado": lineas[0][:120] if lineas and lineas[0] else None,
        "server": cabeceras.get("server"),
        "location": cabeceras.get("location"),
    }


@app.post("/probar")
def probar(p: Prueba):
    ifaces = interfaces()
    t0 = time.monotonic()
    try:
        resueltas = sorted({a[4][0] for a in socket.getaddrinfo(
            p.host, p.puerto, socket.AF_INET, socket.SOCK_STREAM)})
    except socket.gaierror as e:
        return {"ok": False, "etapa": "dns", "detalle": f"No resuelve: {e.strerror}"}
    ms_dns = round((time.monotonic() - t0) * 1000, 1)

    # Todas las IPs resueltas deben estar dentro del alcance.
    for ip in resueltas:
        motivo = verificar_alcance(ip, ifaces)
        if motivo:
            raise HTTPException(403, f"Destino fuera de alcance: {motivo}")

    ip = resueltas[0]
    red = next((i["subred"] for i in ifaces
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(i["subred"])), None)
    resultado = {"ips": resueltas, "ip_usada": ip, "subred": red, "ms_dns": ms_dns}

    t1 = time.monotonic()
    try:
        sock = socket.create_connection((ip, p.puerto), timeout=p.timeout)
    except (TimeoutError, socket.timeout):
        return {**resultado, "ok": False, "etapa": "tcp", "detalle": "Tiempo agotado (filtrado o caído)"}
    except ConnectionRefusedError:
        return {**resultado, "ok": False, "etapa": "tcp", "detalle": "Conexión rechazada (puerto cerrado)"}
    except OSError as e:
        return {**resultado, "ok": False, "etapa": "tcp", "detalle": e.strerror or str(e)}
    resultado["ms_tcp"] = round((time.monotonic() - t1) * 1000, 1)

    try:
        if p.protocolo in ("http", "https", "minio"):
            tls = p.protocolo == "https"
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # interno: solo se informa
                sock = ctx.wrap_socket(sock, server_hostname=p.host)
                resultado["tls"] = {"version": sock.version(), "cifrado": sock.cipher()[0]}
            resultado["http"] = _cabecera_http(sock, p.host)
    except (OSError, ssl.SSLError) as e:
        return {**resultado, "ok": False, "etapa": p.protocolo,
                "detalle": f"TCP abierto, pero falló {p.protocolo}: {e}"}
    finally:
        sock.close()

    return {**resultado, "ok": True, "etapa": "completa", "detalle": "Conexión establecida"}


# ── Ejecución de pruebas ────────────────────────────────────────────────────

class Ejecucion(BaseModel):
    contexto: dict = Field(default_factory=dict)


@app.get("/pruebas")
def pruebas_disponibles():
    return sorted(PRUEBAS)


@app.post("/ejecutar/{tipo}")
async def ejecutar(tipo: str, e: Ejecucion):
    fn = PRUEBAS.get(tipo)
    if not fn:
        raise HTTPException(404, f"La prueba {tipo} no se ejecuta en el probe")
    try:
        return await fn(e.contexto)
    except ErrorPrueba as ex:
        raise HTTPException(400, str(ex))


@app.post("/mapear")
async def mapear_servicios(e: Ejecucion):
    try:
        return await mapear(e.contexto)
    except ErrorPrueba as ex:
        raise HTTPException(400, str(ex))
