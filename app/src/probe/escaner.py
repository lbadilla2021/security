"""Primitivas de red asíncronas: conexión TCP, barrido de puertos y banners."""

from __future__ import annotations

import asyncio
import errno
import re
import socket

from comun import servicio

# Estados de un puerto
ABIERTO, CERRADO, FILTRADO, INALCANZABLE, ERROR = "abierto", "cerrado", "filtrado", "inalcanzable", "error"

_PUERTOS_HTTP = {80, 81, 3000, 3001, 5000, 5050, 5601, 5678, 7000, 8000, 8001, 8008, 8025, 8080,
                 8081, 8088, 8200, 8500, 8888, 9000, 9001, 9090, 9093, 9100, 9200, 9411, 15672, 16686}
_PUERTOS_TLS = {443, 8443, 9443, 6443, 10250, 2376}
_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")


async def conectar(ip: str, puerto: int, timeout: float) -> str:
    """Estado del puerto con un connect() TCP completo (sin privilegios)."""
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, puerto), timeout)
    except asyncio.TimeoutError:
        return FILTRADO
    except ConnectionRefusedError:
        return CERRADO
    except OSError as e:
        if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
            return INALCANZABLE
        return ERROR
    w.close()
    try:
        await asyncio.wait_for(w.wait_closed(), 1)
    except (asyncio.TimeoutError, OSError):
        pass
    return ABIERTO


async def escanear(objetivos: list[tuple[str, int]], timeout: float = 1.0,
                   concurrencia: int = 200) -> dict[tuple[str, int], str]:
    sem = asyncio.Semaphore(concurrencia)

    async def uno(ip, puerto):
        async with sem:
            return (ip, puerto), await conectar(ip, puerto, timeout)

    return dict(await asyncio.gather(*(uno(ip, p) for ip, p in objetivos)))


def _limpiar(texto: str, largo: int = 120) -> str:
    texto = "".join(ch if ch.isprintable() else " " for ch in texto)
    return re.sub(r"\s+", " ", texto).strip()[:largo]


async def banner(ip: str, puerto: int, host: str | None = None, timeout: float = 2.0) -> dict:
    """Lo que el servicio dice de sí mismo. Solo lectura: a lo más un HEAD /."""
    info = {"banner": None, "server": None, "http": None, "tls": False}
    try:
        if puerto in _PUERTOS_TLS:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, puerto, ssl=ctx), timeout)
            info["tls"] = True
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, puerto), timeout)
    except (asyncio.TimeoutError, OSError):
        return info
    try:
        # Protocolos que hablan primero (SSH, SMTP, FTP, MySQL…)
        if puerto not in _PUERTOS_HTTP and not info["tls"]:
            try:
                datos = await asyncio.wait_for(r.read(256), 1.2)
                if datos:
                    info["banner"] = _limpiar(datos.decode("latin-1"))
                    return info
            except asyncio.TimeoutError:
                pass
            # Servicio silencioso: solo se prueba HTTP si su clase lo sugiere
            # (no se envían bytes HTTP a bases de datos, cachés, etc.).
            if servicio(puerto)[1] not in ("web", "admin", "metricas", "almacenamiento", "vectorial", "otro"):
                return info
        w.write(f"HEAD / HTTP/1.0\r\nHost: {host or ip}\r\nUser-Agent: security-probe\r\n\r\n".encode())
        await w.drain()
        datos = await asyncio.wait_for(r.read(4096), timeout)
        texto = datos.decode("latin-1")
        if texto.startswith("HTTP/"):
            lineas = texto.split("\r\n")
            info["http"] = _limpiar(lineas[0], 60)
            for l in lineas[1:]:
                if l.lower().startswith("server:"):
                    info["server"] = _limpiar(l.split(":", 1)[1], 80)
        elif texto:
            info["banner"] = _limpiar(texto)
    except (asyncio.TimeoutError, OSError, UnicodeError):
        pass
    finally:
        w.close()
    return info


def revela_version(info: dict) -> str | None:
    """Texto con versión si el banner o la cabecera Server la exponen."""
    for campo in ("server", "banner"):
        v = info.get(campo)
        if v and _VERSION_RE.search(v):
            return v
    return None


async def nombre_inverso(ip: str, timeout: float = 2.0) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        nombre, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout)
        return nombre
    except (asyncio.TimeoutError, OSError):
        return None


async def resolver(nombre: str, timeout: float = 3.0) -> list[str] | None:
    loop = asyncio.get_running_loop()
    try:
        res = await asyncio.wait_for(loop.getaddrinfo(nombre, None, family=socket.AF_INET,
                                                      type=socket.SOCK_STREAM), timeout)
        return sorted({a[4][0] for a in res})
    except (asyncio.TimeoutError, OSError):
        return None
