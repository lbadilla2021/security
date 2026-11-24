"""
Pruebas de «Cifrado» (auditoría, solo lectura).

  tls           → versiones de protocolo y cifrados de servicios HTTPS
  certificados  → validez, cadena y robustez del certificado
  trafico_claro → servicios que transportan datos sin cifrar en la red interna

No envían credenciales ni modifican nada: a lo más un handshake TLS, la
solicitud de SSL de Postgres (lo mismo que hace libpq) y un PING a Redis.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import struct
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from comun import NOMBRE_CLASE, ErrorPrueba, Resultado, servicio
from probe.escaner import resolver
from probe.red import interfaces, verificar_alcance

TIMEOUT = 5.0

_VERSIONES = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1, "obsoleto"),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, "obsoleto"),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2, "ok"),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3, "ok"),
]
# Familias de cifrado débiles que se intentan ofrecer (SECLEVEL 0) para ver si
# el servidor las acepta. Si el propio cliente no puede ofrecerlas, se omite.
_DEBILES = {"RC4": "RC4", "3DES/DES": "3DES:DES", "NULL (sin cifrado)": "NULL:eNULL",
            "Anónimo (sin autenticación)": "aNULL", "EXPORT": "EXPORT"}


# ── Alcance ─────────────────────────────────────────────────────────────────

async def _validas(ctx: dict, res: Resultado, protocolos: set[str]) -> list[dict]:
    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in protocolos]
    if not conexiones:
        raise ErrorPrueba("Asigna al menos una conexión compatible a esta prueba.")
    ifaces = interfaces()
    validas = []
    for cx in conexiones:
        ips = await resolver(cx["host"])
        if not ips:
            res.hallazgo("info", f"{cx['nombre']}: el host no resuelve", f"{cx['host']} no tiene DNS.", objetivo=cx["host"])
            continue
        motivo = next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None)
        if motivo:
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance", motivo, objetivo=cx["host"])
            continue
        validas.append(cx)
    return validas


# ── Handshakes TLS (síncrono, se corre en hilo) ─────────────────────────────

def _ctx(minv=None, maxv=None, seclevel0=True) -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if minv:
        c.minimum_version = minv
    if maxv:
        c.maximum_version = maxv
    if seclevel0:
        try:
            c.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return c


def _conectar_tls(host, port, ctx):
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=TIMEOUT), server_hostname=host)
    try:
        return s.cipher(), s.getpeercert(binary_form=True)
    finally:
        s.close()


def _sondear_tls(host: str, port: int) -> dict:
    versiones, der = {}, None
    cualquiera = False
    for nombre, ver, estado in _VERSIONES:
        try:
            ctx = _ctx(minv=ver, maxv=ver)
            cipher, cert = _conectar_tls(host, port, ctx)
            versiones[nombre] = {"estado": estado, "cipher": cipher[0], "bits": cipher[2]}
            der = der or cert
            cualquiera = True
        except (ssl.SSLError, OSError):
            continue
    debiles = []
    if cualquiera:
        for etiqueta, spec in _DEBILES.items():
            ctx = _ctx(maxv=ssl.TLSVersion.TLSv1_2)
            try:
                ctx.set_ciphers(f"{spec}:@SECLEVEL=0")
            except ssl.SSLError:
                continue  # el cliente no puede ni ofrecerla
            try:
                cipher, _ = _conectar_tls(host, port, ctx)
                debiles.append((etiqueta, cipher[0]))
            except (ssl.SSLError, OSError):
                pass
    return {"versiones": versiones, "debiles": debiles, "der": der, "respondio": cualquiera}


def _solo_cert(host: str, port: int):
    for ver in (None, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1):
        try:
            _, der = _conectar_tls(host, port, _ctx(maxv=ver))
            if der:
                return der
        except (ssl.SSLError, OSError):
            continue
    return None


# ── 1. TLS: protocolos y cifrados ───────────────────────────────────────────

async def tls(ctx: dict) -> dict:
    res = Resultado("tls")
    conexiones = await _validas(ctx, res, {"https"})
    filas = []
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        datos = await asyncio.to_thread(_sondear_tls, cx["host"], cx["puerto"])
        if not datos["respondio"]:
            res.hallazgo("info", f"{cx['nombre']}: no se pudo negociar TLS",
                         "El servidor no completó el handshake por nombre de contenedor. Suele pasar con proxies "
                         "que exigen SNI del dominio público (p. ej. NPM); probar con el dominio real.", objetivo=o)
            filas.append([cx["nombre"], o, "—", "—", "—"])
            continue
        vers = datos["versiones"]
        obsoletas = [v for v in vers if vers[v]["estado"] == "obsoleto"]
        modernas = [v for v in vers if vers[v]["estado"] == "ok"]
        ciphers = sorted({f"{v}: {vers[v]['cipher']}" for v in vers})
        filas.append([cx["nombre"], o, ", ".join(vers) or "—",
                      ", ".join(sorted({vers[v]["cipher"] for v in vers})),
                      str(min((vers[v]["bits"] for v in vers), default="—"))])
        if obsoletas:
            res.hallazgo("media", f"{cx['nombre']}: versiones TLS obsoletas",
                         f"Acepta {', '.join(obsoletas)}. TLS 1.0/1.1 están en desuso y prohibidos por PCI-DSS.",
                         objetivo=o, recomendacion="Exigir TLS 1.2 como mínimo (idealmente 1.2 y 1.3).")
        for etiqueta, cipher in datos["debiles"]:
            sev = "alta" if ("NULL" in etiqueta or "Anónimo" in etiqueta) else "media"
            res.hallazgo(sev, f"{cx['nombre']}: cifrado débil aceptado ({etiqueta})",
                         f"El servidor negoció {cipher}.", objetivo=o,
                         recomendacion="Deshabilitar RC4, 3DES, EXPORT y las suites NULL/anónimas.")
        bits_min = min((vers[v]["bits"] for v in vers), default=256)
        if bits_min and bits_min < 128:
            res.hallazgo("media", f"{cx['nombre']}: cifrado de menos de 128 bits",
                         f"La suite más débil negociada usa {bits_min} bits.", objetivo=o,
                         recomendacion="Ofrecer solo suites de 128 bits o más.")
        if not modernas and not obsoletas:
            res.hallazgo("info", f"{cx['nombre']}: sin versión TLS reconocida", "", objetivo=o)

    res.metrica("Conexiones HTTPS", len(conexiones))
    res.metrica("Con TLS obsoleto", sum(1 for h in res.hallazgos if "obsoletas" in h["titulo"]))
    res.tabla("TLS por servicio", ["Conexión", "Host", "Versiones aceptadas", "Cifrados", "Bits mín."], filas)
    res.nota("Se prueban handshakes TLS 1.0–1.3 bajando el nivel de seguridad del cliente para poder detectar lo "
             "que el servidor realmente acepta. No se envían datos de aplicación.")
    res.resumen = (f"{len(conexiones)} servicios HTTPS; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] in ('alta', 'media'))} con TLS débil.")
    return res.final()


# ── 2. Certificados ─────────────────────────────────────────────────────────

def _cn(nombre) -> str:
    try:
        attrs = nombre.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else nombre.rfc4514_string()
    except Exception:
        return str(nombre)


def _coincide(host: str, nombres: list[str]) -> bool:
    for n in nombres:
        n = n.lower()
        if n == host.lower():
            return True
        if n.startswith("*.") and host.lower().endswith(n[1:]) and host.count(".") == n.count("."):
            return True
    return False


async def certificados(ctx: dict) -> dict:
    res = Resultado("certificados")
    conexiones = await _validas(ctx, res, {"https"})
    ahora = datetime.now(timezone.utc)
    filas = []
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        der = await asyncio.to_thread(_solo_cert, cx["host"], cx["puerto"])
        if not der:
            res.hallazgo("info", f"{cx['nombre']}: no se obtuvo el certificado",
                         "No se completó el handshake (posible SNI requerido).", objetivo=o)
            filas.append([cx["nombre"], o, "—", "—", "—", "—", "—"])
            continue
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as e:
            res.hallazgo("info", f"{cx['nombre']}: certificado ilegible", type(e).__name__, objetivo=o)
            continue

        sujeto, emisor = _cn(cert.subject), _cn(cert.issuer)
        vence = cert.not_valid_after_utc
        desde = cert.not_valid_before_utc
        dias = (vence - ahora).days
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            clave = f"RSA {pub.key_size}"
            clave_debil = pub.key_size < 2048
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            clave = f"EC {pub.curve.name}"
            clave_debil = pub.key_size < 224
        elif isinstance(pub, dsa.DSAPublicKey):
            clave = f"DSA {pub.key_size}"
            clave_debil = True
        else:
            clave, clave_debil = type(pub).__name__, False
        sig = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?").lower()
        autofirmado = cert.subject == cert.issuer

        filas.append([cx["nombre"], o, f"{sujeto} ← {emisor}", vence.strftime("%Y-%m-%d"),
                      dias, clave, sig])

        if dias < 0:
            res.hallazgo("alta", f"{cx['nombre']}: certificado vencido",
                         f"Venció el {vence:%Y-%m-%d} (hace {-dias} días).", objetivo=o,
                         recomendacion="Renovar el certificado de inmediato.")
        elif dias < 30:
            res.hallazgo("media", f"{cx['nombre']}: certificado por vencer",
                         f"Vence el {vence:%Y-%m-%d} (en {dias} días).", objetivo=o,
                         recomendacion="Programar la renovación.")
        if desde > ahora:
            res.hallazgo("media", f"{cx['nombre']}: certificado aún no válido",
                         f"Empieza a valer el {desde:%Y-%m-%d}.", objetivo=o)
        if sig in ("md5", "sha1", "md2"):
            res.hallazgo("alta", f"{cx['nombre']}: firma con algoritmo débil ({sig})",
                         "Las firmas MD5/SHA-1 son falsificables.", objetivo=o,
                         recomendacion="Reemitir el certificado con SHA-256 o superior.")
        if clave_debil:
            res.hallazgo("media", f"{cx['nombre']}: clave débil ({clave})", "", objetivo=o,
                         recomendacion="Usar RSA ≥ 2048 o una curva EC moderna.")
        if autofirmado:
            res.hallazgo("baja", f"{cx['nombre']}: certificado autofirmado",
                         f"Emisor y sujeto son iguales ({emisor}). Aceptable en servicios internos, pero no da "
                         "garantía de identidad.", objetivo=o,
                         recomendacion="Para servicios expuestos, usar un certificado de una CA (Let's Encrypt).")
        elif not _coincide(cx["host"], san + [sujeto]):
            res.hallazgo("baja", f"{cx['nombre']}: el nombre no coincide",
                         f"El certificado cubre {', '.join(san) or sujeto}, no «{cx['host']}». Normal al probar por "
                         "nombre de contenedor en vez del dominio público.", objetivo=o)

    res.metrica("Conexiones HTTPS", len(conexiones))
    res.metrica("Vencidos o por vencer", sum(1 for h in res.hallazgos if "vencid" in h["titulo"].lower() or "por vencer" in h["titulo"]))
    res.tabla("Certificados", ["Conexión", "Host", "Sujeto ← Emisor", "Vence", "Días", "Clave", "Firma"], filas)
    res.nota("Se lee el certificado presentado sin validarlo contra una CA (son servicios internos); los hallazgos "
             "describen su contenido.")
    res.resumen = (f"{len(conexiones)} certificados; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] in ('alta', 'media'))} con problemas serios.")
    return res.final()


# ── 3. Tráfico interno sin cifrar ───────────────────────────────────────────

def _postgres_ssl(host: str, port: int) -> str | None:
    """'S' si ofrece SSL, 'N' si no, None si error. Igual que libpq, sin autenticar."""
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.sendall(struct.pack("!II", 8, 80877103))  # SSLRequest
        r = s.recv(1)
        s.close()
        return r.decode("latin-1") if r else None
    except OSError:
        return None


def _redis_claro(host: str, port: int) -> bool:
    """True si responde al protocolo RESP en texto plano (sin TLS)."""
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.sendall(b"PING\r\n")
        r = s.recv(64)
        s.close()
        return bool(r) and r[:1] in b"+-:$*"
    except OSError:
        return False


async def trafico_claro(ctx: dict) -> dict:
    res = Resultado("trafico_claro")
    conexiones = await _validas(ctx, res, {"http", "https", "postgres", "redis", "minio", "tcp"})
    filas = []
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        proto = cx["protocolo"]
        cifrado, detalle, sev, reco = "—", "", None, ""

        if proto == "https":
            cifrado = "sí (TLS)"
        elif proto == "postgres":
            r = await asyncio.to_thread(_postgres_ssl, cx["host"], cx["puerto"])
            if r == "N":
                cifrado, sev = "NO", "baja"
                detalle = "PostgreSQL no ofrece SSL: usuario, contraseña y datos viajan en claro por la red interna."
                reco = "Habilitar TLS en Postgres (ssl=on) o exigir SSL, sobre todo si la red se comparte con servicios expuestos."
            elif r == "S":
                cifrado = "disponible (TLS)"
                detalle = "Ofrece SSL; verificar que la app lo use (sslmode=require)."
            else:
                cifrado = "¿?"
        elif proto == "redis":
            if await asyncio.to_thread(_redis_claro, cx["host"], cx["puerto"]):
                cifrado, sev = "NO", "baja"
                detalle = "Redis responde en texto plano: comandos y datos (sesiones, tokens) viajan sin cifrar."
                reco = "Usar Redis con TLS (puerto TLS) si la red no es de confianza."
        elif proto == "minio":
            cifrado, sev = "NO", "baja"
            detalle = "Almacenamiento de objetos por HTTP: credenciales y archivos viajan en claro en la red interna."
            reco = "Servir MinIO por HTTPS o aislar su red."
        elif proto == "http":
            clase = servicio(cx["puerto"])[1]
            cifrado = "NO"
            if clase in ("admin", "bd", "metricas"):
                sev, detalle = "baja", f"HTTP sin cifrar hacia un servicio de tipo «{NOMBRE_CLASE[clase]}»."
                reco = "Exponer solo por el proxy TLS; evitar HTTP directo con datos sensibles."
            else:
                sev, detalle = "info", "HTTP sin cifrar en la red interna (normal si el TLS termina en el proxy)."
        elif proto == "tcp":
            cifrado = "¿? (TCP)"

        filas.append([cx["nombre"], o, proto.upper(), cifrado])
        if sev:
            res.hallazgo(sev, f"{cx['nombre']}: {'tráfico sin cifrar' if cifrado == 'NO' else 'revisar cifrado'}",
                         detalle, objetivo=o, recomendacion=reco)

    sin_cifrar = sum(1 for f in filas if f[3] == "NO")
    res.metrica("Conexiones", len(conexiones))
    res.metrica("Sin cifrar", sin_cifrar)
    res.tabla("Cifrado del transporte", ["Conexión", "Host", "Protocolo", "Cifrado"], filas)
    res.nota("Las redes Docker están aisladas entre sí, así que el tráfico en claro solo es visible para un "
             "contenedor comprometido de la MISMA red. Aun así, las bases de datos y el almacenamiento son los "
             "más sensibles. Cruzar con la prueba «Segmentación entre redes».")
    res.resumen = f"{len(conexiones)} servicios; {sin_cifrar} sin cifrar en la red interna."
    return res.final()


PRUEBAS_CIFRADO = {"tls": tls, "certificados": certificados, "trafico_claro": trafico_claro}
