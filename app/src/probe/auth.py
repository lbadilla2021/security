"""
Pruebas de «Autenticación y sesiones» de solo lectura.

  autenticacion    → endpoints que devuelven datos sin pedir token (solo GET)
  sesiones_cookies → atributos de seguridad de las cookies (Set-Cookie)

No envían credenciales, intentos de login ni tokens: solo peticiones GET. Las
pruebas que sí requieren probar accesos (fuerza bruta, enumeración de usuarios,
JWT forjados, MFA, recuperación de contraseña) NO están aquí.
"""

from __future__ import annotations

import contextlib
import secrets

import httpx

from comun import ErrorPrueba, Resultado
from probe.escaner import resolver
from probe.red import interfaces, verificar_alcance

TIMEOUT = 6.0
UA = "security-probe (auditoria interna)"
LIMITE = 16 * 1024


async def _validas(ctx: dict, res: Resultado) -> list[dict]:
    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in ("http", "https", "minio")]
    if not conexiones:
        raise ErrorPrueba("Asigna al menos una conexión HTTP/HTTPS a esta prueba.")
    ifaces = interfaces()
    validas = []
    for cx in conexiones:
        ips = await resolver(cx["host"])
        if not ips:
            res.hallazgo("info", f"{cx['nombre']}: el host no resuelve", f"{cx['host']} no tiene DNS.", objetivo=cx["host"])
            continue
        if next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None):
            continue
        validas.append(cx)
    return validas


def _esquema(cx):
    return "https" if cx["protocolo"] == "https" else "http"


@contextlib.asynccontextmanager
async def _cliente(cx):
    async with httpx.AsyncClient(
        base_url=f"{_esquema(cx)}://{cx['host']}:{cx['puerto']}",
        verify=False, follow_redirects=False, timeout=TIMEOUT,
        headers={"User-Agent": UA}, limits=httpx.Limits(max_connections=4),
    ) as c:
        yield c


async def _get(c, ruta):
    try:
        async with c.stream("GET", ruta) as r:
            datos = b""
            async for t in r.aiter_bytes():
                datos += t
                if len(datos) >= LIMITE:
                    break
            return r, datos[:LIMITE]
    except httpx.HTTPError:
        return None, b""


# ── 1. Endpoints sin autenticación ──────────────────────────────────────────

# (ruta, categoría)
ENDPOINTS = [
    ("/api/users", "usuarios"), ("/api/v1/users", "usuarios"), ("/rest/users", "usuarios"),
    ("/api/accounts", "usuarios"), ("/api/members", "usuarios"), ("/api/customers", "usuarios"),
    ("/api/admin", "admin"), ("/admin/api", "admin"), ("/api/v1/admin", "admin"),
    ("/api/keys", "credenciales"), ("/api/apikeys", "credenciales"), ("/api/api-keys", "credenciales"),
    ("/api/tokens", "credenciales"), ("/api/credentials", "credenciales"), ("/rest/credentials", "credenciales"),
    ("/api/secrets", "credenciales"),
    ("/api/settings", "config"), ("/api/config", "config"), ("/api/configuration", "config"),
    ("/api/v1/settings", "config"),
    ("/api/logs", "datos"), ("/api/audit", "datos"), ("/api/audit-logs", "datos"), ("/api/events", "datos"),
    ("/api/orders", "datos"), ("/api/invoices", "datos"), ("/api/documents", "datos"),
    ("/api/me", "sesión"), ("/api/profile", "sesión"), ("/api/whoami", "sesión"),
    ("/rest/workflows", "operaciones"), ("/api/v1/workflows", "operaciones"), ("/api/workflows", "operaciones"),
    ("/api/executions", "operaciones"),
]

CAT_SEV = {"usuarios": "alta", "credenciales": "alta", "admin": "alta",
           "config": "media", "datos": "media", "operaciones": "media", "sesión": "media"}
CAT_TXT = {"usuarios": "lista de usuarios/cuentas", "credenciales": "claves o credenciales",
           "admin": "funciones de administración", "config": "configuración",
           "datos": "datos de negocio", "operaciones": "operaciones", "sesión": "datos de sesión"}


def _parece_datos(ct: str, cuerpo: bytes) -> bool:
    ct = ct.lower()
    if "json" in ct:
        return True
    if ct.startswith("text/html"):
        return False
    s = cuerpo.lstrip()[:1]
    return s in (b"{", b"[")


async def autenticacion(ctx: dict) -> dict:
    res = Resultado("autenticacion")
    conexiones = await _validas(ctx, res)
    filas = []
    evaluados = 0
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        async with _cliente(cx) as c:
            rb, base = await _get(c, f"/{secrets.token_hex(8)}")
            if rb is None:
                res.hallazgo("info", f"{cx['nombre']}: sin respuesta", "", objetivo=o)
                continue
            if rb.status_code == 400:
                res.hallazgo("info", f"{cx['nombre']}: rechaza por Host", "Responde 400 a las peticiones por nombre "
                             "de contenedor (valida el encabezado Host); no evaluable por este medio.", objetivo=o)
                continue
            catch_all = rb.status_code == 200
            evaluados += 1
            protegidos = abiertos = 0

            for ruta, cat in ENDPOINTS:
                r, cuerpo = await _get(c, ruta)
                if r is None:
                    continue
                st = r.status_code
                if st in (401, 403) or (st in (301, 302, 303, 307, 308)
                                        and "login" in r.headers.get("location", "").lower()):
                    protegidos += 1
                    continue
                if st != 200 or cuerpo == base:
                    continue
                ct = r.headers.get("content-type", "")
                if catch_all and not _parece_datos(ct, cuerpo):
                    continue  # SPA que responde 200 a todo
                if not _parece_datos(ct, cuerpo):
                    continue
                abiertos += 1
                filas.append([cx["nombre"], ruta, st, ct.split(";")[0], cat, len(cuerpo)])
                res.hallazgo(CAT_SEV[cat], f"{cx['nombre']}: {ruta} responde sin autenticación",
                             f"GET {ruta} devuelve 200 con datos ({ct.split(';')[0]}, {len(cuerpo)} bytes) sin enviar "
                             f"ningún token. Categoría: {CAT_TXT[cat]}.", objetivo=f"{o}{ruta}",
                             recomendacion="Confirmar que el endpoint deba exigir autenticación; si es así, protegerlo. "
                             "Si es público a propósito, revisar que no exponga datos sensibles.")
            if abiertos == 0 and protegidos:
                res.nota(f"{cx['nombre']}: {protegidos} endpoints respondieron 401/403/redirección a login (protegidos).")

    res.metrica("Conexiones", len(conexiones))
    res.metrica("Servicios evaluados", evaluados)
    res.metrica("Endpoints probados c/u", len(ENDPOINTS))
    res.metrica("Endpoints abiertos", len(filas))
    res.tabla("Endpoints accesibles sin token", ["Conexión", "Ruta", "HTTP", "Tipo", "Categoría", "Bytes"], filas)
    res.nota("Solo peticiones GET sin credenciales. Se descartan respuestas de SPA que contestan 200 a cualquier "
             "ruta y los servicios que rechazan por Host. Un 401/403 o una redirección a /login se consideran protegidos.")
    res.resumen = (f"{evaluados} servicios evaluados; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] in ('alta', 'media'))} endpoints sin autenticación.")
    return res.final()


# ── 2. Sesiones y cookies ───────────────────────────────────────────────────

RUTAS_COOKIE = ["/", "/login", "/auth", "/api/auth/login", "/signin", "/users/login"]
NOMBRE_SESION = ("session", "sess", "sid", "token", "jwt", "auth", "connect.sid", "phpsessid", "jsessionid")
NOMBRE_CSRF = ("csrf", "xsrf")


def _parse_cookie(raw: str):
    partes = [p.strip() for p in raw.split(";") if p.strip()]
    if not partes:
        return None
    nombre = partes[0].split("=", 1)[0].strip()
    attrs = {}
    for p in partes[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.lower()] = True
    return nombre, attrs


async def sesiones_cookies(ctx: dict) -> dict:
    res = Resultado("sesiones_cookies")
    conexiones = await _validas(ctx, res)
    filas = []
    total_cookies = 0
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        es_https = _esquema(cx) == "https"
        vistas: dict[str, dict] = {}
        async with _cliente(cx) as c:
            for ruta in RUTAS_COOKIE:
                r, _ = await _get(c, ruta)
                if r is None:
                    continue
                for raw in r.headers.get_list("set-cookie"):
                    pc = _parse_cookie(raw)
                    if pc:
                        vistas.setdefault(pc[0], pc[1])
        if not vistas:
            res.nota(f"{cx['nombre']}: no fijó cookies en las rutas probadas (normal si solo las crea tras el login).")
            continue
        for nombre, attrs in vistas.items():
            total_cookies += 1
            n = nombre.lower()
            es_sesion = any(k in n for k in NOMBRE_SESION)
            es_csrf = any(k in n for k in NOMBRE_CSRF)
            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = str(attrs.get("samesite", "")).lower() or "—"
            filas.append([cx["nombre"], nombre, "sí" if secure else "no", "sí" if httponly else "no",
                          samesite, "sesión" if es_sesion else ("csrf" if es_csrf else "otra")])
            etq = f"cookie «{nombre}»"
            if es_https and not secure:
                res.hallazgo("media", f"{cx['nombre']}: {etq} sin Secure",
                             "En un sitio HTTPS, una cookie sin Secure puede enviarse por HTTP si hay una degradación.",
                             objetivo=o, recomendacion="Marcar la cookie como Secure.")
            if es_sesion and not es_csrf and not httponly:
                res.hallazgo("media", f"{cx['nombre']}: {etq} de sesión sin HttpOnly",
                             "Una cookie de sesión sin HttpOnly es legible por JavaScript: un XSS puede robarla.",
                             objetivo=o, recomendacion="Marcar la cookie de sesión como HttpOnly.")
            if samesite == "—":
                res.hallazgo("baja", f"{cx['nombre']}: {etq} sin SameSite",
                             "Sin SameSite, la cookie viaja en peticiones de otros sitios (riesgo CSRF).",
                             objetivo=o, recomendacion="Definir SameSite=Lax o Strict.")
            elif samesite == "none" and not secure:
                res.hallazgo("media", f"{cx['nombre']}: {etq} con SameSite=None sin Secure",
                             "SameSite=None exige Secure; sin él, el navegador la rechaza o queda expuesta.",
                             objetivo=o, recomendacion="Agregar Secure o cambiar SameSite a Lax/Strict.")

    res.metrica("Conexiones", len(conexiones))
    res.metrica("Cookies observadas", total_cookies)
    res.tabla("Cookies", ["Conexión", "Cookie", "Secure", "HttpOnly", "SameSite", "Tipo"], filas)
    res.nota("Se revisan las cookies fijadas al visitar / y rutas de login habituales (solo GET). La mayoría de las "
             "apps fijan la cookie de sesión recién al autenticarse, así que esta prueba cubre lo visible sin login.")
    res.resumen = (f"{total_cookies} cookies en {len(conexiones)} servicios; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] == 'media')} con atributos faltantes importantes.")
    return res.final()


PRUEBAS_AUTH = {"autenticacion": autenticacion, "sesiones_cookies": sesiones_cookies}
