"""
Pruebas de «Web y HTTP» de solo lectura (auditoría/escaneo).

Hacen únicamente peticiones GET / OPTIONS / HEAD / TRACE a servicios internos
ya configurados como conexiones. No envían credenciales, no mandan payloads de
ataque y no usan métodos que modifiquen estado (PUT/POST/DELETE/PATCH): los
métodos peligrosos solo se *reportan* si el servidor los anuncia en Allow.

Las pruebas de explotación activa (inyección, XSS, SSRF, traversal, carga de
archivos, deserialización, smuggling, host header) NO están aquí.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets

import httpx

from comun import ErrorPrueba, Resultado
from probe.escaner import resolver
from probe.red import interfaces, verificar_alcance

LIMITE_CUERPO = 24 * 1024
TIMEOUT = 6.0
UA = "security-probe (auditoria interna)"


# ── Preparación: conexiones web alcanzables ─────────────────────────────────

async def _conexiones_web(ctx: dict, res: Resultado) -> list[dict]:
    conexiones = [c for c in (ctx.get("conexiones") or [])
                  if c["protocolo"] in ("http", "https", "minio")]
    if not conexiones:
        raise ErrorPrueba("Asigna al menos una conexión HTTP/HTTPS a esta prueba.")
    ifaces = interfaces()
    validas = []
    for cx in conexiones:
        ips = await resolver(cx["host"])
        if not ips:
            res.hallazgo("info", f"{cx['nombre']}: el host no resuelve", f"{cx['host']} no tiene DNS.",
                         objetivo=cx["host"])
            continue
        motivo = next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None)
        if motivo:
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance", motivo, objetivo=cx["host"])
            continue
        validas.append(cx)
    return validas


def _esquema(cx: dict) -> str:
    return "https" if cx["protocolo"] == "https" else "http"


def _url(cx: dict) -> str:
    return f"{cx['host']}:{cx['puerto']}"


@contextlib.asynccontextmanager
async def _cliente(cx: dict):
    async with httpx.AsyncClient(
        base_url=f"{_esquema(cx)}://{cx['host']}:{cx['puerto']}",
        verify=False, follow_redirects=False, timeout=TIMEOUT,
        headers={"User-Agent": UA}, limits=httpx.Limits(max_connections=4),
    ) as c:
        yield c


async def _get(c: httpx.AsyncClient, ruta: str, **kw):
    """GET sin leer cuerpo (solo cabeceras). Devuelve (resp|None, error|None)."""
    try:
        async with c.stream("GET", ruta, **kw) as r:
            return r, None
    except httpx.HTTPError as e:
        return None, type(e).__name__


async def _get_cuerpo(c: httpx.AsyncClient, ruta: str, limite: int = LIMITE_CUERPO, **kw):
    try:
        async with c.stream("GET", ruta, **kw) as r:
            datos = b""
            async for trozo in r.aiter_bytes():
                datos += trozo
                if len(datos) >= limite:
                    break
            return r, datos[:limite], None
    except httpx.HTTPError as e:
        return None, b"", type(e).__name__


def _texto(datos: bytes) -> str:
    return datos.decode("utf-8", "replace")


# ── 1. Cabeceras de seguridad ───────────────────────────────────────────────

async def cabeceras_http(ctx: dict) -> dict:
    res = Resultado("cabeceras_http")
    conexiones = await _conexiones_web(ctx, res)
    filas = []
    for cx in conexiones:
        async with _cliente(cx) as c:
            r, err = await _get(c, "/")
        if err:
            res.hallazgo("info", f"{cx['nombre']}: sin respuesta", err, objetivo=_url(cx))
            continue
        h = {k.lower(): v for k, v in r.headers.items()}
        es_https = _esquema(cx) == "https"
        o = _url(cx)

        def falta(nombre, sev, texto, reco):
            res.hallazgo(sev, f"{cx['nombre']}: {texto}", f"La respuesta a GET / ({r.status_code}) no incluye "
                         f"{nombre}.", objetivo=o, recomendacion=reco)

        csp = h.get("content-security-policy")
        if not csp:
            falta("Content-Security-Policy", "media", "sin Content-Security-Policy",
                  "Definir una CSP para limitar de dónde se cargan scripts y a quién se conecta la página.")
        else:
            flojos = [t for t in ("unsafe-inline", "unsafe-eval") if t in csp]
            if "default-src *" in csp or re.search(r"(script-src|default-src)[^;]*\*", csp):
                flojos.append("comodín *")
            if flojos:
                res.hallazgo("baja", f"{cx['nombre']}: CSP permisiva", f"La CSP usa {', '.join(flojos)}, "
                             "lo que debilita su protección contra XSS.", objetivo=o,
                             recomendacion="Evitar unsafe-inline/unsafe-eval y comodines; usar nonces o hashes.")

        if es_https and "strict-transport-security" not in h:
            falta("Strict-Transport-Security (HSTS)", "media", "HTTPS sin HSTS",
                  "Agregar HSTS para que el navegador use siempre HTTPS con este servicio.")

        if "x-content-type-options" not in h or "nosniff" not in h.get("x-content-type-options", "").lower():
            falta("X-Content-Type-Options: nosniff", "baja", "sin X-Content-Type-Options",
                  "Agregar «X-Content-Type-Options: nosniff».")

        tiene_fa = "frame-ancestors" in (csp or "")
        if "x-frame-options" not in h and not tiene_fa:
            falta("X-Frame-Options / frame-ancestors", "baja", "sin protección contra clickjacking",
                  "Agregar «X-Frame-Options: DENY» o «frame-ancestors 'none'» en la CSP.")

        for nombre, etiqueta in (("referrer-policy", "Referrer-Policy"),
                                 ("permissions-policy", "Permissions-Policy")):
            if nombre not in h:
                falta(etiqueta, "info", f"sin {etiqueta}", f"Agregar {etiqueta} (defensa en profundidad).")

        presentes = sum(1 for k in ("content-security-policy", "strict-transport-security",
                                    "x-content-type-options", "x-frame-options", "referrer-policy",
                                    "permissions-policy") if k in h) + (1 if tiene_fa else 0)
        filas.append([cx["nombre"], _url(cx), _esquema(cx).upper(), r.status_code, f"{min(presentes, 6)}/6",
                      "sí" if csp else "no", "sí" if es_https and "strict-transport-security" in h else ("—" if not es_https else "no")])

    res.metrica("Conexiones", len(conexiones))
    res.tabla("Cabeceras por servicio", ["Conexión", "Host", "Esquema", "HTTP", "Cabeceras", "CSP", "HSTS"], filas)
    res.nota("Se evalúa la respuesta a GET /. Un servicio que redirige (3xx) puede poner las cabeceras en el "
             "destino final; revisar el caso concreto.")
    res.resumen = (f"{len(conexiones)} servicios; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] == 'media')} con faltantes importantes.")
    return res.final()


# ── 2. Métodos HTTP permitidos ──────────────────────────────────────────────

PELIGROSOS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE", "TRACK"}


async def metodos_http(ctx: dict) -> dict:
    res = Resultado("metodos_http")
    conexiones = await _conexiones_web(ctx, res)
    filas = []
    for cx in conexiones:
        o = _url(cx)
        async with _cliente(cx) as c:
            # OPTIONS: lee el Allow anunciado (no invoca los métodos).
            allow = ""
            try:
                ro = await c.request("OPTIONS", "/")
                allow = ro.headers.get("allow", "") or ro.headers.get("access-control-allow-methods", "")
            except httpx.HTTPError:
                ro = None
            # TRACE: no modifica estado; detecta Cross-Site Tracing.
            trace_ok = False
            try:
                async with c.stream("TRACE", "/") as rt:
                    cuerpo = b""
                    async for t in rt.aiter_bytes():
                        cuerpo += t
                        if len(cuerpo) > 2048:
                            break
                    trace_ok = rt.status_code == 200 and b"TRACE /" in cuerpo
            except httpx.HTTPError:
                pass

        metodos = {m.strip().upper() for m in allow.split(",") if m.strip()}
        peligrosos = sorted(metodos & PELIGROSOS)
        filas.append([cx["nombre"], o, ", ".join(sorted(metodos)) or "(sin Allow)", "sí" if trace_ok else "no"])
        if trace_ok:
            res.hallazgo("media", f"{cx['nombre']}: método TRACE activo",
                         "El servidor responde a TRACE reflejando la petición (Cross-Site Tracing).",
                         objetivo=o, recomendacion="Deshabilitar TRACE en el servidor/proxy.")
        for m in peligrosos:
            if m == "TRACE" and trace_ok:
                continue
            res.hallazgo("baja", f"{cx['nombre']}: método {m} anunciado",
                         f"OPTIONS declara el método {m} como permitido.", objetivo=o,
                         recomendacion=f"Confirmar que {m} es necesario; si no, restringirlo.")
        if not metodos and not trace_ok:
            res.nota(f"{cx['nombre']}: no respondió a OPTIONS con Allow (común en APIs por ruta).")

    res.metrica("Conexiones", len(conexiones))
    res.tabla("Métodos por servicio", ["Conexión", "Host", "Allow (OPTIONS /)", "TRACE"], filas)
    res.nota("Solo se envían OPTIONS y TRACE (no modifican datos). Los métodos de escritura NO se invocan: "
             "se informan únicamente si el servidor los anuncia.")
    res.resumen = f"{len(conexiones)} servicios; {len(res.hallazgos)} hallazgos de métodos."
    return res.final()


# ── 3. CORS ─────────────────────────────────────────────────────────────────

ORIGEN_PRUEBA = "https://origen-no-confiable.example"


async def cors(ctx: dict) -> dict:
    res = Resultado("cors")
    conexiones = await _conexiones_web(ctx, res)
    filas = []
    for cx in conexiones:
        o = _url(cx)
        async with _cliente(cx) as c:
            r, err = await _get(c, "/", headers={"Origin": ORIGEN_PRUEBA})
            acao = acac = None
            if r is not None:
                acao = r.headers.get("access-control-allow-origin")
                acac = r.headers.get("access-control-allow-credentials")
        if err:
            res.hallazgo("info", f"{cx['nombre']}: sin respuesta", err, objetivo=o)
            continue
        refleja = acao == ORIGEN_PRUEBA
        comodin = acao == "*"
        credenciales = (acac or "").lower() == "true"
        filas.append([cx["nombre"], o, acao or "—", "sí" if credenciales else "no"])
        if refleja and credenciales:
            res.hallazgo("alta", f"{cx['nombre']}: CORS refleja cualquier origen con credenciales",
                         f"Devuelve Access-Control-Allow-Origin: {acao} (el origen enviado) junto con "
                         "Allow-Credentials: true. Cualquier sitio puede leer respuestas autenticadas de este servicio.",
                         objetivo=o, recomendacion="Validar el Origin contra una lista blanca; nunca reflejar el "
                         "origen recibido junto con credenciales.")
        elif refleja:
            res.hallazgo("media", f"{cx['nombre']}: CORS refleja el origen recibido",
                         f"Devuelve Access-Control-Allow-Origin: {acao} sin validarlo.", objetivo=o,
                         recomendacion="Responder solo a orígenes de una lista blanca.")
        elif comodin and credenciales:
            res.hallazgo("media", f"{cx['nombre']}: CORS comodín con credenciales",
                         "Access-Control-Allow-Origin: * junto a Allow-Credentials: true (combinación inconsistente "
                         "y peligrosa).", objetivo=o, recomendacion="Quitar el comodín o las credenciales.")

    res.metrica("Conexiones", len(conexiones))
    res.tabla("CORS por servicio", ["Conexión", "Host", "Allow-Origin (Origin ajeno)", "Credenciales"], filas)
    res.nota(f"Se envía un GET con Origin «{ORIGEN_PRUEBA}» y se observa si el servicio lo refleja.")
    res.resumen = f"{len(conexiones)} servicios; {len(res.hallazgos)} con CORS permisivo."
    return res.final()


# ── 4. Rutas y archivos expuestos ───────────────────────────────────────────

# (ruta, categoría, firma que confirma el contenido o None)
RUTAS = [
    ("/.env", "secreto", re.compile(rb"(?im)^[A-Z0-9_]+\s*=")),
    ("/.git/config", "código", re.compile(rb"\[core\]")),
    ("/.git/HEAD", "código", re.compile(rb"ref:\s")),
    ("/.svn/entries", "código", None),
    ("/.hg/requires", "código", None),
    ("/.DS_Store", "info", re.compile(rb"Bud1")),
    ("/.htpasswd", "secreto", re.compile(rb":\$")),
    ("/config.json", "config", None),
    ("/config.yaml", "config", None),
    ("/docker-compose.yml", "config", re.compile(rb"(?m)^services:")),
    ("/backup.sql", "respaldo", re.compile(rb"(?i)(INSERT INTO|CREATE TABLE)")),
    ("/dump.sql", "respaldo", re.compile(rb"(?i)(INSERT INTO|CREATE TABLE)")),
    ("/backup.zip", "respaldo", re.compile(rb"^PK\x03\x04")),
    ("/db.sqlite3", "respaldo", re.compile(rb"SQLite format 3")),
    ("/.aws/credentials", "secreto", re.compile(rb"aws_access_key_id")),
    ("/.npmrc", "secreto", re.compile(rb"_authToken")),
    ("/wp-config.php", "config", None),
    ("/phpinfo.php", "info", re.compile(rb"phpinfo\(\)")),
    ("/server-status", "info", re.compile(rb"Apache Server Status")),
    ("/actuator", "api", re.compile(rb'"_links"')),
    ("/actuator/env", "secreto", re.compile(rb'"systemProperties"')),
    ("/actuator/health", "api", re.compile(rb'"status"')),
    ("/metrics", "metricas", re.compile(rb"(?m)^# (HELP|TYPE) ")),
    ("/debug/pprof/", "api", re.compile(rb"goroutine")),
    ("/docs", "api", re.compile(rb"(swagger|redoc|openapi)", re.I)),
    ("/openapi.json", "api", re.compile(rb'"openapi"')),
    ("/swagger.json", "api", re.compile(rb'"swagger"')),
    ("/graphql", "api", None),
]

CAT_SEV = {"secreto": "alta", "respaldo": "alta", "código": "alta", "config": "media",
           "api": "baja", "metricas": "baja", "info": "baja"}
CAT_RECO = {
    "secreto": "Quitar el archivo del contenido servido de inmediato y rotar las credenciales que contenga.",
    "respaldo": "Mover los respaldos fuera de la raíz web; nunca servirlos por HTTP.",
    "código": "Bloquear el acceso a .git/.svn/.hg en el servidor y no desplegarlos.",
    "config": "No servir archivos de configuración; moverlos fuera de la raíz web.",
    "api": "Si es un entorno de producción, deshabilitar la documentación/endpoint o exigir autenticación.",
    "metricas": "Restringir /metrics a la red de monitoreo o exigir autenticación.",
    "info": "Eliminar el archivo o bloquear su acceso.",
}


async def rutas_expuestas(ctx: dict) -> dict:
    res = Resultado("rutas_expuestas")
    conexiones = await _conexiones_web(ctx, res)
    filas = []
    protegidas = 0
    for cx in conexiones:
        o = _url(cx)
        async with _cliente(cx) as c:
            # Línea base para detectar catch-all / soft-404 (SPA que devuelve index).
            # Se lee con el MISMO tope que las candidatas para poder comparar cuerpos.
            rb, base_cuerpo, _ = await _get_cuerpo(c, f"/{secrets.token_hex(8)}-no-existe")
            catch_all = rb is not None and rb.status_code == 200

            for ruta, cat, firma in RUTAS:
                r, cuerpo, err = await _get_cuerpo(c, ruta)
                if err or r is None:
                    continue
                st = r.status_code
                if st in (401, 403):
                    protegidas += 1  # el servicio rechaza el acceso (bien); no se lista
                    continue
                if st != 200 or cuerpo == base_cuerpo:
                    continue  # igual que una ruta inexistente → la app responde a todo
                tipo = r.headers.get("content-type", "").lower()
                if firma is not None:
                    if not firma.search(cuerpo):
                        continue  # 200 pero el contenido no corresponde
                    etiqueta = "confirmado"
                else:
                    # Sin firma: un archivo sensible real no se sirve como la página HTML de la app.
                    if catch_all and tipo.startswith("text/html"):
                        continue
                    etiqueta = tipo.split(";")[0] or "200"
                filas.append([cx["nombre"], ruta, st, cat, etiqueta])
                res.hallazgo(CAT_SEV[cat], f"{cx['nombre']}: {ruta} accesible",
                             f"GET {ruta} devuelve 200 ({tipo or 'sin tipo'})"
                             + (" con contenido que coincide con lo esperado." if firma is not None else ".")
                             + f" Categoría: {cat}.", objetivo=f"{o}{ruta}",
                             recomendacion=CAT_RECO[cat])

    res.metrica("Conexiones", len(conexiones))
    res.metrica("Rutas probadas por host", len(RUTAS))
    res.metrica("Rutas expuestas (200)", len(filas))
    res.metrica("Accesos rechazados (401/403)", protegidas)
    res.tabla("Rutas accesibles (200)", ["Conexión", "Ruta", "HTTP", "Categoría", "Tipo"], filas)
    res.nota("Solo se hacen peticiones GET. Se descartan respuestas de aplicaciones que contestan 200 a cualquier "
             "ruta (SPA con catch-all) comparando con una ruta aleatoria inexistente.")
    res.resumen = (f"{len(conexiones)} servicios; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] in ('alta', 'media'))} rutas sensibles.")
    return res.final()


# ── 5. Fuga de información ───────────────────────────────────────────────────

MARCAS_TRAZA = [
    (re.compile(rb"Traceback \(most recent call last\)"), "traza de Python"),
    (re.compile(rb"Werkzeug Debugger|werkzeug\.debug"), "depurador Werkzeug activo"),
    (re.compile(rb"(?i)<b>Fatal error</b>|on line <b>\d+"), "error de PHP"),
    (re.compile(rb"org\.springframework|java\.lang\.[A-Za-z]+Exception"), "traza de Java"),
    (re.compile(rb"(?i)SQLSTATE\[|syntax error at or near|psql:"), "error de base de datos"),
    (re.compile(rb"(?i)stack trace:|at [\w./]+:\d+\)"), "traza de pila"),
    (re.compile(rb"(?i)ActiveRecord::|RAILS_ENV"), "traza de Rails"),
]
CABECERAS_DELATORAS = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                       "x-runtime", "x-generator", "x-drupal-cache"]


async def fuga_informacion(ctx: dict) -> dict:
    res = Resultado("fuga_informacion")
    conexiones = await _conexiones_web(ctx, res)
    filas = []
    for cx in conexiones:
        o = _url(cx)
        async with _cliente(cx) as c:
            r, cuerpo, err = await _get_cuerpo(c, "/")
            if err or r is None:
                res.hallazgo("info", f"{cx['nombre']}: sin respuesta", err or "", objetivo=o)
                continue
            h = {k.lower(): v for k, v in r.headers.items()}
            server = h.get("server", "")
            powered = [f"{k}: {h[k]}" for k in CABECERAS_DELATORAS if k in h]

            # Página de error forzada (ruta inexistente): busca trazas.
            re404, cuerpo404, _ = await _get_cuerpo(c, f"/{secrets.token_hex(6)}.err")
            marcas = set()
            for cuerpo_rev in (cuerpo, cuerpo404 or b""):
                for patron, etiqueta in MARCAS_TRAZA:
                    if patron.search(cuerpo_rev):
                        marcas.add(etiqueta)

        version = bool(re.search(r"\d+\.\d+", server))
        filas.append([cx["nombre"], o, server or "—", ", ".join(powered) or "—",
                      ", ".join(sorted(marcas)) or "—"])

        if marcas:
            res.hallazgo("media", f"{cx['nombre']}: fuga de detalles internos en errores",
                         f"Las respuestas revelan: {', '.join(sorted(marcas))}. Esto expone rutas, versiones y "
                         "estructura interna que facilitan un ataque dirigido.", objetivo=o,
                         recomendacion="Desactivar el modo debug en producción y servir páginas de error genéricas.")
        if powered:
            res.hallazgo("baja", f"{cx['nombre']}: cabeceras que revelan la tecnología",
                         f"Presentes: {', '.join(powered)}.", objetivo=o,
                         recomendacion="Quitar esas cabeceras (p. ej. en el proxy).")
        if version:
            res.hallazgo("baja", f"{cx['nombre']}: versión del servidor expuesta",
                         f"Cabecera Server: «{server}».", objetivo=o,
                         recomendacion="Ocultar la versión (server_tokens off, ServerTokens Prod, etc.).")

    res.metrica("Conexiones", len(conexiones))
    res.tabla("Información expuesta", ["Conexión", "Host", "Server", "Cabeceras de tecnología", "Trazas/errores"], filas)
    res.nota("Se revisa la respuesta a GET / y a una ruta inexistente, buscando trazas de error y cabeceras que "
             "delatan la tecnología. No se envían payloads.")
    res.resumen = (f"{len(conexiones)} servicios; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] == 'media')} con fuga en errores.")
    return res.final()


PRUEBAS_WEB = {
    "cabeceras_http": cabeceras_http,
    "metodos_http": metodos_http,
    "cors": cors,
    "rutas_expuestas": rutas_expuestas,
    "fuga_informacion": fuga_informacion,
}
