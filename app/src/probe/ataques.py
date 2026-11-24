"""
Pruebas intrusivas (envían intentos de acceso). Requieren confirmación y
parámetros explícitos. Pensadas para correr contra Demo o con objetivos
controlados, NO a ciegas contra producción.

  fuerza_bruta → envía N intentos de login con un correo INEXISTENTE y una
                 contraseña incorrecta, para ver si el endpoint frena los
                 intentos (rate limit por IP, fail2ban). Con un correo que no
                 existe no se bloquea ninguna cuenta real. Si detecta que la
                 cuenta sí existe (respuesta 423), se detiene de inmediato.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import secrets
import statistics
import time
from collections import Counter
from datetime import datetime, timezone

import httpx

from comun import ErrorPrueba, Resultado
from probe.escaner import resolver
from probe.red import interfaces, verificar_alcance

TIMEOUT = 8.0
UA = "security-probe (prueba de fuerza bruta autorizada)"


@contextlib.asynccontextmanager
async def _cliente(cx, host_header: str):
    esquema = "https" if cx["protocolo"] == "https" else "http"
    headers = {"User-Agent": UA}
    if host_header:
        headers["Host"] = host_header
    async with httpx.AsyncClient(
        base_url=f"{esquema}://{cx['host']}:{cx['puerto']}",
        verify=False, follow_redirects=False, timeout=TIMEOUT,
        headers=headers, limits=httpx.Limits(max_connections=2),
    ) as c:
        yield c


async def fuerza_bruta(ctx: dict) -> dict:
    res = Resultado("fuerza_bruta")
    p = ctx.get("parametros") or {}
    email = (p.get("email") or "").strip()
    if not email or "@" not in email:
        raise ErrorPrueba("Indica un correo objetivo válido que NO exista en la base de datos.")
    try:
        intentos = int(p.get("intentos") or 12)
    except (TypeError, ValueError):
        intentos = 12
    intentos = max(1, min(intentos, 50))
    ruta = (p.get("ruta") or "/api/v1/auth/login").strip()
    formato = p.get("formato") or "json"
    campo_u = (p.get("campo_usuario") or "email").strip()
    campo_p = (p.get("campo_password") or "password").strip()
    host_header = (p.get("host_header") or "").strip()
    password = "FuerzaBruta-Prueba-" + secrets.token_hex(6)  # contraseña incorrecta fija

    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in ("http", "https")]
    if not conexiones:
        raise ErrorPrueba("Asigna una conexión HTTP/HTTPS (el login objetivo) a esta prueba.")
    ifaces = interfaces()

    filas = []
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        ips = await resolver(cx["host"])
        if not ips or next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None):
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance o sin DNS", "", objetivo=o)
            continue

        codigos: list[int] = []
        bloqueado_en = None
        tipo_bloqueo = None  # rate_limit | cuenta | red
        cuerpo = {campo_u: email, campo_p: password}
        async with _cliente(cx, host_header) as c:
            for i in range(1, intentos + 1):
                try:
                    if formato == "form":
                        r = await c.post(ruta, data=cuerpo)
                    else:
                        r = await c.post(ruta, json=cuerpo)
                except httpx.HTTPError as e:
                    tipo_bloqueo, bloqueado_en = "red", i
                    codigos.append(-1)
                    res.nota(f"{cx['nombre']}: sin respuesta de red en el intento {i} ({type(e).__name__}).")
                    break
                codigos.append(r.status_code)
                if r.status_code == 423:
                    tipo_bloqueo, bloqueado_en = "cuenta", i
                    break
                if r.status_code == 429:
                    tipo_bloqueo, bloqueado_en = "rate_limit", i
                    break

        enviados = len([c for c in codigos if c != -1])
        dominante = Counter(c for c in codigos if c not in (-1, 429, 423)).most_common(1)
        dominante = dominante[0][0] if dominante else None

        # ── Interpretación ──
        if tipo_bloqueo == "cuenta":
            resultado = f"La cuenta EXISTE (423) en el intento {bloqueado_en}"
            res.hallazgo("media", f"{cx['nombre']}: el correo objetivo existe — se detuvo la prueba",
                         f"En el intento {bloqueado_en} el servidor respondió 423 (cuenta bloqueada): el correo «{email}» "
                         f"SÍ está en la base de datos y acaba de quedar bloqueado por los intentos de esta prueba.",
                         objetivo=o,
                         recomendacion="Usa un correo que NO exista. Para desbloquear la cuenta afectada: esperar el "
                         "tiempo de bloqueo (en payroll, 15 min) o limpiar locked_until/failed_login_attempts de ese usuario.")
        elif tipo_bloqueo == "rate_limit":
            resultado = f"Bloqueó por IP (429) en el intento {bloqueado_en}"
            res.hallazgo("info", f"{cx['nombre']}: protección activa (límite por IP)",
                         f"El login empezó a responder 429 (demasiados intentos) en el intento {bloqueado_en}. El "
                         "límite de intentos por IP funciona; la fuerza bruta queda frenada.", objetivo=o,
                         recomendacion="Sin acción. El bloqueo del probe se levanta solo cuando expira la ventana (en "
                         "payroll, 5 min).")
        elif tipo_bloqueo == "red":
            resultado = f"Sin respuesta de red desde el intento {bloqueado_en}"
            res.hallazgo("baja", f"{cx['nombre']}: posible bloqueo de red (fail2ban)",
                         f"Los intentos dejaron de recibir respuesta en el {bloqueado_en}. Puede ser un bloqueo por IP "
                         "a nivel de red (fail2ban). La protección actúa, pero la IP del probe puede quedar bloqueada.",
                         objetivo=o, recomendacion="Si el probe pierde acceso a otros servicios, desbloquear en el host: "
                         "fail2ban-client unban <ip-del-probe>.")
        elif dominante in (401, 403):
            resultado = f"{enviados} intentos sin bloqueo (todas {dominante})"
            res.hallazgo("alta", f"{cx['nombre']}: sin límite de intentos de login",
                         f"Se enviaron {enviados} intentos de login seguidos y todos respondieron {dominante}, sin "
                         "ningún bloqueo (429) ni demora. El endpoint permite fuerza bruta de contraseñas.", objetivo=o,
                         recomendacion="Agregar límite de intentos por IP (p. ej. 10/5 min → 429) y bloqueo de cuenta "
                         "tras varios fallos. Idealmente también fail2ban sobre el log de login.")
        elif dominante == 400:
            resultado = "Respondió 400 (¿Host inválido?)"
            res.hallazgo("info", f"{cx['nombre']}: no se alcanzó el login (400)",
                         "El servidor respondió 400, probablemente porque valida el encabezado Host. Indica el Host "
                         "correcto en los parámetros (p. ej. app.automatizaml.cl).", objetivo=o)
        elif dominante in (404, 405):
            resultado = f"La ruta no es un login ({dominante})"
            res.hallazgo("info", f"{cx['nombre']}: ruta de login incorrecta",
                         f"GET/POST a {ruta} devolvió {dominante}. Ajusta la ruta del login en los parámetros.", objetivo=o)
        elif dominante == 422:
            resultado = "Respondió 422 (formato/campos)"
            res.hallazgo("info", f"{cx['nombre']}: el login rechazó el formato (422)",
                         "Revisa el formato del cuerpo (json/form) y los nombres de los campos de usuario y contraseña.",
                         objetivo=o)
        else:
            resultado = f"Respuestas: {sorted(set(codigos))}"
            res.hallazgo("info", f"{cx['nombre']}: resultado no concluyente",
                         f"Códigos recibidos: {codigos}. Revisa la configuración de la prueba.", objetivo=o)

        filas.append([cx["nombre"], o, enviados, resultado, codigos[-1] if codigos else "—"])

    res.metrica("Conexiones probadas", len(filas))
    res.metrica("Intentos máx. por login", intentos)
    res.metrica("Correo objetivo", email)
    res.tabla("Resultado por login", ["Conexión", "Host", "Intentos", "Resultado", "Último código"], filas)
    res.nota(f"Se enviaron hasta {intentos} intentos de login con el correo «{email}» (que debe NO existir) y una "
             "contraseña incorrecta aleatoria. No se envían correos ni se tocan cuentas reales. La prueba se detiene "
             "en cuanto aparece un bloqueo (429/423) o se pierde la conexión.")
    res.nota("El límite por IP bloquea temporalmente la IP del probe para ese login (no a usuarios reales) y se levanta "
             "solo al expirar la ventana.")
    sin_limite = sum(1 for h in res.hallazgos if "sin límite" in h["titulo"])
    res.resumen = (f"{len(filas)} login(s) probados; "
                   + (f"{sin_limite} SIN límite de intentos." if sin_limite else "todos con protección o detenidos."))
    return res.final()


async def _post_login(c, ruta, formato, cuerpo):
    if formato == "form":
        return await c.post(ruta, data=cuerpo)
    return await c.post(ruta, json=cuerpo)


def _norm(texto: str, correos: list[str]) -> str:
    """Normaliza el cuerpo para comparar mensajes, sin que el correo propio cuente."""
    t = texto[:600]
    for e in correos:
        t = t.replace(e, "<correo>")
    t = re.sub(r"\d+", "#", t)
    return re.sub(r"\s+", " ", t).strip().lower()


async def enumeracion_usuarios(ctx: dict) -> dict:
    res = Resultado("enumeracion_usuarios")
    p = ctx.get("parametros") or {}
    existe = (p.get("email_existe") or "").strip()
    no_existe = (p.get("email_no_existe") or "").strip()
    if not existe or "@" not in existe:
        raise ErrorPrueba("Indica el correo de una cuenta que SÍ exista (idealmente de prueba/Demo).")
    if not no_existe or "@" not in no_existe:
        raise ErrorPrueba("Indica un correo que NO exista.")
    if existe.lower() == no_existe.lower():
        raise ErrorPrueba("Los dos correos deben ser distintos.")
    try:
        muestras = int(p.get("muestras") or 3)
    except (TypeError, ValueError):
        muestras = 3
    muestras = max(2, min(muestras, 4))  # bajo el umbral de bloqueo de cuenta (5)
    ruta = (p.get("ruta") or "/api/v1/auth/login").strip()
    formato = p.get("formato") or "json"
    cu = (p.get("campo_usuario") or "email").strip()
    cp = (p.get("campo_password") or "password").strip()
    host_header = (p.get("host_header") or "").strip()
    pw = "Enum-Prueba-" + secrets.token_hex(6)
    correos = [existe, no_existe]

    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in ("http", "https")]
    if not conexiones:
        raise ErrorPrueba("Asigna una conexión HTTP/HTTPS (el login objetivo) a esta prueba.")
    ifaces = interfaces()

    filas = []
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        ips = await resolver(cx["host"])
        if not ips or next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None):
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance o sin DNS", "", objetivo=o)
            continue

        datos = {e: {"estado": [], "ms": [], "cuerpo": []} for e in correos}
        abortado = None
        async with _cliente(cx, host_header) as c:
            # calentamiento (descarta la latencia de la primera conexión)
            try:
                await _post_login(c, ruta, formato, {cu: no_existe, cp: pw})
            except httpx.HTTPError:
                pass
            for _ in range(muestras):
                for e in correos:  # intercalado, para promediar la carga
                    try:
                        t0 = time.perf_counter()
                        r = await _post_login(c, ruta, formato, {cu: e, cp: pw})
                        dt = (time.perf_counter() - t0) * 1000
                    except httpx.HTTPError as ex:
                        abortado = f"sin respuesta de red ({type(ex).__name__})"
                        break
                    if r.status_code in (429, 423):
                        abortado = f"{'límite por IP (429)' if r.status_code == 429 else 'bloqueo de cuenta (423)'} en «{e}»"
                        break
                    datos[e]["estado"].append(r.status_code)
                    datos[e]["ms"].append(dt)
                    datos[e]["cuerpo"].append(_norm(r.text, correos))
                if abortado:
                    break

        if abortado:
            res.hallazgo("info", f"{cx['nombre']}: prueba incompleta", f"Se detuvo: {abortado}. Reintenta cuando "
                         "expire la ventana (en payroll, 5 min) o con menos muestras.", objetivo=o)
            if "423" in abortado:
                res.hallazgo("media", f"{cx['nombre']}: respuesta distinta para la cuenta existente (423)",
                             "Una cuenta se bloqueó (423) mientras la inexistente no: ese contraste ya revela que la "
                             "cuenta existe.", objetivo=o, recomendacion="Devolver el mismo código para ambos casos.")
            filas.append([cx["nombre"], "incompleta", "—", "—", "—"])
            continue

        est_e = Counter(datos[existe]["estado"]).most_common(1)[0][0]
        est_n = Counter(datos[no_existe]["estado"]).most_common(1)[0][0]
        cuerpo_e = Counter(datos[existe]["cuerpo"]).most_common(1)[0][0]
        cuerpo_n = Counter(datos[no_existe]["cuerpo"]).most_common(1)[0][0]
        med_e = round(statistics.median(datos[existe]["ms"]), 1)
        med_n = round(statistics.median(datos[no_existe]["ms"]), 1)
        filas.append([cx["nombre"], f"{est_e} vs {est_n}",
                      "iguales" if cuerpo_e == cuerpo_n else "DISTINTOS",
                      f"{med_e} ms", f"{med_n} ms"])

        señales = []
        if est_e != est_n:
            señales.append("código")
            res.hallazgo("alta", f"{cx['nombre']}: el código de respuesta revela si la cuenta existe",
                         f"La cuenta existente devuelve {est_e} y la inexistente {est_n}. Con una sola petición se "
                         "puede saber qué correos están registrados.", objetivo=o,
                         recomendacion="Devolver exactamente el mismo código (401) en ambos casos.")
        if cuerpo_e != cuerpo_n:
            señales.append("mensaje")
            res.hallazgo("alta", f"{cx['nombre']}: el mensaje de error revela si la cuenta existe",
                         f"La respuesta difiere entre un correo registrado y uno que no.\nExistente: «{cuerpo_e[:160]}»\n"
                         f"Inexistente: «{cuerpo_n[:160]}»", objetivo=o,
                         recomendacion="Usar un mensaje idéntico (p. ej. «correo o contraseña incorrectos») para ambos.")
        # Fuga por tiempo (p. ej. bcrypt solo cuando la cuenta existe)
        if med_n > 0 and med_e > med_n * 2.5 and (med_e - med_n) > 30:
            señales.append("tiempo")
            res.hallazgo("media", f"{cx['nombre']}: el tiempo de respuesta revela si la cuenta existe",
                         f"La cuenta existente tarda {med_e} ms y la inexistente {med_n} ms (más de 2,5×). Suele pasar "
                         "cuando el hash de contraseña solo se calcula si la cuenta existe; permite enumerar por tiempo.",
                         objetivo=o, recomendacion="Calcular siempre el hash (comparar contra un hash ficticio para las "
                         "cuentas inexistentes) para igualar los tiempos.")

        if not señales:
            res.hallazgo("info", f"{cx['nombre']}: sin enumeración detectable",
                         f"Mismo código ({est_e}), mismo mensaje y tiempos similares ({med_e} vs {med_n} ms). Si estás "
                         f"seguro de que «{existe}» existe, el login no distingue; si no, verifica que ese correo exista.",
                         objetivo=o)

    res.metrica("Conexiones probadas", len(filas))
    res.metrica("Muestras por correo", muestras)
    res.metrica("Señales de fuga", sum(1 for h in res.hallazgos if h["severidad"] in ("alta", "media")))
    res.tabla("Comparación existente vs inexistente", ["Conexión", "Código (ex/no)", "Mensaje", "Tiempo existe", "Tiempo no existe"], filas)
    res.nota(f"Se enviaron {muestras} intentos por correo (bajo el umbral de bloqueo), con contraseña incorrecta y "
             "comparando código, mensaje y tiempo. La cuenta existente recibe esos intentos fallidos: si corres la "
             "prueba varias veces sin que esa cuenta inicie sesión, podría bloquearse. Usa una cuenta de prueba.")
    res.resumen = (f"{len(filas)} login(s); "
                   + (f"{sum(1 for h in res.hallazgos if h['severidad'] in ('alta', 'media'))} con fuga de enumeración."
                      if any(h["severidad"] in ("alta", "media") for h in res.hallazgos) else "sin enumeración detectable."))
    return res.final()


# ── Tokens y JWT ────────────────────────────────────────────────────────────

def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_enc(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _craft(header: dict, payload: dict, sig: str = "") -> str:
    return f"{_b64url_enc(header)}.{_b64url_enc(payload)}.{sig}"


_CLAIMS_SENSIBLES = re.compile(r"(password|passwd|pwd|secret|clave|private|api[_-]?key)", re.I)


async def _enviar_token(c, endpoint, token, envio, nombre_cookie):
    headers = {"Cookie": f"{nombre_cookie}={token}"} if envio == "cookie" else {"Authorization": f"Bearer {token}"}
    try:
        r = await c.get(endpoint, headers=headers)
        return r.status_code
    except httpx.HTTPError as e:
        return f"error:{type(e).__name__}"


def _exito(status) -> bool:
    return isinstance(status, int) and status not in (401, 403, 419, 440)


async def tokens_jwt(ctx: dict) -> dict:
    res = Resultado("tokens_jwt")
    p = ctx.get("parametros") or {}
    token = (p.get("token") or "").strip()
    if not token or token.count(".") < 1:
        raise ErrorPrueba("Pega un JWT (tres partes separadas por puntos) de tu sesión.")
    endpoint = (p.get("endpoint") or "").strip()
    envio = p.get("envio") or "cookie"
    nombre_cookie = (p.get("nombre_cookie") or "access_token").strip()
    host_header = (p.get("host_header") or "").strip()

    # ── 1. Análisis local (sin enviar nada) ──
    try:
        partes = token.split(".")
        header = json.loads(_b64url_dec(partes[0]))
        payload = json.loads(_b64url_dec(partes[1]))
    except Exception as e:
        raise ErrorPrueba(f"No se pudo decodificar el JWT: {e}")

    alg = str(header.get("alg", "")).strip()
    res.metrica("Algoritmo (alg)", alg or "—")
    res.metrica("Claims", ", ".join(payload)[:60] or "—")

    if alg.lower() == "none":
        res.hallazgo("alta", "El token declara alg=none (sin firma)",
                     "El propio token dice no estar firmado. Si el servidor lo acepta, cualquiera forja sesiones.",
                     objetivo="header.alg", recomendacion="Rechazar alg=none y fijar el algoritmo esperado al validar.")
    elif not alg:
        res.hallazgo("media", "El token no declara algoritmo", "Falta el campo alg en el encabezado.", objetivo="header.alg")

    ahora = int(datetime.now(timezone.utc).timestamp())
    exp, iat = payload.get("exp"), payload.get("iat")
    if exp is None:
        res.hallazgo("alta", "El token no expira (sin claim exp)",
                     "Sin fecha de expiración, un token robado sirve para siempre.", objetivo="payload.exp",
                     recomendacion="Incluir exp y mantener vida corta en los tokens de acceso.")
    else:
        vida = (exp - iat) if isinstance(iat, (int, float)) else (exp - ahora)
        horas = round(vida / 3600, 1)
        res.metrica("Vida del token", f"{horas} h")
        if exp < ahora:
            res.hallazgo("info", "El token ya expiró", f"Venció hace {round((ahora - exp)/3600,1)} h. Útil para "
                         "probar si el servidor rechaza tokens vencidos.", objetivo="payload.exp")
        elif vida > 24 * 3600:
            res.hallazgo("media", f"Vida muy larga para un token de acceso ({horas} h)",
                         "Los tokens de acceso deberían durar minutos; cuanto más viven, más peligroso es que se filtren.",
                         objetivo="payload.exp", recomendacion="Acortar la vida del token de acceso (usar refresh tokens).")

    sens = [k for k in payload if _CLAIMS_SENSIBLES.search(str(k))]
    if sens:
        res.hallazgo("media", "El token lleva datos sensibles en el payload",
                     f"Claims {sens}: el payload de un JWT va en base64, no cifrado; cualquiera que lo vea lo lee.",
                     objetivo="payload", recomendacion="No poner secretos ni contraseñas en el token.")

    res.tabla("Contenido del token", ["Parte", "Campo", "Valor"],
              [["header", k, str(v)] for k, v in header.items()]
              + [["payload", k, (datetime.fromtimestamp(v, timezone.utc).isoformat() if k in ("exp", "iat", "nbf")
                                 and isinstance(v, (int, float)) else str(v)[:80])] for k, v in payload.items()])

    # ── 2. Pruebas activas (solo si se indicó un endpoint protegido) ──
    if not endpoint:
        res.nota("Solo se hizo análisis local. Para probar si el servidor verifica la firma (alg=none, firma alterada, "
                 "etc.), indica un endpoint protegido y cómo viaja el token.")
        res.resumen = f"Análisis local del token; {sum(1 for h in res.hallazgos if h['severidad'] in ('alta','media'))} hallazgos."
        return res.final()

    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in ("http", "https")]
    if not conexiones:
        raise ErrorPrueba("Asigna la conexión del servicio a esta prueba (para las pruebas activas).")
    ifaces = interfaces()

    # Variantes forjadas del token
    hdr_none = {**header, "alg": "none"}
    payload_priv = {**payload, "role": "superadmin", "rol": "superadmin", "is_admin": True}
    sig_orig = partes[2] if len(partes) > 2 else ""
    sig_alterada = (sig_orig[:-4] + "AAAA") if len(sig_orig) > 4 else "AAAA"
    forjados = [
        ("alg=none + firma vacía", _craft(hdr_none, payload, "")),
        ("alg=none + privilegios elevados", _craft(hdr_none, payload_priv, "")),
        ("firma alterada", f"{partes[0]}.{partes[1]}.{sig_alterada}"),
        ("sin tercer segmento", f"{partes[0]}.{partes[1]}"),
        ("payload alterado, misma firma", f"{partes[0]}.{_b64url_enc(payload_priv)}.{sig_orig}"),
    ]

    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        ips = await resolver(cx["host"])
        if not ips or next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None):
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance o sin DNS", "", objetivo=o)
            continue
        filas = []
        async with _cliente(cx, host_header) as c:
            base = await _enviar_token(c, endpoint, token, envio, nombre_cookie)
            filas.append(["token real (base)", str(base), "sí" if _exito(base) else "no"])
            if not _exito(base):
                res.hallazgo("info", f"{cx['nombre']}: el token real no fue aceptado (base {base})",
                             f"GET {endpoint} con tu token dio {base}. Revisa el token (¿vigente?), el endpoint, el "
                             "envío (cookie/bearer) o el Host. Sin una base que funcione no se pueden probar los falsos.",
                             objetivo=o)
                res.tabla(f"Pruebas en {cx['nombre']}", ["Token enviado", "Código", "Aceptado"], filas)
                continue
            aceptados = []
            for nombre, tok in forjados:
                st = await _enviar_token(c, endpoint, tok, envio, nombre_cookie)
                ok = _exito(st)
                filas.append([nombre, str(st), "SÍ" if ok else "no"])
                if ok:
                    aceptados.append(nombre)
        for nombre in aceptados:
            res.hallazgo("alta", f"{cx['nombre']}: acepta un token falso («{nombre}»)",
                         f"El servidor respondió como autenticado a un token {nombre}, igual que al token real. No está "
                         "verificando la firma: cualquiera puede forjar una sesión o elevar privilegios.", objetivo=o,
                         recomendacion="Validar siempre la firma con el algoritmo esperado (no aceptar alg=none ni cambios "
                         "de algoritmo) y rechazar tokens sin firma válida.")
        if not aceptados:
            res.hallazgo("info", f"{cx['nombre']}: rechazó todos los tokens manipulados",
                         "El servidor verifica la firma correctamente (alg=none, firma alterada y payload alterado "
                         "fueron rechazados).", objetivo=o)
        res.tabla(f"Pruebas en {cx['nombre']}", ["Token enviado", "Código", "Aceptado"], filas)

    criticos = sum(1 for h in res.hallazgos if h["severidad"] == "alta")
    res.resumen = (f"{criticos} problema(s) crítico(s) de JWT." if criticos else "El token y la verificación de firma se ven correctos.")
    return res.final()


# ── MFA y su evasión ────────────────────────────────────────────────────────

def _cookie_valor(set_cookies: list[str], nombre: str) -> str | None:
    """Valor de una cookie recién fijada (no una borrada con Max-Age=0)."""
    for sc in set_cookies:
        if sc.split("=", 1)[0].strip() == nombre:
            valor = sc.split("=", 1)[1].split(";", 1)[0].strip()
            borrada = "max-age=0" in sc.lower() or 'expires=thu, 01 jan 1970' in sc.lower()
            if valor and len(valor) > 4 and not borrada:
                return valor
    return None


async def mfa(ctx: dict) -> dict:
    res = Resultado("mfa")
    p = ctx.get("parametros") or {}
    email = (p.get("email") or "").strip()
    password = p.get("password") or ""
    if not email or not password:
        raise ErrorPrueba("Indica el correo y la contraseña de una cuenta de prueba que tenga MFA activo.")
    endpoint = (p.get("endpoint") or "/api/v1/auth/me").strip()
    ruta_login = (p.get("ruta_login") or "/api/v1/auth/login").strip()
    campo_req = (p.get("campo_mfa_requerido") or "mfa_requerido").strip()
    campo_tok = (p.get("campo_mfa_token") or "mfa_token").strip()
    envio = p.get("envio") or "cookie"
    nombre_cookie = (p.get("nombre_cookie") or "access_token").strip()
    host_header = (p.get("host_header") or "").strip()

    conexiones = [c for c in (ctx.get("conexiones") or []) if c["protocolo"] in ("http", "https")]
    if not conexiones:
        raise ErrorPrueba("Asigna la conexión del servicio a esta prueba.")
    ifaces = interfaces()

    probados = 0
    for cx in conexiones:
        o = f"{cx['host']}:{cx['puerto']}"
        ips = await resolver(cx["host"])
        if not ips or next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None):
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance o sin DNS", "", objetivo=o)
            continue
        filas = []
        async with _cliente(cx, host_header) as c:
            try:
                rl = await c.post(ruta_login, json={"email": email, "password": password})
            except httpx.HTTPError as e:
                res.hallazgo("info", f"{cx['nombre']}: sin respuesta al login", type(e).__name__, objetivo=o)
                continue
            if rl.status_code != 200:
                res.hallazgo("info", f"{cx['nombre']}: no se pudo iniciar sesión (status {rl.status_code})",
                             "Revisa el correo/contraseña, la ruta del login y el Host. Se necesita pasar el primer "
                             "paso (contraseña) para probar el segundo factor.", objetivo=o)
                continue
            try:
                cuerpo = rl.json()
            except ValueError:
                cuerpo = {}
            mfa_req = bool(cuerpo.get(campo_req))
            cookie_login = _cookie_valor(rl.headers.get_list("set-cookie"), nombre_cookie)
            mfa_token = cuerpo.get(campo_tok)

            if not mfa_req:
                res.hallazgo("info", f"{cx['nombre']}: la cuenta no pidió segundo factor",
                             f"El login respondió 200 sin «{campo_req}». La cuenta no tiene MFA activo (o el login no "
                             "lo exige), así que no se puede probar la evasión. Activa MFA en la cuenta de prueba.",
                             objetivo=o)
                filas.append(["login con contraseña", str(rl.status_code), "MFA no requerido"])
                res.tabla(f"Pasos en {cx['nombre']}", ["Paso", "Código", "Resultado"], filas)
                continue

            filas.append(["login con contraseña", str(rl.status_code), f"{campo_req}=true (pide segundo factor)"])
            probados += 1

            # A) ¿El login ya entregó una cookie de sesión antes del MFA?
            if cookie_login:
                res.hallazgo("alta", f"{cx['nombre']}: el login entrega sesión antes del segundo factor",
                             f"La respuesta al paso de contraseña ya fijó la cookie «{nombre_cookie}», pese a exigir MFA. "
                             "La sesión queda abierta sin el segundo factor.", objetivo=o,
                             recomendacion="No emitir cookies de sesión hasta validar el segundo factor.")

            # A2) ¿Las cookies que dejó el login dan acceso al endpoint protegido?
            try:
                r_a2 = await c.get(endpoint)
                acceso_cookies = _exito(r_a2.status_code)
                filas.append(["usar cookies del paso 1 en el endpoint", str(r_a2.status_code),
                              "ACCESO" if acceso_cookies else "sin acceso"])
                if acceso_cookies:
                    res.hallazgo("alta", f"{cx['nombre']}: se accede al endpoint con solo la contraseña",
                                 f"Tras el paso de contraseña (con MFA pendiente), GET {endpoint} respondió "
                                 f"{r_a2.status_code}: se entra sin el segundo factor.", objetivo=o,
                                 recomendacion="Exigir el segundo factor antes de autorizar cualquier endpoint protegido.")
            except httpx.HTTPError:
                pass

        # B) El token intermedio de MFA, ¿sirve como token de sesión? (cliente limpio)
        if mfa_token:
            async with _cliente(cx, host_header) as c2:
                st_b = await _enviar_token(c2, endpoint, mfa_token, envio, nombre_cookie)
            filas.append(["token intermedio de MFA como sesión", str(st_b),
                          "ACCESO" if _exito(st_b) else "rechazado"])
            if _exito(st_b):
                res.hallazgo("alta", f"{cx['nombre']}: el token intermedio de MFA abre sesión",
                             f"El token que entrega el paso 1 (antes del segundo factor) fue aceptado en {endpoint} "
                             f"({st_b}): sirve como sesión y salta el MFA.", objetivo=o,
                             recomendacion="El token intermedio debe servir SOLO para canjear el código; marcarlo con "
                             "un tipo distinto y rechazarlo en los endpoints protegidos.")
        else:
            res.nota(f"{cx['nombre']}: el login no devolvió «{campo_tok}» en el cuerpo; no se probó el token intermedio "
                     "(revisa el nombre del campo si la app usa otro).")

        # C) Línea base: el endpoint sin ningún token debe dar 401/403
        async with _cliente(cx, host_header) as c3:
            try:
                st_c = (await c3.get(endpoint)).status_code
                filas.append(["endpoint sin token (control)", str(st_c), "protegido" if not _exito(st_c) else "ABIERTO"])
                if _exito(st_c):
                    res.hallazgo("media", f"{cx['nombre']}: el endpoint de control no exige sesión",
                                 f"GET {endpoint} sin ningún token respondió {st_c}. El endpoint elegido no está "
                                 "protegido, así que las demás comprobaciones no son concluyentes; usa una ruta que exija sesión.",
                                 objetivo=o)
            except httpx.HTTPError:
                pass

        if not any(h["severidad"] == "alta" and cx["nombre"] in h["titulo"] for h in res.hallazgos):
            res.hallazgo("info", f"{cx['nombre']}: el segundo factor no se pudo evadir",
                         "El login no entregó sesión antes del MFA, el token intermedio no sirve como sesión y el "
                         "endpoint protegido exige el segundo factor.", objetivo=o)
        res.tabla(f"Pasos en {cx['nombre']}", ["Paso", "Código", "Resultado"], filas)

    criticos = sum(1 for h in res.hallazgos if h["severidad"] == "alta")
    res.nota("Solo se prueba la EVASIÓN del segundo factor (saltárselo). No se envían códigos MFA al azar: la fuerza "
             "bruta del código y la reutilización necesitan el secreto TOTP y no se cubren aquí. El paso de contraseña "
             "se hace una vez (no acumula intentos fallidos).")
    if criticos:
        res.resumen = f"{criticos} forma(s) de evadir el MFA."
    elif probados:
        res.resumen = "No se encontró forma de evadir el segundo factor."
    else:
        res.resumen = "No se pudo probar: revisa las credenciales y que la cuenta tenga MFA activo."
    return res.final()


PRUEBAS_ATAQUES = {"fuerza_bruta": fuerza_bruta, "enumeracion_usuarios": enumeracion_usuarios,
                   "tokens_jwt": tokens_jwt, "mfa": mfa}
