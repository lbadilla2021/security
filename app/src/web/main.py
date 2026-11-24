"""
web — página de configuración de conexiones para pruebas de seguridad.

Sin usuarios: la protección es de red (solo 127.0.0.1 del host, por túnel SSH).
Aun así, como es una página sin login abierta en el navegador del operador,
se defiende de ataques desde OTRAS pestañas:
  · DNS rebinding  → solo acepta Host = localhost / 127.0.0.1 / [::1].
  · CSRF           → toda escritura exige la cabecera X-Security-UI (un
                     formulario o fetch de otro sitio no puede enviarla sin
                     un preflight CORS, y aquí no hay CORS) y un Origin local.
  · Inyección/XSS  → CSP estricta sin inline; el front usa textContent.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

from comun import HOST_RE, ErrorPrueba, Protocolo, servicio
from web.catalogo import GRUPOS, IDS_TIPOS, NIVELES, TIPOS
from web.plataforma import PRUEBAS_WEB

DATA = Path(os.environ.get("DATA_DIR", "/data"))
ARCH_CONEXIONES = DATA / "conexiones.json"
ARCH_INVENTARIO = DATA / "inventario.json"
DIR_RESULTADOS = DATA / "resultados"
MAX_RESULTADOS = 20
SOCK_PROBE = os.environ.get("PROBE_SOCK", "/run/probe/probe.sock")
ESTATICOS = Path(__file__).parent / "static"

HOSTS_LOCALES = {"localhost", "127.0.0.1", "[::1]", "::1"}
MAX_CUERPO = 64 * 1024

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")


def _host_local(valor: str | None) -> bool:
    if not valor:
        return False
    nombre = urlsplit("//" + valor).hostname or ""
    return nombre.lower() in HOSTS_LOCALES or f"[{nombre}]" in HOSTS_LOCALES


@app.middleware("http")
async def guardia(request: Request, call_next):
    if not _host_local(request.headers.get("host")):
        return PlainTextResponse("Host no permitido", status_code=421)
    if request.method not in ("GET", "HEAD"):
        origen = request.headers.get("origin")
        if origen and not _host_local(urlsplit(origen).netloc):
            return PlainTextResponse("Origen no permitido", status_code=403)
        if request.headers.get("x-security-ui") != "1":
            return PlainTextResponse("Falta cabecera X-Security-UI", status_code=403)
        if int(request.headers.get("content-length") or 0) > MAX_CUERPO:
            return PlainTextResponse("Cuerpo demasiado grande", status_code=413)
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ── Persistencia (JSON en /data, escritura atómica) ─────────────────────────

_cerrojo = threading.Lock()


def _leer_json(ruta: Path, defecto):
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return defecto
    except json.JSONDecodeError:
        raise HTTPException(500, f"{ruta.name} está corrupto")


def _guardar_conexiones(lista: list[dict]) -> None:
    tmp = ARCH_CONEXIONES.with_suffix(".tmp")
    tmp.write_text(json.dumps(lista, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, ARCH_CONEXIONES)


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Probe (socket Unix) ─────────────────────────────────────────────────────

async def _probe(metodo: str, ruta: str, cuerpo: dict | None = None, timeout: float = 15):
    transporte = httpx.AsyncHTTPTransport(uds=SOCK_PROBE)
    try:
        async with httpx.AsyncClient(transport=transporte, base_url="http://probe",
                                     timeout=timeout) as c:
            r = await c.request(metodo, ruta, json=cuerpo)
    except httpx.HTTPError as e:
        raise HTTPException(503, f"Probe no disponible: {e.__class__.__name__}")
    if r.status_code >= 400:
        try:
            detalle = r.json().get("detail")
        except ValueError:
            detalle = r.text
        raise HTTPException(r.status_code, detalle if isinstance(detalle, str) else "Datos inválidos")
    return r.json()


# ── Modelos ─────────────────────────────────────────────────────────────────

class ConexionIn(BaseModel):
    nombre: str = Field(min_length=1, max_length=80)
    red: str = Field("", max_length=64, pattern=r"^[A-Za-z0-9_.-]*$")
    host: str = Field(pattern=HOST_RE, max_length=253)
    puerto: int = Field(ge=1, le=65535)
    protocolo: Protocolo = "tcp"
    tipos: list[str] = Field(default_factory=list, max_length=len(TIPOS))
    notas: str = Field("", max_length=500)

    @field_validator("tipos")
    @classmethod
    def _tipos_validos(cls, v):
        desconocidos = set(v) - IDS_TIPOS
        if desconocidos:
            raise ValueError(f"tipos desconocidos: {sorted(desconocidos)}")
        return sorted(set(v))

    @model_validator(mode="after")
    def _tipos_aplicables(self):
        por_id = {t["id"]: t for t in TIPOS}
        malos = [i for i in self.tipos
                 if por_id[i]["objetivo"] != "conexion" or self.protocolo not in por_id[i]["protocolos"]]
        if malos:
            raise ValueError(f"tipos no aplicables a {self.protocolo}: {malos}")
        return self

    @field_validator("nombre", "notas")
    @classmethod
    def _sin_control(cls, v):
        return "".join(ch for ch in v if ch.isprintable() or ch == "\n").strip()


class PruebaIn(BaseModel):
    host: str = Field(pattern=HOST_RE, max_length=253)
    puerto: int = Field(ge=1, le=65535)
    protocolo: Protocolo = "tcp"


# ── Rutas ───────────────────────────────────────────────────────────────────

@app.get("/salud")
def salud():
    return {"ok": True}


@app.get("/api/estado")
async def estado():
    try:
        probe = await _probe("GET", "/estado")
    except HTTPException as e:
        return {"probe": None, "error": e.detail}
    inv = _leer_json(ARCH_INVENTARIO, {})
    por_subred = {r.get("subred"): nombre for nombre, r in inv.get("redes", {}).items()}
    for i in probe["interfaces"]:
        i["red"] = por_subred.get(i["subred"])
    return {"probe": probe, "inventario_generado": inv.get("generado")}


@app.get("/api/inventario")
def inventario():
    return _leer_json(ARCH_INVENTARIO, {"generado": None, "redes": {}})


@app.get("/api/tipos")
def tipos():
    return {"grupos": GRUPOS, "niveles": NIVELES}


@app.get("/api/conexiones")
def listar():
    return _leer_json(ARCH_CONEXIONES, [])


@app.post("/api/conexiones", status_code=201)
def crear(c: ConexionIn):
    with _cerrojo:
        lista = _leer_json(ARCH_CONEXIONES, [])
        if len(lista) >= 500:
            raise HTTPException(400, "Máximo 500 conexiones")
        nueva = {"id": uuid.uuid4().hex, **c.model_dump(), "creada": _ahora(),
                 "actualizada": _ahora(), "ultima_prueba": None}
        lista.append(nueva)
        _guardar_conexiones(lista)
    return nueva


@app.put("/api/conexiones/{cid}")
def actualizar(cid: str, c: ConexionIn):
    with _cerrojo:
        lista = _leer_json(ARCH_CONEXIONES, [])
        for item in lista:
            if item["id"] == cid:
                cambio_destino = (item["host"], item["puerto"], item["protocolo"]) != (c.host, c.puerto, c.protocolo)
                item.update(c.model_dump(), actualizada=_ahora())
                if cambio_destino:
                    item["ultima_prueba"] = None
                _guardar_conexiones(lista)
                return item
    raise HTTPException(404, "No existe")


@app.delete("/api/conexiones/{cid}", status_code=204)
def eliminar(cid: str):
    with _cerrojo:
        lista = _leer_json(ARCH_CONEXIONES, [])
        nueva = [i for i in lista if i["id"] != cid]
        if len(nueva) == len(lista):
            raise HTTPException(404, "No existe")
        _guardar_conexiones(nueva)


# ── Importación desde el inventario ─────────────────────────────────────────

# Pruebas que solo tienen sentido en un tipo de servicio concreto.
ESPECIFICAS = {
    "bases_datos": lambda proto, clase, p: proto == "postgres",
    "cache_colas": lambda proto, clase, p: proto == "redis",
    "almacenamiento": lambda proto, clase, p: proto == "minio",
    "vectoriales": lambda proto, clase, p: clase == "vectorial",
    "paneles_admin": lambda proto, clase, p: clase == "admin",
    "metricas_trazas": lambda proto, clase, p: clase == "metricas",
    "automatizacion": lambda proto, clase, p: p == 5678,
}


def _protocolo(s: dict) -> str:
    p, clase = s["puerto"], servicio(s["puerto"])[1]
    if p in (5432, 6432):
        return "postgres"
    if p == 6379:
        return "redis"
    if p == 9000 and "minio" in (s.get("server") or "").lower():
        return "minio"
    if s.get("http"):
        return "https" if s.get("tls") else "http"
    if p in (443, 8443, 9443):
        return "https"  # TLS sin SNI puede fallar (p. ej. NPM), pero el servicio es HTTPS
    return "tcp"


def tipos_sugeridos(protocolo: str, puerto: int) -> list[str]:
    """No intrusivas, compatibles con el protocolo, genéricas o específicas del servicio."""
    clase = servicio(puerto)[1]
    salida = []
    for t in TIPOS:
        if t["objetivo"] != "conexion" or t["intrusivo"] or protocolo not in t["protocolos"]:
            continue
        if next(g for g in GRUPOS if g["id"] == t["grupo"])["seccion"] != "generales":
            continue
        regla = ESPECIFICAS.get(t["id"])
        if regla and not regla(protocolo, clase, puerto):
            continue
        salida.append(t["id"])
    return sorted(salida)


@app.post("/api/conexiones/importar")
async def importar():
    if _en_curso.locked():
        raise HTTPException(409, "Hay una prueba en curso; espera a que termine")
    async with _en_curso:
        inv = _leer_json(ARCH_INVENTARIO, {})
        mapa = await _probe("POST", "/mapear", {"contexto": {"inventario": inv}}, timeout=300)
    creadas, existentes = [], 0
    with _cerrojo:
        lista = _leer_json(ARCH_CONEXIONES, [])
        ya = {(c["host"], c["puerto"]) for c in lista}
        for s in mapa["servicios"]:
            if (s["contenedor"], s["puerto"]) in ya:
                existentes += 1
                continue
            proto = _protocolo(s)
            nombre_srv = servicio(s["puerto"])[0]
            ident = s.get("server") or s.get("banner") or s.get("http") or ""
            c = ConexionIn(
                nombre=f"{s['contenedor']} · {nombre_srv}"[:80],
                red=s["red"], host=s["contenedor"], puerto=s["puerto"], protocolo=proto,
                tipos=tipos_sugeridos(proto, s["puerto"]),
                notas=(f"Importada del inventario ({inv.get('generado', '')[:10]})."
                       + ("" if s["declarado"] else " Puerto no declarado por la imagen.")
                       + (f" Se identifica como: {ident}" if ident else ""))[:500],
            )
            nueva = {"id": uuid.uuid4().hex, **c.model_dump(), "creada": _ahora(), "actualizada": _ahora(),
                     "ultima_prueba": {"fecha": _ahora(), "ok": True, "detalle": "Abierto al importar", "ms_tcp": None}}
            lista.append(nueva)
            creadas.append(nueva)
            ya.add((c.host, c.puerto))
        if len(lista) > 500:
            raise HTTPException(400, "Se superaría el máximo de 500 conexiones")
        _guardar_conexiones(lista)
    return {"creadas": len(creadas), "existentes": existentes, "contenedores": mapa["contenedores"],
            "puertos_probados": mapa["puertos_probados"], "conexiones": creadas}


@app.post("/api/probar")
async def probar(p: PruebaIn):
    return await _probe("POST", "/probar", p.model_dump())


@app.post("/api/conexiones/{cid}/probar")
async def probar_guardada(cid: str):
    lista = _leer_json(ARCH_CONEXIONES, [])
    item = next((i for i in lista if i["id"] == cid), None)
    if not item:
        raise HTTPException(404, "No existe")
    try:
        res = await _probe("POST", "/probar", {k: item[k] for k in ("host", "puerto", "protocolo")})
    except HTTPException as e:
        res = {"ok": False, "etapa": "alcance", "detalle": e.detail}
    with _cerrojo:
        lista = _leer_json(ARCH_CONEXIONES, [])
        for i in lista:
            if i["id"] == cid:
                i["ultima_prueba"] = {"fecha": _ahora(), "ok": res.get("ok"),
                                      "detalle": res.get("detalle"), "ms_tcp": res.get("ms_tcp")}
                _guardar_conexiones(lista)
    return res


# ── Ejecución de pruebas y resultados ───────────────────────────────────────

_en_curso = asyncio.Lock()
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
POR_ID = {t["id"]: t for t in TIPOS}


class EjecucionIn(BaseModel):
    parametros: dict = Field(default_factory=dict)
    confirmar: bool = False


def _tipo_o_404(tipo: str) -> dict:
    t = POR_ID.get(tipo)
    if not t:
        raise HTTPException(404, "Tipo de prueba desconocido")
    return t


def _dir_resultados(tipo: str) -> Path:
    d = DIR_RESULTADOS / tipo
    d.mkdir(parents=True, exist_ok=True)
    return d


def _guardar_resultado(tipo: str, r: dict) -> None:
    d = _dir_resultados(tipo)
    nombre = r["inicio"].replace(":", "").replace("+0000", "Z") + f"_{r['id']}.json"
    (d / nombre).write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
    for viejo in sorted(d.glob("*.json"))[:-MAX_RESULTADOS]:
        viejo.unlink(missing_ok=True)


def _resumen(r: dict) -> dict:
    return {k: r.get(k) for k in ("id", "tipo", "inicio", "duracion_s", "resumen", "conteo")}


@app.post("/api/pruebas/{tipo}/ejecutar")
async def ejecutar(tipo: str, e: EjecucionIn):
    t = _tipo_o_404(tipo)
    if not t["implementada"]:
        raise HTTPException(400, "Esta prueba aún no está implementada")
    if t["intrusivo"] and not e.confirmar:
        raise HTTPException(428, "Prueba intrusiva: requiere confirmación")
    if _en_curso.locked():
        raise HTTPException(409, "Ya hay una prueba en curso; espera a que termine")
    async with _en_curso:
        contexto = {
            "inventario": _leer_json(ARCH_INVENTARIO, {}),
            "conexiones": [c for c in _leer_json(ARCH_CONEXIONES, []) if tipo in c["tipos"]],
            "parametros": e.parametros,
        }
        if tipo in PRUEBAS_WEB:
            try:
                r = await asyncio.to_thread(PRUEBAS_WEB[tipo], DATA, contexto["inventario"])
            except ErrorPrueba as ex:
                raise HTTPException(400, str(ex))
        else:
            r = await _probe("POST", f"/ejecutar/{tipo}", {"contexto": contexto}, timeout=600)
    r["id"] = uuid.uuid4().hex
    _guardar_resultado(tipo, r)
    return r


@app.get("/api/pruebas/resumen")
def resumen_pruebas():
    """Último resultado de cada tipo (para el menú)."""
    salida = {}
    if DIR_RESULTADOS.exists():
        for d in DIR_RESULTADOS.iterdir():
            archivos = sorted(d.glob("*.json"))
            if d.name in POR_ID and archivos:
                salida[d.name] = _resumen(json.loads(archivos[-1].read_text(encoding="utf-8")))
    return salida


@app.get("/api/pruebas/{tipo}/resultados")
def listar_resultados(tipo: str):
    _tipo_o_404(tipo)
    d = DIR_RESULTADOS / tipo
    if not d.exists():
        return []
    return [_resumen(json.loads(a.read_text(encoding="utf-8"))) for a in sorted(d.glob("*.json"), reverse=True)]


@app.get("/api/pruebas/{tipo}/resultados/{rid}")
def ver_resultado(tipo: str, rid: str):
    _tipo_o_404(tipo)
    if not _ID_RE.match(rid):
        raise HTTPException(404, "No existe")
    d = DIR_RESULTADOS / tipo
    for a in d.glob(f"*_{rid}.json"):
        return json.loads(a.read_text(encoding="utf-8"))
    raise HTTPException(404, "No existe")


@app.exception_handler(HTTPException)
async def _error(_, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


app.mount("/static", StaticFiles(directory=ESTATICOS), name="static")


@app.get("/")
def portada():
    return FileResponse(ESTATICOS / "index.html")
