"""
Pruebas de plataforma: la recolección la hace el host (scripts/plataforma.sh) y
aquí solo se analiza. Así ningún contenedor necesita docker.sock.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from comun import CLASES_CRITICAS, NOMBRE_CLASE, ErrorPrueba, Resultado, servicio

DIAS_VIGENCIA = 7


def _leer(ruta: Path, comando: str) -> dict:
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ErrorPrueba(f"No hay datos recolectados. Ejecuta en el host: {comando}")
    except json.JSONDecodeError:
        raise ErrorPrueba(f"{ruta.name} está corrupto. Vuelve a ejecutar: {comando}")


def _antiguedad_dias(iso: str) -> float:
    t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - t).total_seconds() / 86400


def _criticos_por_nombre(inv: dict) -> dict[str, list[str]]:
    """contenedor → clases críticas que expone (según puertos declarados)."""
    salida = {}
    for r in (inv.get("redes") or {}).values():
        for c in r["contenedores"]:
            clases = sorted({servicio(int(p))[1] for p in c["puertos"] if str(p).isdigit()} & CLASES_CRITICAS)
            if clases:
                salida[c["nombre"]] = clases
    return salida


def egress(data_dir: Path, inv: dict) -> dict:
    comando = "./scripts/plataforma.sh egress"
    datos = _leer(data_dir / "plataforma" / "egress.json", comando)
    res = Resultado("egress")
    criticos = _criticos_por_nombre(inv)
    sino = lambda r, k: "sí" if (r.get(k) or {}).get("ok") else "no"

    filas, con_salida, smtp_sub, sin_uso = [], [], [], []
    for red, d in sorted(datos["redes"].items()):
        r = d.get("resultados") or {}
        internet = any((r.get(k) or {}).get("ok") for k in ("https", "http", "dns_externo_tcp"))
        cs = d.get("contenedores") or []
        filas.append([red, "sí" if d.get("interna") else "no", len(cs), sino(r, "dns"), sino(r, "https"),
                      sino(r, "http"), sino(r, "dns_externo_tcp"), sino(r, "smtp_25"),
                      sino(r, "smtp_465"), sino(r, "smtp_587")])
        if "error" in r:
            res.hallazgo("info", f"No se pudo medir {red}", r["error"].get("detalle", ""), objetivo=red)
            continue
        if not cs:
            sin_uso.append(red)
        if internet:
            con_salida.append(red)
        sensibles = [f"{c} ({', '.join(NOMBRE_CLASE[k] for k in criticos[c])})" for c in cs if c in criticos]
        if internet and sensibles:
            res.hallazgo("media", f"{red}: datos sensibles con salida a Internet",
                         f"La red tiene salida libre y contiene {', '.join(sensibles)}. Un contenedor comprometido "
                         "aquí puede enviar datos hacia afuera sin restricción.",
                         objetivo=red,
                         recomendacion="Separar las bases/cachés en una red `internal: true` y dejar con salida solo "
                                       "los contenedores que la necesitan (backend, worker).")
        if (r.get("smtp_25") or {}).get("ok"):
            res.hallazgo("alta", f"{red}: SMTP puerto 25 abierto hacia Internet",
                         "Desde esta red se puede entregar correo directo a cualquier servidor: es la vía típica de "
                         "envío de spam desde un contenedor comprometido.", objetivo=red,
                         recomendacion="Bloquear 25/tcp saliente en DOCKER-USER (la regla de UFW solo cubre al host).")
        if (r.get("smtp_587") or {}).get("ok") or (r.get("smtp_465") or {}).get("ok"):
            smtp_sub.append(red)

    if smtp_sub:
        res.hallazgo("baja", f"Envío de correo autenticado (465/587) permitido desde {len(smtp_sub)} redes",
                     f"Redes: {', '.join(smtp_sub)}. Solo payroll, n8n y prospección envían correo; en las demás no "
                     "hace falta. Requiere credenciales, pero con una clave filtrada permite enviar spam.",
                     objetivo="587/465 saliente",
                     recomendacion="Limitar 465/587 en DOCKER-USER a las subredes que envían correo.")
    for red in sin_uso:
        res.hallazgo("info", f"Red sin contenedores: {red}", "No tiene contenedores conectados.",
                     objetivo=red, recomendacion="Eliminarla si quedó de una instalación anterior (docker network rm).")

    edad = _antiguedad_dias(datos["generado"])
    if edad > DIAS_VIGENCIA:
        res.nota(f"Los datos tienen {edad:.0f} días. Conviene volver a ejecutar: {comando}")
    res.nota(f"Datos recolectados el {datos['generado']} con {comando}: un contenedor temporal por red abre "
             "conexiones TCP a 1.1.1.1 (80/443), 8.8.8.8:53 y smtp.gmail.com (25/465/587).")
    res.nota("En este servidor DOCKER-USER devuelve (RETURN) todo el tráfico de 172.16.0.0/12: no hay filtro de "
             "salida para contenedores; la regla «deny out 25» de UFW aplica solo al propio host.")

    res.metrica("Redes medidas", len(datos["redes"]))
    res.metrica("Con salida a Internet", len(con_salida))
    res.metrica("Sin salida", len(datos["redes"]) - len(con_salida))
    res.metrica("Permiten SMTP 465/587", len(smtp_sub))
    res.tabla("Salida por red", ["Red", "Interna", "Contenedores", "DNS ext.", "HTTPS", "HTTP", "DNS TCP",
                                 "SMTP 25", "SMTPS 465", "SMTP 587"], filas)
    res.resumen = (f"{len(con_salida)} de {len(datos['redes'])} redes con salida libre a Internet; "
                   f"SMTP 587/465 abierto en {len(smtp_sub)}.")
    return res.final()


PRUEBAS_WEB = {"egress": egress}
