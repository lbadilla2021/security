"""
Pruebas de Red e infraestructura que corren dentro del probe.

Todas son de solo lectura: conexiones TCP, un HEAD / en servicios web y
consultas DNS. Ninguna envía credenciales ni modifica nada.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections import defaultdict

from comun import (CLASES_CRITICAS, CLASES_SENSIBLES, NOMBRE_CLASE, PUERTOS_COMUNES,
                   ErrorPrueba, Resultado, servicio)
from probe import escaner as E
from probe.red import interfaces, leer_arp, verificar_alcance


# ── Utilidades de contexto ──────────────────────────────────────────────────

def _inventario(ctx: dict) -> dict:
    inv = ctx.get("inventario") or {}
    if not inv.get("redes"):
        raise ErrorPrueba("No hay inventario. Ejecuta ./scripts/inventario.sh en el host.")
    return inv


def _red_de_iface(ifaces: list[dict], inv: dict) -> dict[str, str]:
    """subred → nombre de red Docker."""
    por_subred = {r.get("subred"): n for n, r in inv["redes"].items()}
    return {i["subred"]: por_subred.get(i["subred"], i["iface"]) for i in ifaces}


def _redes_expuestas(inv: dict) -> dict[str, list[str]]:
    """Redes con algún contenedor publicado a Internet → nombres de esos contenedores."""
    expuestas = defaultdict(list)
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            if c.get("publico"):
                expuestas[red].append(c["nombre"])
    return dict(expuestas)


def _fmt_servicio(p: int) -> str:
    nombre, clase = servicio(p)
    return f"{p} {nombre}"


# ── 1. Descubrimiento de hosts ──────────────────────────────────────────────

async def descubrimiento(ctx: dict) -> dict:
    res = Resultado("descubrimiento")
    inv = _inventario(ctx)
    ifaces = interfaces()
    nombres_red = _red_de_iface(ifaces, inv)
    hosts_por_red = max(16, min(int(ctx.get("parametros", {}).get("hosts_por_red", 254)), 1024))

    conocidos = {}
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            conocidos[c["ip"]] = (red, c["nombre"])

    ip_a_red: dict[str, str] = {}
    estados: dict = {}
    # Red por red: barrer todas a la vez desborda la tabla ARP del kernel
    # (gc_thresh3 = 1024 vecinos) y se pierden respuestas reales.
    for i in ifaces:
        red = ipaddress.IPv4Network(i["subred"])
        lote = []
        for k in range(2, min(hosts_por_red, red.num_addresses - 2) + 1):
            ip = str(red.network_address + k)
            if ip != i["ip"]:
                lote.append((ip, 80))
                ip_a_red[ip] = nombres_red[i["subred"]]
        estados.update(await E.escanear(lote, timeout=1.5, concurrencia=128))
    # Lo inventariado fuera del rango barrido también se sondea.
    for ip, (red, _) in conocidos.items():
        if ip not in ip_a_red and not verificar_alcance(ip, ifaces):
            ip_a_red[ip] = red
            estados.update(await E.escanear([(ip, 80)], timeout=1.5))

    vivos = {ip for (ip, _), est in estados.items() if est in (E.ABIERTO, E.CERRADO)}
    # Reintento pausado para inventariados sin respuesta.
    pendientes = [(ip, 80) for ip in conocidos if ip in ip_a_red and ip not in vivos]
    reintento = await E.escanear(pendientes, timeout=3.0, concurrencia=16) if pendientes else {}
    vivos |= {ip for (ip, _), est in reintento.items() if est in (E.ABIERTO, E.CERRADO)}
    arp = leer_arp()
    vivos |= {ip for ip in arp if ip in ip_a_red}
    objetivos = list(estados)

    inversos = dict(zip(sorted(vivos), await asyncio.gather(*(E.nombre_inverso(ip) for ip in sorted(vivos)))))

    filas, no_inventariados = [], []
    for ip in sorted(vivos, key=lambda x: (ip_a_red[x], ipaddress.IPv4Address(x))):
        inv_red, inv_nombre = conocidos.get(ip, (None, None))
        dns = inversos.get(ip)
        filas.append([ip_a_red[ip], ip, dns or "—", inv_nombre or "NO", "sí" if ip in arp else "—"])
        if not inv_nombre:
            no_inventariados.append((ip, dns))

    for ip, dns in no_inventariados:
        res.hallazgo("media", f"Host no inventariado: {ip}",
                     f"Responde en {ip_a_red[ip]}" + (f" con nombre DNS {dns}" if dns else " y no tiene nombre DNS") +
                     ", pero no aparece en el inventario de Docker.",
                     objetivo=ip,
                     recomendacion="Regenerar el inventario (./scripts/inventario.sh). Si sigue apareciendo, "
                                   "identificar qué es: puede ser un contenedor efímero o algo no autorizado.")

    caidos = [(ip, n) for ip, (r, n) in conocidos.items() if ip not in vivos]
    for ip, nombre in caidos:
        res.hallazgo("baja", f"Contenedor inventariado sin respuesta: {nombre}",
                     f"{ip} figura en el inventario pero no respondió.",
                     objetivo=nombre, recomendacion="Probablemente el inventario está desactualizado; regenerarlo.")

    res.metrica("Redes barridas", len(ifaces))
    res.metrica("Direcciones sondeadas", len(objetivos))
    res.metrica("Hosts activos", len(vivos))
    res.metrica("No inventariados", len(no_inventariados))
    res.tabla("Hosts activos", ["Red", "IP", "DNS inverso", "Inventario", "ARP"], filas)
    res.nota(f"Se barrieron las primeras {hosts_por_red} direcciones de cada subred (Docker asigna desde el inicio).")
    res.resumen = (f"{len(vivos)} hosts activos en {len(ifaces)} redes; "
                   f"{len(no_inventariados)} fuera del inventario.")
    return res.final()


# ── 2. Puertos y servicios (por conexión) ───────────────────────────────────

async def puertos(ctx: dict) -> dict:
    res = Resultado("puertos")
    conexiones = ctx.get("conexiones") or []
    if not conexiones:
        raise ErrorPrueba("Asigna al menos una conexión a esta prueba.")
    inv = ctx.get("inventario") or {"redes": {}}
    ifaces = interfaces()

    declarados_por_ip = defaultdict(set)
    for r in inv.get("redes", {}).values():
        for c in r["contenedores"]:
            declarados_por_ip[c["ip"]] |= {int(p) for p in c["puertos"] if str(p).isdigit()}

    # Un escaneo por host, aunque tenga varias conexiones asignadas.
    por_ip: dict[str, list[dict]] = defaultdict(list)
    for cx in conexiones:
        ips = await E.resolver(cx["host"])
        if not ips:
            res.hallazgo("media", f"{cx['nombre']}: el host no resuelve", f"{cx['host']} no tiene DNS.",
                         objetivo=cx["host"])
            continue
        motivo = next((m for ip in ips if (m := verificar_alcance(ip, ifaces))), None)
        if motivo:
            res.hallazgo("info", f"{cx['nombre']}: fuera de alcance", motivo, objetivo=cx["host"])
            continue
        por_ip[ips[0]].append(cx)

    filas, total_abiertos = [], 0
    for ip, cxs in sorted(por_ip.items(), key=lambda x: x[1][0]["host"]):
        host = cxs[0]["host"]
        configurados = {cx["puerto"] for cx in cxs}
        declarados = declarados_por_ip.get(ip, set())
        lista = sorted(set(PUERTOS_COMUNES) | declarados | configurados)
        estados = await E.escanear([(ip, p) for p in lista], timeout=1.0, concurrencia=100)
        abiertos = sorted(p for (_, p), est in estados.items() if est == E.ABIERTO)
        total_abiertos += len(abiertos)
        banners = dict(zip(abiertos, await asyncio.gather(*(E.banner(ip, p, host) for p in abiertos))))

        for cx in cxs:
            if estados[(ip, cx["puerto"])] != E.ABIERTO:
                res.hallazgo("media", f"{cx['nombre']}: el puerto configurado no responde",
                             f"{cx['host']}:{cx['puerto']} está {estados[(ip, cx['puerto'])]}.",
                             objetivo=f"{cx['host']}:{cx['puerto']}")

        for p in abiertos:
            nombre, clase = servicio(p)
            info = banners[p]
            declarado = p in declarados or p in configurados
            detalle_srv = info["server"] or info["banner"] or info["http"] or ""
            filas.append([host, ip, p, nombre, NOMBRE_CLASE[clase], "sí" if declarado else "NO", detalle_srv or "—"])
            objetivo = f"{host}:{p}"
            if clase == "docker":
                res.hallazgo("alta", f"API de orquestación abierta en {objetivo}",
                             f"{nombre} responde: quien llegue a este puerto controla los contenedores.",
                             objetivo=objetivo, recomendacion="Cerrar el puerto o protegerlo con TLS mutuo.")
            elif clase == "inseguro":
                res.hallazgo("media", f"Protocolo inseguro en {objetivo}", f"{nombre} transmite sin cifrar o "
                             "tiene historial de abusos.", objetivo=objetivo,
                             recomendacion="Deshabilitarlo si no se usa.")
            if not p in declarados:
                res.hallazgo("media", f"Puerto no declarado: {objetivo}",
                             f"{nombre} ({NOMBRE_CLASE[clase]}) escucha, pero la imagen no lo declara (EXPOSE). "
                             "Suele ser un servicio auxiliar olvidado o una consola de depuración.",
                             objetivo=objetivo, recomendacion="Confirmar si es necesario; si no, desactivarlo.")
            if (v := E.revela_version(info)):
                res.hallazgo("baja", f"Versión expuesta en {objetivo}", f"El servicio se identifica como «{v}».",
                             objetivo=objetivo,
                             recomendacion="Ocultar la versión (server_tokens off, ServerTokens Prod, etc.).")

    res.metrica("Conexiones", len(conexiones))
    res.metrica("Hosts escaneados", len(por_ip))
    res.metrica("Puertos probados por host", len(PUERTOS_COMUNES))
    res.metrica("Puertos abiertos", total_abiertos)
    res.tabla("Puertos abiertos", ["Host", "IP", "Puerto", "Servicio", "Clase", "Declarado", "Identificación"], filas)
    res.nota("Se prueban los puertos más comunes, los declarados por la imagen y el de la conexión. "
             "La identificación usa solo lo que el servicio anuncia (banner o un HEAD /).")
    res.resumen = f"{total_abiertos} puertos abiertos en {len(por_ip)} hosts ({len(conexiones)} conexiones)."
    return res.final()


# ── 3. Segmentación entre redes ─────────────────────────────────────────────

async def segmentacion(ctx: dict) -> dict:
    res = Resultado("segmentacion")
    inv = _inventario(ctx)
    ifaces = interfaces()
    expuestas = _redes_expuestas(inv)
    sensibles = sorted(p for p in PUERTOS_COMUNES if servicio(p)[1] in CLASES_CRITICAS | CLASES_SENSIBLES)

    objetivos, ubicacion = [], {}
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            if verificar_alcance(c["ip"], ifaces):
                continue
            puertos_c = sorted(set(sensibles) | {int(p) for p in c["puertos"] if str(p).isdigit()
                                                  and servicio(int(p))[1] in CLASES_CRITICAS | CLASES_SENSIBLES})
            for p in puertos_c:
                objetivos.append((c["ip"], p))
                ubicacion[(c["ip"], p)] = (red, c["nombre"])

    estados = await E.escanear(objetivos, timeout=1.0, concurrencia=200)
    alcanzables = [(ubicacion[k], k[1]) for k, est in estados.items() if est == E.ABIERTO]

    filas = []
    en_expuestas = defaultdict(list)  # (contenedor, puerto) → redes expuestas
    for (red, nombre), p in sorted(alcanzables):
        srv, clase = servicio(p)
        expuesta = red in expuestas
        filas.append([red, "SÍ" if expuesta else "no", nombre, f"{p} {srv}", NOMBRE_CLASE[clase]])
        if expuesta and clase in CLASES_CRITICAS | CLASES_SENSIBLES:
            en_expuestas[(nombre, p)].append(red)

    for (nombre, p), redes in sorted(en_expuestas.items()):
        srv, clase = servicio(p)
        frontera = sorted({c for r in redes for c in expuestas[r] if c != nombre})
        junto = f"junto a {', '.join(frontera)} (publicado a Internet)" if frontera else \
                "y es el propio contenedor publicado a Internet: cualquier vecino de la red llega a este puerto"
        objetivo = f"{nombre}:{p}"
        if clase in CLASES_CRITICAS:
            res.hallazgo("alta", f"{srv} de {nombre} alcanzable desde una red expuesta",
                         f"{objetivo} responde en {', '.join(redes)}, {junto}. Si un contenedor de esa red se "
                         f"compromete, llega directo a la {NOMBRE_CLASE[clase]}.", objetivo=objetivo,
                         recomendacion=f"Sacar {nombre} de {', '.join(redes)} y dejarlo solo en la red privada de su aplicación.")
        else:
            res.hallazgo("media", f"{srv} de {nombre} alcanzable desde una red expuesta",
                         f"{objetivo} ({NOMBRE_CLASE[clase]}) responde en {', '.join(redes)}, {junto}.",
                         objetivo=objetivo,
                         recomendacion="Si el proxy lo publica a propósito es esperado; si no, moverlo a una red "
                                       "privada o exigir autenticación fuerte.")

    # Contenedores puente (en varias redes)
    redes_por_c = defaultdict(list)
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            redes_por_c[c["nombre"]].append(red)
    puentes = {n: rs for n, rs in redes_por_c.items() if len(rs) > 1}
    for n, rs in sorted(puentes.items()):
        toca_expuesta = [r for r in rs if r in expuestas]
        if toca_expuesta and len(rs) > 1:
            res.hallazgo("info", f"{n} une {len(rs)} redes", f"Está en {', '.join(rs)}; desde "
                         f"{', '.join(toca_expuesta)} (expuesta) es un salto hacia las demás. "
                         "Es normal en un proxy inverso; revisar que sea intencional.", objetivo=n)

    res.metrica("Redes analizadas", len(inv["redes"]))
    res.metrica("Redes expuestas", len(expuestas))
    res.metrica("Servicios sensibles alcanzables", len(alcanzables))
    res.metrica("Contenedores puente", len(puentes))
    res.tabla("Servicios sensibles alcanzables", ["Red", "Expuesta", "Contenedor", "Puerto", "Clase"], filas)
    res.tabla("Redes expuestas (con contenedores publicados a Internet)", ["Red", "Contenedores publicados"],
              [[r, ", ".join(cs)] for r, cs in sorted(expuestas.items())])
    res.tabla("Contenedores puente", ["Contenedor", "Redes"], [[n, ", ".join(rs)] for n, rs in sorted(puentes.items())])
    res.nota("Red expuesta = red donde hay algún contenedor con puertos publicados en una IP pública del host. "
             "Docker aísla redes distintas entre sí; el riesgo está en lo que comparte red con lo expuesto y en los contenedores puente.")
    res.resumen = (f"{len(alcanzables)} servicios sensibles alcanzables; "
                   f"{sum(1 for h in res.hallazgos if h['severidad'] == 'alta')} críticos en redes expuestas.")
    return res.final()


# ── 4. Exposición hacia el host ─────────────────────────────────────────────

ESPERADOS_HOST = {80, 443}


async def gateway_host(ctx: dict) -> dict:
    res = Resultado("gateway_host")
    inv = ctx.get("inventario") or {"redes": {}}
    ifaces = interfaces()
    nombres_red = _red_de_iface(ifaces, inv) if inv.get("redes") else {i["subred"]: i["iface"] for i in ifaces}

    extra = {111, 631, 2375, 2376, 6443, 9100, 10250, 10255, 19999}
    lista = sorted(set(PUERTOS_COMUNES) | extra)
    objetivos = []
    for i in ifaces:
        # Esta prueba existe para mirar el gateway: se habilita solo aquí.
        if verificar_alcance(i["gateway"], ifaces, permitir_gateway=True) is None:
            objetivos += [(i["gateway"], p) for p in lista]
    estados = await E.escanear(objetivos, timeout=1.0, concurrencia=150)

    por_puerto = defaultdict(list)
    for (gw, p), est in estados.items():
        if est == E.ABIERTO:
            por_puerto[p].append(gw)
    gw_a_red = {i["gateway"]: nombres_red[i["subred"]] for i in ifaces}

    filas = []
    for p, gws in sorted(por_puerto.items()):
        srv, clase = servicio(p)
        info = await E.banner(gws[0], p)
        ident = info["server"] or info["banner"] or info["http"] or "—"
        filas.append([f"{p} {srv}", NOMBRE_CLASE[clase], f"{len(gws)}/{len(ifaces)}", ident,
                      ", ".join(sorted(gw_a_red[g] for g in gws))])
        objetivo = f"host:{p}"
        if p in ESPERADOS_HOST:
            continue
        if p == 22:
            res.hallazgo("baja", "SSH del host alcanzable desde los contenedores",
                         f"Desde {len(gws)} redes se llega al SSH del servidor ({ident}). Un contenedor comprometido "
                         "puede intentar acceder al host sin pasar por Internet.",
                         objetivo=objetivo, recomendacion="Restringir en UFW el 22 a orígenes externos "
                         "(denegar desde 172.16.0.0/12) si no se administra desde contenedores.")
        elif clase in ("docker",) or p in (10250, 10255):
            res.hallazgo("alta", f"{srv} del host alcanzable desde contenedores", f"Puerto {p} abierto ({ident}).",
                         objetivo=objetivo, recomendacion="Cerrarlo de inmediato o limitarlo a localhost.")
        else:
            res.hallazgo("media", f"Servicio del host alcanzable: {p} {srv}",
                         f"Responde desde {len(gws)} redes ({ident}). Los servicios del host deberían escuchar "
                         "en 127.0.0.1 o quedar bloqueados para los contenedores.",
                         objetivo=objetivo, recomendacion="Ligarlo a 127.0.0.1 o bloquear 172.16.0.0/12 en UFW para ese puerto.")

    res.metrica("Gateways probados", len(ifaces))
    res.metrica("Puertos por gateway", len(lista))
    res.metrica("Puertos del host alcanzables", len(por_puerto))
    res.tabla("Puertos del host alcanzables desde contenedores",
              ["Puerto", "Clase", "Redes", "Identificación", "Desde"], filas)
    res.nota("El gateway de cada red Docker es el propio servidor. 80/443 se consideran esperados (NPM). "
             "Esta prueba es la única que puede apuntar al gateway, aunque PERMITIR_GATEWAY esté en false.")
    res.resumen = f"{len(por_puerto)} puertos del host alcanzables desde los contenedores."
    return res.final()


# ── 5. Resolución DNS interna ───────────────────────────────────────────────

async def dns_interno(ctx: dict) -> dict:
    res = Resultado("dns_interno")
    inv = _inventario(ctx)

    # nombre → {(red, contenedor, ip)}
    duenos = defaultdict(set)
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            for n in set(c.get("dns") or [c["nombre"]]):
                duenos[n].add((red, c["nombre"], c["ip"]))

    redes_de = defaultdict(set)
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            redes_de[c["nombre"]].add(red)

    nombres = sorted(duenos)
    resueltos = dict(zip(nombres, await asyncio.gather(*(E.resolver(n) for n in nombres))))

    filas, ambiguos = [], 0
    for n in nombres:
        ips = resueltos[n] or []
        esperados = {ip for _, _, ip in duenos[n]}
        contenedores = sorted({c for _, c, _ in duenos[n]})
        estado = "ok"
        if not ips:
            estado = "no resuelve"
        elif len(contenedores) > 1:
            ambiguos += 1
            redes = sorted({r for r, _, _ in duenos[n]})
            dueno_en = {r: {c for rr, c, _ in duenos[n] if rr == r} for r in redes}
            # Afectados: contenedores en ≥2 redes donde «n» apunta a dueños distintos.
            afectados = sorted(x for x, rs in redes_de.items()
                               if len({frozenset(dueno_en[r]) for r in rs & set(redes)}) > 1)
            if afectados:
                estado = "AMBIGUO"
                res.hallazgo("media", f"Alias ambiguo: «{n}»",
                             f"Lo usan {', '.join(contenedores)} en {', '.join(redes)}. {', '.join(afectados)} "
                             f"está(n) en más de una de esas redes: al resolver «{n}» puede(n) terminar hablando "
                             "con el servicio equivocado.", objetivo=n,
                             recomendacion="En los servicios que están en varias redes, usar el nombre completo del "
                                           "contenedor en las variables de conexión, no el alias corto.")
            else:
                estado = "repetido"
                res.hallazgo("info", f"Alias repetido: «{n}»",
                             f"Lo usan {', '.join(contenedores)} en redes distintas ({', '.join(redes)}). Hoy "
                             "ningún contenedor está en dos de ellas, así que no hay confusión; la habría si "
                             "alguno se uniera a otra red.", objetivo=n)
            filas.append([n, ", ".join(contenedores), ", ".join(redes), ", ".join(ips) or "—", estado])
            continue
        elif not set(ips) & esperados:
            estado = "IP inesperada"
            res.hallazgo("media", f"«{n}» resuelve a una IP inesperada", f"Resuelve a {', '.join(ips)}; "
                         f"el inventario dice {', '.join(sorted(esperados))}.", objetivo=n,
                         recomendacion="Regenerar el inventario y revisar si hay otro servicio con ese nombre.")
        filas.append([n, ", ".join(contenedores), ", ".join(sorted({r for r, _, _ in duenos[n]})),
                      ", ".join(ips) or "—", estado])

    # Aislamiento: nombres de redes donde el probe NO está no deberían resolver.
    filtrados = []
    for red, r in (inv.get("otras_redes") or {}).items():
        for c in r["contenedores"]:
            for n in sorted(set(c.get("dns") or [c["nombre"]])):
                if n in duenos:
                    continue  # el mismo nombre existe en una red unida
                ips = await E.resolver(n)
                if ips:
                    filtrados.append(n)
                    res.hallazgo("alta", f"Nombre de otra red visible: «{n}»",
                                 f"{c['nombre']} está solo en {red} (el probe no está ahí), pero su nombre resuelve "
                                 f"a {', '.join(ips)}.", objetivo=n,
                                 recomendacion="Revisar la configuración de red; las redes deberían estar aisladas.")

    # Resolución de nombres de Internet (canal de salida por DNS)
    externo = await E.resolver("example.com")
    if externo:
        res.hallazgo("baja", "Los contenedores resuelven nombres de Internet",
                     f"example.com → {', '.join(externo)}. El DNS de Docker reenvía consultas al exterior, lo que "
                     "permite exfiltrar datos codificados en consultas DNS desde un contenedor comprometido.",
                     objetivo="DNS embebido", recomendacion="Normal en Docker. Si alguna red no necesita salida, "
                     "declararla internal: true; ver también la prueba «Salida a Internet».")

    # DNS inverso
    muestra = [c["ip"] for r in inv["redes"].values() for c in r["contenedores"]][:200]
    inversos = await asyncio.gather(*(E.nombre_inverso(ip) for ip in muestra))
    con_ptr = sum(1 for x in inversos if x)

    res.metrica("Nombres revisados", len(nombres))
    res.metrica("Alias repetidos", ambiguos)
    res.metrica("Ambiguos con riesgo", sum(1 for h in res.hallazgos if h["titulo"].startswith("Alias ambiguo")))
    res.metrica("IPs con DNS inverso", f"{con_ptr}/{len(muestra)}")
    res.metrica("Resuelve Internet", "sí" if externo else "no")
    res.tabla("Nombres DNS por red", ["Nombre", "Contenedor(es)", "Red(es)", "Resuelve a", "Estado"], filas)
    res.nota("Docker registra para cada contenedor su nombre, el nombre del servicio de compose y sus alias. "
             f"Se revisaron también {sum(len(r['contenedores']) for r in (inv.get('otras_redes') or {}).values())} "
             "contenedores de redes donde el probe no está (deben no resolver).")
    res.resumen = (f"{len(nombres)} nombres; {sum(1 for h in res.hallazgos if h['titulo'].startswith('Alias ambiguo'))} "
                   f"alias ambiguos con riesgo; "
                   f"{len(filtrados)} filtrados entre redes; Internet {'resuelve' if externo else 'no resuelve'}.")
    return res.final()


# ── Mapeo para importar conexiones ──────────────────────────────────────────

async def mapear(ctx: dict) -> dict:
    """Puertos realmente abiertos de cada contenedor del inventario, con identificación."""
    inv = _inventario(ctx)
    ifaces = interfaces()
    expuestas = _redes_expuestas(inv)
    contenedores: dict[str, dict] = {}
    for red, r in inv["redes"].items():
        for c in r["contenedores"]:
            if verificar_alcance(c["ip"], ifaces):
                continue
            x = contenedores.setdefault(c["nombre"], {"nombre": c["nombre"], "ip": c["ip"], "red": red,
                                                       "declarados": set()})
            # Preferir una red no expuesta como red "propia" del contenedor.
            if x["red"] in expuestas and red not in expuestas:
                x.update(ip=c["ip"], red=red)
            x["declarados"] |= {int(p) for p in c["puertos"] if str(p).isdigit()}

    objetivos = [(c["ip"], p) for c in contenedores.values()
                 for p in sorted(set(PUERTOS_COMUNES) | c["declarados"])]
    estados = await E.escanear(objetivos, timeout=1.0, concurrencia=200)
    abiertos = [(ip, p) for (ip, p), est in estados.items() if est == E.ABIERTO]
    sem = asyncio.Semaphore(32)

    async def identificar(ip, p):
        async with sem:
            return await E.banner(ip, p)

    infos = dict(zip(abiertos, await asyncio.gather(*(identificar(ip, p) for ip, p in abiertos))))
    salida = []
    for c in sorted(contenedores.values(), key=lambda x: x["nombre"]):
        for p in sorted(p for ip, p in abiertos if ip == c["ip"]):
            salida.append({"contenedor": c["nombre"], "red": c["red"], "ip": c["ip"], "puerto": p,
                           "declarado": p in c["declarados"], **infos[(c["ip"], p)]})
    return {"servicios": salida, "contenedores": len(contenedores), "puertos_probados": len(objetivos)}


from probe.web import PRUEBAS_WEB
from probe.cifrado import PRUEBAS_CIFRADO
from probe.auth import PRUEBAS_AUTH
from probe.ataques import PRUEBAS_ATAQUES  # fuerza_bruta, enumeracion_usuarios, tokens_jwt, mfa

PRUEBAS = {
    **PRUEBAS_WEB,
    **PRUEBAS_CIFRADO,
    **PRUEBAS_AUTH,
    **PRUEBAS_ATAQUES,
    "descubrimiento": descubrimiento,
    "puertos": puertos,
    "segmentacion": segmentacion,
    "gateway_host": gateway_host,
    "dns_interno": dns_interno,
}
