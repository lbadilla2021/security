"use strict";

// Estado en memoria
const S = { grupos: [], niveles: {}, tipos: [], conexiones: [], inventario: { redes: {} },
            estado: null, editando: null, filtroNivel: "todos" };

// Preferencias del menú (solo comodidad local; la página funciona sin ellas)
const PREF = "security-ui:menu";
function leerPref() {
  try { return JSON.parse(localStorage.getItem(PREF)) || {}; } catch { return {}; }
}
function guardarPref(cambio) {
  try { localStorage.setItem(PREF, JSON.stringify({ ...leerPref(), ...cambio })); } catch { /* sin almacenamiento */ }
}

const OBJETIVOS = {
  conexion: "Se aplica a conexiones",
  red: "Se aplica a las subredes del probe",
  plataforma: "Se aplica a la plataforma Docker",
};

const $ = (sel, raiz = document) => raiz.querySelector(sel);
const el = (tag, props = {}, ...hijos) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v;
    else if (k === "dataset") Object.assign(n.dataset, v);
    else if (k in n) n[k] = v;
    else n.setAttribute(k, v);
  }
  for (const h of hijos.flat()) if (h != null) n.append(h instanceof Node ? h : document.createTextNode(String(h)));
  return n;
};

// ── API ─────────────────────────────────────────────────────────────────────
async function api(metodo, ruta, cuerpo) {
  const op = { method: metodo, headers: { "X-Security-UI": "1" }, credentials: "same-origin" };
  if (cuerpo !== undefined) {
    op.headers["Content-Type"] = "application/json";
    op.body = JSON.stringify(cuerpo);
  }
  const r = await fetch(ruta, op);
  if (r.status === 204) return null;
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) {
    let msg = datos.detail;
    if (Array.isArray(msg)) msg = msg.map(e => `${(e.loc || []).slice(-1)[0]}: ${e.msg}`).join(" · ");
    throw new Error(msg || `Error ${r.status}`);
  }
  return datos;
}

let temporizador;
function avisar(texto) {
  const a = $("#aviso");
  a.textContent = texto;
  a.classList.remove("oculto");
  clearTimeout(temporizador);
  temporizador = setTimeout(() => a.classList.add("oculto"), 4000);
}

const tipoPorId = id => S.tipos.find(t => t.id === id);
const fecha = iso => iso ? new Date(iso).toLocaleString("es-CL", { dateStyle: "short", timeStyle: "short" }) : "—";

// ── Carga ───────────────────────────────────────────────────────────────────
async function cargar() {
  const [catalogo, conexiones, inventario, ultimos] = await Promise.all([
    api("GET", "/api/tipos"), api("GET", "/api/conexiones"), api("GET", "/api/inventario"),
    api("GET", "/api/pruebas/resumen"),
  ]);
  S.ultimos = ultimos;
  const tipos = catalogo.grupos.flatMap(g => g.tipos.map(t => ({ ...t, grupo: g.id, grupoNombre: g.nombre, seccion: g.seccion })));
  Object.assign(S, { grupos: catalogo.grupos, niveles: catalogo.niveles, tipos, conexiones, inventario,
                     filtroNivel: leerPref().nivel || "todos" });
  pintarFiltro();
  pintarMenu();
  cargarEstado();
}

async function cargarEstado() {
  const p = $("#estado-probe");
  try {
    S.estado = await api("GET", "/api/estado");
  } catch (e) {
    S.estado = { probe: null, error: e.message };
  }
  if (S.estado.probe) {
    const n = S.estado.probe.interfaces.length;
    p.textContent = `Probe conectado · ${n} red${n === 1 ? "" : "es"}`;
    p.className = "pildora pildora-ok";
  } else {
    p.textContent = "Probe sin conexión";
    p.title = S.estado.error || "";
    p.className = "pildora pildora-error";
  }
  if (["red", "tipo"].includes(rutaActual().vista)) render();
}

const nivelPill = (nivel, corta = false) =>
  el("span", { class: `nivel nivel-${nivel}`, title: S.niveles[nivel]?.descripcion || "" },
    corta ? "" : (S.niveles[nivel]?.nombre || nivel));

const SEVERIDADES = ["alta", "media", "baja", "info"];
const NOMBRE_SEV = { alta: "Alta", media: "Media", baja: "Baja", info: "Info" };

function marcaSeveridad(r) {
  if (!r?.conteo) return null;
  const peor = SEVERIDADES.find(s => r.conteo[s] > 0 && s !== "info");
  if (!peor) return el("span", { class: "sev sev-ok", title: `Última ejecución sin hallazgos relevantes (${fecha(r.inicio)})` }, "✓");
  return el("span", { class: `sev sev-${peor}`, title: `Última ejecución: ${r.conteo[peor]} hallazgo(s) ${peor} (${fecha(r.inicio)})` }, r.conteo[peor]);
}

function pintarFiltro() {
  const opciones = [["todos", "Todos"], ...Object.entries(S.niveles).map(([k, v]) => [k, v.nombre])];
  $("#filtro-niveles").replaceChildren(...opciones.map(([k, nombre]) => el("button", {
    type: "button", class: `filtro${k === S.filtroNivel ? " activo" : ""}`,
    dataset: { accion: "filtrar", nivel: k }, "aria-pressed": String(k === S.filtroNivel),
  }, k === "todos" ? null : nivelPill(k, true), nombre)));
}

function pintarMenu() {
  const abiertos = leerPref().abiertos || {};
  const actual = rutaActual();
  const grupoActual = actual.vista === "tipo" ? tipoPorId(actual.id)?.grupo : null;
  const pintarGrupo = g => {
    const tipos = S.tipos.filter(t => t.grupo === g.id && (S.filtroNivel === "todos" || t.nivel === S.filtroNivel));
    if (!tipos.length) return null;
    const asignadas = tipos.reduce((n, t) => n + S.conexiones.filter(c => c.tipos.includes(t.id)).length, 0);
    const det = el("details", { class: "grupo", dataset: { grupo: g.id } },
      el("summary", {},
        el("span", { class: "grupo-nombre" }, g.nombre),
        el("span", { class: "contador", title: `${tipos.length} tipos · ${asignadas} asignaciones` }, tipos.length)),
      el("div", { class: "grupo-items" }, tipos.map(t => {
        const n = S.conexiones.filter(c => c.tipos.includes(t.id)).length;
        return el("a", { href: `#/tipo/${t.id}`, dataset: { ruta: `tipo/${t.id}` },
                         class: t.implementada ? "" : "sin-implementar",
                         title: `${S.niveles[t.nivel]?.nombre}${t.intrusivo ? " · intrusiva" : ""}${t.implementada ? "" : " · por implementar"} — ${t.descripcion}` },
          nivelPill(t.nivel, true),
          el("span", { class: "item-nombre" }, t.nombre),
          marcaSeveridad(S.ultimos?.[t.id]),
          t.objetivo === "conexion"
            ? (n ? el("span", { class: "contador" }, n) : null)
            : el("span", { class: "objetivo-icono", title: OBJETIVOS[t.objetivo] }, t.objetivo === "red" ? "red" : "host"));
      })));
    det.open = g.id === grupoActual || S.filtroNivel !== "todos" || !!abiertos[g.id];
    return det;
  };
  const porSeccion = sec => S.grupos.filter(g => g.seccion === sec).map(pintarGrupo).filter(Boolean);
  $("#menu-tipos").replaceChildren(...porSeccion("generales"));
  const apps = porSeccion("aplicacion");
  $("#menu-apps").replaceChildren(...(apps.length ? apps
    : [el("p", { class: "menu-nota" }, "Ninguna con el filtro actual.")]));
  const general = $('.grupo[data-grupo="general"]');
  if (abiertos.general === false) general.open = false;
  marcarMenu();
}

function marcarMenu() {
  const actual = location.hash.replace(/^#\//, "") || "conexiones";
  document.querySelectorAll(".menu a").forEach(a => {
    if (a.dataset.ruta === actual) {
      a.setAttribute("aria-current", "page");
      const det = a.closest("details");
      if (det && !det.open) det.open = true;
    } else a.removeAttribute("aria-current");
  });
}

// ── Rutas ───────────────────────────────────────────────────────────────────
function rutaActual() {
  const [vista, id] = (location.hash.replace(/^#\//, "") || "conexiones").split("/");
  return { vista, id };
}

function render() {
  const { vista, id } = rutaActual();
  const main = $("#vista");
  marcarMenu();
  if (vista === "red") return vistaRed(main);
  if (vista === "tipo" && tipoPorId(id)) return vistaTipo(main, tipoPorId(id));
  return vistaConexiones(main);
}

// ── Vista: conexiones ───────────────────────────────────────────────────────
function vistaConexiones(main) {
  main.replaceChildren($("#tpl-conexiones").content.cloneNode(true));
  $("#filtro-conexiones").value = filtroConexiones;
  pintarTabla();
  prepararForm();
  if (S.editando) abrirForm(S.editando);
}

function resultadoPill(u) {
  if (!u) return el("span", { class: "pildora pildora-neutra" }, "Sin probar");
  return el("span", { class: `pildora ${u.ok ? "pildora-ok" : "pildora-error"}`, title: `${u.detalle || ""} · ${fecha(u.fecha)}` },
    u.ok ? `OK${u.ms_tcp != null ? ` · ${u.ms_tcp} ms` : ""}` : "Falla");
}

let filtroConexiones = "";

function pintarTabla() {
  const tb = $("#tabla-conexiones");
  if (!tb) return;
  const q = filtroConexiones.trim().toLowerCase();
  const visibles = S.conexiones.filter(c => !q ||
    [c.nombre, c.host, c.red, c.protocolo, String(c.puerto), c.notas].some(v => (v || "").toLowerCase().includes(q)));
  $("#sin-conexiones").classList.toggle("oculto", S.conexiones.length > 0);
  $("#cuenta-conexiones").textContent = S.conexiones.length
    ? (q ? `${visibles.length} de ${S.conexiones.length}` : `${S.conexiones.length} conexiones`) : "";
  const orden = [...visibles].sort((a, b) => (a.red || "").localeCompare(b.red || "") || a.host.localeCompare(b.host) || a.puerto - b.puerto);
  tb.replaceChildren(...orden.map(c => el("tr", {},
    el("td", {}, el("strong", {}, c.nombre), c.notas ? el("div", { class: "muted pequeño nota-fila", title: c.notas }, c.notas) : null),
    el("td", {}, el("span", { class: "mono" }, `${c.host}:${c.puerto}`), el("div", { class: "muted pequeño" }, c.protocolo.toUpperCase())),
    el("td", {}, c.red || el("span", { class: "muted" }, "—")),
    el("td", {}, c.tipos.length
      ? el("span", { class: "etiqueta", title: c.tipos.map(t => tipoPorId(t)?.nombre || t).join("\n") }, `${c.tipos.length} prueba${c.tipos.length === 1 ? "" : "s"}`)
      : el("span", { class: "muted" }, "—")),
    el("td", {}, resultadoPill(c.ultima_prueba)),
    el("td", {}, el("div", { class: "acciones" },
      el("button", { type: "button", class: "btn btn-chico", dataset: { accion: "probar", id: c.id } }, "Probar"),
      el("button", { type: "button", class: "btn btn-chico", dataset: { accion: "editar", id: c.id } }, "Editar"),
      el("button", { type: "button", class: "btn btn-chico btn-peligro", dataset: { accion: "eliminar", id: c.id } }, "Eliminar"),
    )),
  )));
}

function prepararForm() {
  const f = $("#form-conexion");
  const selRed = f.elements.red;
  for (const [nombre, r] of Object.entries(S.inventario.redes || {})) {
    selRed.append(el("option", { value: nombre }, `${nombre} (${r.subred})`));
  }
  selRed.addEventListener("change", llenarHosts);
  f.elements.protocolo.addEventListener("change", pintarChipsTipos);
  f.elements.host.addEventListener("change", sugerirRed);
  f.addEventListener("submit", guardar);
  llenarHosts();
  pintarChipsTipos();
}

function llenarHosts() {
  const f = $("#form-conexion");
  const red = f.elements.red.value;
  const redes = S.inventario.redes || {};
  const nombres = new Set();
  for (const [n, r] of Object.entries(redes)) {
    if (red && n !== red) continue;
    r.contenedores.forEach(c => nombres.add(c.nombre));
  }
  $("#lista-hosts").replaceChildren(...[...nombres].sort().map(n => el("option", { value: n })));
}

function sugerirRed() {
  const f = $("#form-conexion");
  if (f.elements.red.value) return;
  const host = f.elements.host.value.trim();
  for (const [n, r] of Object.entries(S.inventario.redes || {})) {
    const c = r.contenedores.find(c => c.nombre === host || c.ip === host);
    if (c) {
      f.elements.red.value = n;
      if (!f.elements.puerto.value && c.puertos.length) f.elements.puerto.value = parseInt(c.puertos[0], 10);
      break;
    }
  }
}

function pintarChipsTipos(marcados) {
  const f = $("#form-conexion");
  const proto = f.elements.protocolo.value;
  const previos = Array.isArray(marcados) ? marcados
    : [...f.querySelectorAll('input[name="tipos"]:checked')].map(i => i.value);
  const bloques = S.grupos.map(g => {
    const aplicables = S.tipos.filter(t => t.grupo === g.id && t.objetivo === "conexion" && t.protocolos.includes(proto));
    if (!aplicables.length) return null;
    return el("div", { class: "form-grupo" },
      el("p", { class: "form-grupo-titulo" }, g.seccion === "aplicacion" ? `Aplicación · ${g.nombre}` : g.nombre),
      el("div", { class: "chips" }, aplicables.map(t => el("label", { class: "chip", title: t.descripcion },
        el("input", { type: "checkbox", name: "tipos", value: t.id, checked: previos.includes(t.id) }),
        nivelPill(t.nivel, true), t.nombre))));
  }).filter(Boolean);
  $("#form-tipos").replaceChildren(...(bloques.length ? bloques
    : [el("p", { class: "muted pequeño" }, `Ningún tipo de prueba aplica a ${proto.toUpperCase()}.`)]));
}

function abrirForm(c) {
  const f = $("#form-conexion");
  S.editando = c || null;
  $("#panel-form").classList.remove("oculto");
  $("#form-titulo").textContent = c?.id ? `Editar: ${c.nombre}` : "Nueva conexión";
  f.reset();
  $("#form-resultado").classList.add("oculto");
  if (c) {
    for (const k of ["nombre", "red", "host", "puerto", "protocolo", "notas"]) {
      if (c[k] != null) f.elements[k].value = c[k];
    }
  }
  llenarHosts();
  pintarChipsTipos(c?.tipos || []);
  f.elements.nombre.focus();
}

function cerrarForm() {
  S.editando = null;
  $("#panel-form").classList.add("oculto");
}

function leerForm() {
  const f = $("#form-conexion");
  return {
    nombre: f.elements.nombre.value.trim(),
    red: f.elements.red.value,
    host: f.elements.host.value.trim(),
    puerto: parseInt(f.elements.puerto.value, 10),
    protocolo: f.elements.protocolo.value,
    notas: f.elements.notas.value.trim(),
    tipos: [...f.querySelectorAll('input[name="tipos"]:checked')].map(i => i.value),
  };
}

function validar(d, paraGuardar) {
  const f = $("#form-conexion");
  const errores = [];
  const marca = (campo, mal) => { f.elements[campo].setAttribute("aria-invalid", mal ? "true" : "false"); if (mal) errores.push(campo); };
  if (paraGuardar) marca("nombre", !d.nombre);
  marca("host", !/^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/.test(d.host));
  marca("puerto", !(d.puerto >= 1 && d.puerto <= 65535));
  if (errores.length) { avisar(`Revisa: ${errores.join(", ")}`); return false; }
  return true;
}

function mostrarResultado(caja, r) {
  caja.className = `resultado ${r.ok ? "ok" : "error"}`;
  const filas = [
    ["Resultado", r.detalle],
    ["Etapa", r.etapa],
    r.ips && ["IPs", r.ips.join(", ")],
    r.subred && ["Subred", r.subred],
    r.ms_tcp != null && ["Latencia TCP", `${r.ms_tcp} ms`],
    r.tls && ["TLS", `${r.tls.version} · ${r.tls.cifrado}`],
    r.http?.linea_estado && ["HTTP", r.http.linea_estado],
    r.http?.server && ["Server", r.http.server],
    r.http?.location && ["Location", r.http.location],
  ].filter(Boolean);
  caja.replaceChildren(el("strong", {}, r.ok ? "Conexión establecida" : "Sin conexión"),
    el("dl", {}, filas.flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: "mono" }, v ?? "—")])));
}

async function probarForm(boton) {
  const d = leerForm();
  if (!validar(d, false)) return;
  const caja = $("#form-resultado");
  boton.disabled = true;
  try {
    mostrarResultado(caja, await api("POST", "/api/probar", { host: d.host, puerto: d.puerto, protocolo: d.protocolo }));
  } catch (e) {
    mostrarResultado(caja, { ok: false, detalle: e.message, etapa: "alcance" });
  } finally {
    boton.disabled = false;
  }
}

async function guardar(ev) {
  ev.preventDefault();
  const d = leerForm();
  if (!validar(d, true)) return;
  try {
    if (S.editando?.id) {
      const act = await api("PUT", `/api/conexiones/${S.editando.id}`, d);
      S.conexiones = S.conexiones.map(c => c.id === act.id ? act : c);
      avisar("Conexión actualizada");
    } else {
      S.conexiones.push(await api("POST", "/api/conexiones", d));
      avisar("Conexión guardada");
    }
    cerrarForm();
    pintarTabla();
    pintarMenu();
  } catch (e) {
    avisar(e.message);
  }
}

async function probarGuardada(id, boton) {
  boton.disabled = true;
  boton.textContent = "Probando…";
  try {
    const r = await api("POST", `/api/conexiones/${id}/probar`);
    avisar(r.ok ? `OK · ${r.detalle}` : `Falla · ${r.detalle}`);
    S.conexiones = await api("GET", "/api/conexiones");
    pintarTabla();
  } catch (e) {
    avisar(e.message);
    boton.disabled = false;
    boton.textContent = "Probar";
  }
}

async function importar(boton) {
  if (!confirm("Se escanearán todos los contenedores del inventario y se creará una conexión por cada puerto abierto " +
               "que aún no exista, con las pruebas no intrusivas que le apliquen. ¿Continuar?")) return;
  const texto = boton.textContent;
  boton.disabled = true;
  boton.textContent = "Escaneando…";
  try {
    const r = await api("POST", "/api/conexiones/importar");
    S.conexiones = await api("GET", "/api/conexiones");
    pintarTabla();
    pintarMenu();
    avisar(`${r.creadas} conexiones creadas (${r.existentes} ya existían) en ${r.contenedores} contenedores.`);
  } catch (e) {
    avisar(e.message);
  } finally {
    boton.disabled = false;
    boton.textContent = texto;
  }
}

async function eliminar(id) {
  const c = S.conexiones.find(x => x.id === id);
  if (!c || !confirm(`¿Eliminar la conexión "${c.nombre}"?`)) return;
  try {
    await api("DELETE", `/api/conexiones/${id}`);
    S.conexiones = S.conexiones.filter(x => x.id !== id);
    pintarTabla();
    pintarMenu();
    avisar("Conexión eliminada");
  } catch (e) {
    avisar(e.message);
  }
}

// ── Vista: red e inventario ─────────────────────────────────────────────────
function vistaRed(main) {
  main.replaceChildren($("#tpl-red").content.cloneNode(true));
  const tb = $("#tabla-interfaces");
  const ifs = S.estado?.probe?.interfaces;
  if (!ifs) {
    tb.replaceChildren(el("tr", {}, el("td", { colspan: 5, class: "muted" }, S.estado ? `Probe sin conexión: ${S.estado.error || ""}` : "Cargando…")));
  } else {
    tb.replaceChildren(...ifs.map(i => el("tr", {},
      el("td", {}, i.red || el("span", { class: "muted" }, "desconocida")),
      el("td", { class: "mono" }, i.iface), el("td", { class: "mono" }, i.ip || "—"),
      el("td", { class: "mono" }, i.subred),
      el("td", { class: "mono" }, S.estado.probe.permitir_gateway ? `${i.gateway} (permitido)` : i.gateway))));
  }
  const inv = S.inventario;
  $("#inv-fecha").textContent = inv.generado
    ? `Generado ${fecha(inv.generado)} con scripts/inventario.sh (se ejecuta en el host).`
    : "Sin inventario. Ejecuta scripts/inventario.sh en el host.";
  $("#inventario").replaceChildren(...Object.entries(inv.redes || {}).map(([nombre, r]) =>
    el("details", { class: "red", open: true },
      el("summary", {}, el("strong", {}, nombre), el("span", { class: "mono" }, r.subred), el("span", { class: "contador" }, r.contenedores.length)),
      el("div", { class: "tabla-envoltura" }, el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "Contenedor"), el("th", {}, "IP"), el("th", {}, "Puertos expuestos"), el("th", { class: "der" }, ""))),
        el("tbody", {}, r.contenedores.map(c => el("tr", {},
          el("td", {}, c.nombre), el("td", { class: "mono" }, c.ip),
          el("td", { class: "mono" }, c.puertos.length ? c.puertos.join(", ") : "—"),
          el("td", { class: "der" }, el("button", { type: "button", class: "btn btn-chico", dataset: { accion: "usar", red: nombre, host: c.nombre, puerto: c.puertos[0] || "" } }, "Usar"))))),
      )))));
}

// ── Vista: tipo de prueba ───────────────────────────────────────────────────
function vistaTipo(main, t) {
  main.replaceChildren($("#tpl-tipo").content.cloneNode(true));
  const campo = n => main.querySelector(`[data-campo="${n}"]`);
  campo("grupo").textContent = `${t.seccion === "aplicacion" ? "Pruebas por aplicación" : "Pruebas generales"} / ${t.grupoNombre}`;
  campo("nombre").textContent = t.nombre;
  campo("descripcion").textContent = t.descripcion;
  campo("nivel").replaceWith(nivelPill(t.nivel));
  campo("intrusivo").classList.toggle("oculto", !t.intrusivo);
  campo("verifica").replaceChildren(...t.verifica.map(v => el("li", {}, v)));
  campo("alcance").textContent = t.objetivo === "conexion"
    ? `Protocolos compatibles: ${t.protocolos.map(p => p.toUpperCase()).join(", ")}`
    : OBJETIVOS[t.objetivo];

  if (t.objetivo !== "conexion") {
    campo("titulo-objetivo").textContent = t.objetivo === "red" ? "Redes incluidas" : "Alcance";
    campo("ayuda-objetivo").textContent = t.objetivo === "red"
      ? "No usa conexiones: recorre las subredes a las que está unido el probe."
      : "No usa conexiones: revisa la configuración de Docker y del servidor (se ejecutará desde el host).";
    const ifs = S.estado?.probe?.interfaces || [];
    campo("conexiones").replaceChildren(...(t.objetivo === "red"
      ? (ifs.length ? ifs.map(i => el("div", {}, el("strong", {}, i.red || i.iface), " ", el("span", { class: "mono muted" }, i.subred)))
                    : [el("p", { class: "muted" }, "Probe sin conexión.")])
      : [el("p", { class: "muted" }, `${Object.values(S.inventario.redes || {}).reduce((n, r) => n + r.contenedores.length, 0)} contenedores en el inventario.`)]));
  } else {
    campo("ayuda-objetivo").textContent = "Marca las conexiones a las que se aplicará esta prueba. Solo aparecen las de protocolo compatible.";
    const compatibles = S.conexiones.filter(c => t.protocolos.includes(c.protocolo));
    campo("conexiones").replaceChildren(...(compatibles.length
      ? compatibles.map(c => el("label", {},
          el("input", { type: "checkbox", checked: c.tipos.includes(t.id), dataset: { accion: "asignar", id: c.id, tipo: t.id } }),
          el("span", {}, c.nombre), el("span", { class: "mono muted" }, `${c.host}:${c.puerto}`)))
      : [el("p", { class: "muted" }, "No hay conexiones con protocolo compatible. ", el("a", { href: "#/conexiones" }, "Crear una"))]));
  }

  if (!t.implementada) return;
  const estado = campo("estado");
  estado.textContent = "Implementada";
  estado.className = "pildora pildora-ok";
  const boton = campo("boton");
  boton.disabled = false;
  boton.dataset.tipo = t.id;
  boton.title = "";
  if (t.recoleccion) {
    campo("recoleccion").classList.remove("oculto");
    campo("comando").textContent = `cd /root/docker/security && ${t.recoleccion}`;
    boton.textContent = "Analizar última recolección";
  }
  renderGuia(t, campo);
  renderParametros(t, campo);
  cargarResultados(t.id);
}

function _emailFalso() {
  return `fuerzabruta-noexiste-${Math.random().toString(16).slice(2, 10)}@gmail.com`;
}

function renderGuia(t, campo) {
  if (!t.guia) return;
  campo("seccion-guia").classList.remove("oculto");
  campo("guia-intro").textContent = t.guia.intro || "";
  campo("guia-pasos").replaceChildren(...(t.guia.pasos || []).map(x => el("li", {}, x)));
  const lectura = t.guia.lectura || [];
  campo("guia-lectura-titulo").classList.toggle("oculto", !lectura.length);
  campo("guia-lectura").replaceChildren(...lectura.map(x => el("li", {}, x)));
}

function renderParametros(t, campo) {
  if (!t.parametros?.length) return;
  campo("seccion-parametros").classList.remove("oculto");
  const cont = campo("parametros");
  cont.replaceChildren(...t.parametros.map(p => {
    let entrada;
    if (p.tipo === "select") {
      entrada = el("select", { name: `param-${p.id}` }, ...(p.opciones || []).map(o => el("option", { value: o, selected: o === p.default }, o)));
    } else if (p.tipo === "numero") {
      entrada = el("input", { type: "number", name: `param-${p.id}`, value: p.default ?? "", min: p.min ?? "", max: p.max ?? "" });
    } else {
      const val = p.default ?? (p.generar === "email_falso" ? _emailFalso() : "");
      entrada = el("input", { type: "text", name: `param-${p.id}`, value: val, autocomplete: "off", spellcheck: "false" });
    }
    const ancho = (p.tipo === "texto" && (p.id === "email" || p.id === "ruta" || p.id === "host_header")) ? " ancho" : "";
    return el("label", { class: `param${ancho}` },
      el("span", {}, p.etiqueta + (p.requerido ? " *" : "")),
      entrada,
      p.ayuda ? el("span", { class: "muted pequeño param-ayuda" }, p.ayuda) : null);
  }));
}

function leerParametros(t) {
  const out = {};
  for (const p of (t.parametros || [])) {
    const campo = $(`#vista [name="param-${p.id}"]`);
    if (!campo) continue;
    out[p.id] = p.tipo === "numero" ? Number(campo.value) : campo.value.trim();
  }
  return out;
}

// ── Ejecución y resultados ──────────────────────────────────────────────────
const campoVista = n => $(`#vista [data-campo="${n}"]`);

async function cargarResultados(tipo, rid) {
  const lista = await api("GET", `/api/pruebas/${tipo}/resultados`).catch(() => []);
  if (rutaActual().id !== tipo) return;  // el usuario ya navegó a otra vista
  const sec = campoVista("seccion-resultados");
  if (!lista.length) { sec.classList.add("oculto"); return; }
  sec.classList.remove("oculto");
  const sel = campoVista("historial");
  sel.replaceChildren(...lista.map((r, i) => el("option", { value: r.id },
    `${fecha(r.inicio)}${i === 0 ? " (última)" : ""} · ${r.conteo ? SEVERIDADES.filter(s => r.conteo[s]).map(s => `${r.conteo[s]} ${s}`).join(", ") || "sin hallazgos" : ""}`)));
  sel.value = rid || lista[0].id;
  sel.dataset.tipo = tipo;
  mostrarResultadoPrueba(await api("GET", `/api/pruebas/${tipo}/resultados/${sel.value}`));
}

function mostrarResultadoPrueba(r) {
  const caja = campoVista("resultado");
  const conteo = SEVERIDADES.map(s => el("div", { class: `conteo conteo-${s}` },
    el("span", { class: "conteo-num" }, r.conteo[s]), el("span", {}, NOMBRE_SEV[s])));
  const metricas = r.metricas.map(m => el("div", { class: "metrica" },
    el("span", { class: "metrica-valor" }, m.valor), el("span", { class: "metrica-nombre" }, m.nombre)));
  const hallazgos = r.hallazgos.length
    ? r.hallazgos.map(h => el("article", { class: `hallazgo hallazgo-${h.severidad}` },
        el("header", {}, el("span", { class: `sev-etiqueta sev-${h.severidad}` }, NOMBRE_SEV[h.severidad]),
          el("strong", {}, h.titulo)),
        h.detalle ? el("p", {}, h.detalle) : null,
        h.objetivo ? el("p", { class: "muted pequeño" }, "Objetivo: ", el("span", { class: "mono" }, h.objetivo)) : null,
        h.recomendacion ? el("p", { class: "recomendacion" }, el("strong", {}, "Qué hacer: "), h.recomendacion) : null))
    : [el("p", { class: "muted" }, "Sin hallazgos.")];
  const tablas = r.tablas.map((tb, i) => el("details", { class: "tabla-resultado", open: i === 0 && tb.filas.length <= 60 },
    el("summary", {}, el("strong", {}, tb.titulo), el("span", { class: "contador" }, tb.filas.length)),
    tb.filas.length
      ? el("div", { class: "tabla-envoltura" }, el("table", {},
          el("thead", {}, el("tr", {}, tb.columnas.map(c => el("th", {}, c)))),
          el("tbody", {}, tb.filas.map(f => el("tr", {}, f.map(v => el("td", {}, v ?? "—")))))))
      : el("p", { class: "muted vacio" }, "Sin filas.")));
  caja.replaceChildren(
    el("div", { class: "tarjeta" },
      el("p", { class: "resumen-resultado" }, r.resumen),
      el("p", { class: "muted pequeño" }, `Ejecutada ${fecha(r.inicio)} · ${r.duracion_s} s`),
      el("div", { class: "conteos" }, conteo),
      metricas.length ? el("div", { class: "metricas" }, metricas) : null),
    el("div", { class: "tarjeta" }, el("h3", {}, `Hallazgos (${r.hallazgos.length})`), el("div", { class: "hallazgos" }, hallazgos)),
    ...(tablas.length ? [el("div", { class: "tarjeta" }, el("h3", {}, "Detalle"), tablas)] : []),
    ...(r.notas?.length ? [el("div", { class: "tarjeta notas" }, el("h3", {}, "Notas"), el("ul", { class: "lista" }, r.notas.map(n => el("li", {}, n))))] : []));
}

async function ejecutarPrueba(boton) {
  const t = tipoPorId(boton.dataset.tipo);
  const parametros = leerParametros(t);
  for (const p of (t.parametros || [])) {
    if (p.requerido && !parametros[p.id]) {
      avisar(`Falta el parámetro: ${p.etiqueta}`);
      $(`#vista [name="param-${p.id}"]`)?.focus();
      return;
    }
  }
  if (t.intrusivo) {
    const detalle = t.id === "fuerza_bruta"
      ? `\n\nObjetivo: ${parametros.email}\nIntentos: ${parametros.intentos}\n\nConfirma que ese correo NO pertenece a un usuario real.`
      : "";
    if (!confirm(`«${t.nombre}» es intrusiva.${detalle}\n\n¿Ejecutar?`)) return;
  }
  const progreso = campoVista("progreso");
  const textoOriginal = boton.textContent;
  boton.disabled = true;
  boton.textContent = "Ejecutando…";
  const t0 = Date.now();
  const reloj = setInterval(() => { if (progreso) progreso.textContent = `${Math.round((Date.now() - t0) / 1000)} s`; }, 1000);
  try {
    const r = await api("POST", `/api/pruebas/${t.id}/ejecutar`, { parametros, confirmar: t.intrusivo });
    S.ultimos = { ...(S.ultimos || {}), [t.id]: r };
    pintarMenu();
    avisar(r.resumen || "Prueba terminada");
    if (rutaActual().id === t.id) await cargarResultados(t.id, r.id);
  } catch (e) {
    avisar(e.message);
  } finally {
    clearInterval(reloj);
    if (progreso) progreso.textContent = "";
    boton.disabled = false;
    boton.textContent = textoOriginal;
  }
}

async function asignar(cb) {
  const c = S.conexiones.find(x => x.id === cb.dataset.id);
  const tipos = new Set(c.tipos);
  cb.checked ? tipos.add(cb.dataset.tipo) : tipos.delete(cb.dataset.tipo);
  const { id, creada, actualizada, ultima_prueba, ...datos } = c;
  try {
    const act = await api("PUT", `/api/conexiones/${id}`, { ...datos, tipos: [...tipos] });
    S.conexiones = S.conexiones.map(x => x.id === id ? act : x);
    pintarMenu();
  } catch (e) {
    cb.checked = !cb.checked;
    avisar(e.message);
  }
}

// ── Eventos delegados ───────────────────────────────────────────────────────
document.addEventListener("click", ev => {
  const b = ev.target.closest("[data-accion]");
  if (!b || b.tagName === "INPUT") return;
  const { accion, id } = b.dataset;
  if (accion === "nueva") abrirForm(null);
  else if (accion === "cancelar") cerrarForm();
  else if (accion === "probar-form") probarForm(b);
  else if (accion === "probar") probarGuardada(id, b);
  else if (accion === "editar") abrirForm(S.conexiones.find(c => c.id === id));
  else if (accion === "eliminar") eliminar(id);
  else if (accion === "ejecutar") ejecutarPrueba(b);
  else if (accion === "importar") importar(b);
  else if (accion === "filtrar") {
    S.filtroNivel = b.dataset.nivel;
    guardarPref({ nivel: S.filtroNivel });
    pintarFiltro();
    pintarMenu();
  }
  else if (accion === "expandir" || accion === "contraer") {
    const abrir = accion === "expandir";
    const abiertos = {};
    document.querySelectorAll(".menu details.grupo").forEach(d => { d.open = abrir; abiertos[d.dataset.grupo] = abrir; });
    guardarPref({ abiertos });
  }
  else if (accion === "usar") {
    S.editando = { nombre: b.dataset.host, red: b.dataset.red, host: b.dataset.host,
                   puerto: b.dataset.puerto ? parseInt(b.dataset.puerto, 10) : "", protocolo: "tcp", notas: "", tipos: [] };
    location.hash = "#/conexiones";
  }
});
document.addEventListener("change", ev => {
  if (ev.target.dataset?.accion === "asignar") asignar(ev.target);
  if (ev.target.matches?.('[data-campo="historial"]')) cargarResultados(ev.target.dataset.tipo, ev.target.value);
});
// Recordar qué grupos abrió o cerró el usuario a mano
document.addEventListener("click", ev => {
  const sum = ev.target.closest(".menu details.grupo > summary");
  if (!sum) return;
  const d = sum.parentElement;
  setTimeout(() => {  // después de que el navegador cambie el estado
    const abiertos = leerPref().abiertos || {};
    abiertos[d.dataset.grupo] = d.open;
    guardarPref({ abiertos });
  });
});
document.addEventListener("input", ev => {
  if (ev.target.id === "filtro-conexiones") { filtroConexiones = ev.target.value; pintarTabla(); }
});
window.addEventListener("hashchange", render);

cargar().then(render).catch(e => {
  $("#vista").replaceChildren(el("div", { class: "tarjeta" }, el("h3", {}, "No se pudo cargar"), el("p", { class: "muted" }, e.message)));
});
