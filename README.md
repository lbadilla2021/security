# security — consola de pruebas de red interna

Página local para definir **conexiones** hacia los contenedores de la red
interna y asignarles **tipos de prueba** de seguridad. Por ahora solo se
configuran y se prueba la conectividad; las pruebas en sí no se ejecutan todavía.

No tiene usuarios: la protección es que **solo se puede abrir desde el propio
servidor**, por túnel SSH.

## Uso

```bash
# En tu equipo:
ssh -N -L 9510:127.0.0.1:9510 root@<servidor>
# y abre http://localhost:9510
```

El puerto local puede ser otro (`-L 8888:127.0.0.1:9510` → `http://localhost:8888`).
Se debe entrar con `localhost` o `127.0.0.1`; cualquier otro nombre responde 421.

```bash
cd /root/docker/security
docker compose up -d --build      # levantar / aplicar cambios
./scripts/inventario.sh           # refrescar la lista de contenedores (en el host)
./scripts/plataforma.sh egress    # recolectar salida a Internet por red (en el host)
docker compose logs -f            # logs
docker compose down               # apagar (las conexiones quedan en data/)
```

## Arquitectura

```
navegador ──túnel SSH──▶ 127.0.0.1:9510 (host)
                              │
                     ┌────────▼────────┐  red security-ui (solo este contenedor)
                     │  security-web   │  página + API, guarda data/conexiones.json
                     └────────┬────────┘
                              │ socket Unix (volumen probe-sock), sin TCP
                     ┌────────▼────────┐  redes: payroll_saas-net, nocobase-network,
                     │ security-probe  │  apex-internal, automatiza-network,
                     └─────────────────┘  prospeccion-net, site-halcon_default
```

| Archivo | Qué es |
|---|---|
| `docker-compose.yml` | Los dos servicios, redes y endurecimiento |
| `app/src/web/` | FastAPI + página (HTML/CSS/JS en `static/`) |
| `app/src/web/catalogo.py` | Catálogo: 50 pruebas generales en 9 grupos + pruebas por aplicación (Firma electrónica), con nivel y objetivo |
| `app/src/probe/main.py` | Resolución DNS, conexión TCP/HTTP/TLS y regla de alcance |
| `app/src/probe/pruebas.py` | Pruebas que corren en el probe (red) |
| `app/src/probe/escaner.py` | Conexión TCP, barrido de puertos, banners, DNS |
| `app/src/web/plataforma.py` | Análisis de pruebas de plataforma (datos del host) |
| `scripts/inventario.sh` | Genera `data/inventario.json` desde el host (IPs, puertos, DNS, publicaciones) |
| `scripts/plataforma.sh` | Recolecta datos de plataforma en `data/plataforma/` |
| `data/` | `conexiones.json`, `inventario.json`, `plataforma/`, `resultados/<tipo>/` (últimas 20 por tipo) |

## Por qué no hay riesgo de acceso externo

1. **Red:** el puerto se publica solo en `127.0.0.1:9510`. No escucha en la IP
   pública (v4 ni v6) y UFW sigue con 22/80/443 como únicos puertos abiertos.
   NPM no tiene ningún proxy hacia este servicio; **no crear uno.**
2. **Contenedores vecinos:** `security-web` está solo en su red `security-ui`.
   `security-probe` comparte redes con las apps pero **no abre ningún puerto
   TCP**: atiende por un socket Unix. Un contenedor comprometido no puede
   llegar a ninguno de los dos.
3. **Navegador** (la página no tiene login, así que se defiende de otras pestañas):
   - DNS rebinding: solo acepta `Host` igual a localhost, 127.0.0.1 o [::1].
   - CSRF: toda escritura exige la cabecera `X-Security-UI` y un `Origin` local.
   - XSS: CSP estricta sin código inline; el front nunca usa `innerHTML`.
4. **Alcance del probe:** solo se conecta a IPs dentro de las subredes de sus
   interfaces. Internet, loopback y el gateway de cada red (que es el host)
   quedan bloqueados. Para probar servicios del host: `PERMITIR_GATEWAY=true`.
5. **Contenedores endurecidos:** usuario sin privilegios (uid 10001), sistema
   de archivos de solo lectura, `cap_drop: ALL`, `no-new-privileges`, límites
   de memoria, CPU y procesos, y sin `docker.sock` (el inventario lo arma el host).

Verificado el 2026-11-21: la IP pública (v4 y v6) rechaza la conexión, un
contenedor de payroll no resuelve ni alcanza a `security-web`, un `Host`
ajeno responde 421, un POST sin la cabecera o con `Origin` ajeno responde 403
y los destinos 1.1.1.1 y 172.22.0.1 dan "fuera de alcance".

## Agregar o quitar redes

Editar la lista `networks` de `probe` (y la sección `networks:` del final) en
`docker-compose.yml`, luego `docker compose up -d` y `./scripts/inventario.sh`.
Fuera a propósito: `alerting`, `seguridad_default`, `backup-offsite_default`.

## Catálogo de pruebas

El menú separa **pruebas generales** (9 grupos desplegables; el usuario elige a qué conexiones aplicarlas) de **pruebas por aplicación** (un grupo por sistema, hoy solo Firma electrónica; agregar otro = un grupo con `"seccion": "aplicacion"` en catalogo.py). Se puede filtrar por nivel:

| Nivel | Qué hace |
|---|---|
| Auditoría | Revisa configuración, sin atacar |
| Escaneo | Busca debilidades conocidas de forma automática |
| Pentest | Intenta explotar la debilidad (intrusivo) |
| Red team | Simula un ataque y mide si se detecta (intrusivo) |

Cada tipo tiene un **objetivo**: `conexion` (se asigna a conexiones con
protocolo compatible; la API rechaza asignaciones que no aplican), `red`
(recorre las subredes del probe) o `plataforma` (revisa Docker/host desde el
host). Las intrusivas mostrarán una advertencia y pedirán confirmación; conviene
correrlas contra el tenant Demo o una copia.

## Importar conexiones

En **Conexiones → Importar desde inventario** se escanea cada contenedor del
inventario (puertos comunes + declarados) y se crea una conexión por cada
puerto **realmente abierto** que aún no exista (host + puerto), con:
- protocolo inferido de la respuesta (HTTP/HTTPS/Postgres/Redis/MinIO/TCP);
- la red propia del contenedor (si está en varias, la no expuesta);
- las pruebas **no intrusivas** compatibles; las específicas (bases de datos,
  Redis, MinIO, Qdrant, paneles, métricas, n8n) solo donde corresponde.

Es idempotente: volver a importar solo agrega lo nuevo.

## Pruebas implementadas

Casi todas son de solo lectura (excepto «Fuerza bruta», que envía intentos de login): conexiones TCP, a lo más un `HEAD /` en servicios
web, y consultas DNS. Una prueba a la vez (la segunda recibe 409).

| Prueba | Dónde corre | Qué hace |
|---|---|---|
| Descubrimiento de hosts | probe | Barre las primeras 254 IPs de cada subred, red por red (más rápido desborda la tabla ARP), reintenta inventariados y cruza con ARP; marca hosts fuera del inventario |
| Puertos y servicios | probe | ~75 puertos comunes + declarados en cada conexión asignada; banner/Server; marca puertos no declarados, versiones expuestas, APIs de Docker |
| Segmentación entre redes | probe | Puertos sensibles de cada contenedor; crítico si una BD/caché/almacenamiento comparte red con un contenedor publicado a Internet |
| Exposición hacia el host | probe | Escanea el gateway de cada red (= el servidor). Es la única que puede apuntar al gateway |
| Salida a Internet | host + web | `plataforma.sh egress` levanta un contenedor temporal por red y prueba 1.1.1.1:80/443, 8.8.8.8:53 y SMTP 25/465/587; la web analiza |
| Resolución DNS interna | probe | Alias repetidos entre redes (riesgo solo si un contenedor está en dos de ellas), aislamiento con redes sin probe, resolución externa |
| **Web y HTTP (solo lectura):** | | |
| Cabeceras de seguridad | probe | CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy en GET / |
| Métodos HTTP permitidos | probe | OPTIONS (lee Allow) y TRACE; los métodos de escritura solo se informan, nunca se invocan |
| CORS | probe | GET con Origin ajeno; detecta reflexión del origen y comodín con credenciales |
| Rutas y archivos expuestos | probe | GET a ~28 rutas sensibles (.env, .git, respaldos, /metrics, /docs…), con firma de contenido y descarte de catch-all/SPA |
| Fuga de información | probe | Server, X-Powered-By y trazas de error (sin enviar payloads) |

| **Cifrado (solo lectura):** | | |
| TLS: protocolos y cifrados | probe | Handshakes TLS 1.0–1.3 (cliente con SECLEVEL 0) y sondeo de familias débiles (RC4/3DES/NULL/anón/EXPORT) |
| Certificados | probe | Vigencia, autofirmado, algoritmo de firma, tamaño de clave y coincidencia de nombre (parseo con `cryptography`) |
| Tráfico interno sin cifrar | probe | Postgres (SSLRequest como libpq), Redis (PING), MinIO y HTTP en claro en la red interna |

| **Autenticación y sesiones (solo lectura):** | | |
| Endpoints sin autenticación | probe | GET a ~35 endpoints de API/admin; marca los que devuelven datos (JSON) sin token, descartando SPA y rechazo por Host |
| Sesiones y cookies | probe | Atributos Secure/HttpOnly/SameSite de las cookies fijadas en / y rutas de login |
| **Fuerza bruta (intrusiva, con parámetros):** | | |
| Fuerza bruta y límite de intentos | probe | Envía N intentos de login con un correo INEXISTENTE; detecta 429 (rate limit), 423 (cuenta existe → se detiene) o caída de red (fail2ban). Parámetros: correo, intentos, Host, ruta, formato, campos |
| Enumeración de usuarios | probe | Compara el login de un correo que SÍ existe vs uno que NO (código, mensaje y tiempo); detecta fuga por tiempo (bcrypt solo si la cuenta existe). Pocas muestras, se detiene ante 423/429. Parámetros: ambos correos, muestras, Host, ruta, formato, campos |
| Tokens y JWT | probe | Análisis local del token (alg=none, sin exp, vida larga, datos sensibles) + envío de tokens forjados a un endpoint protegido para ver si el servidor verifica la firma. Parámetros: token, endpoint, envío (cookie/bearer), nombre de cookie, Host |
| MFA y su evasión | probe | Con una cuenta de prueba con MFA activo, verifica que no se pueda saltar el segundo factor: sin cookie de sesión antes del código, token intermedio no sirve como sesión, endpoint protegido inalcanzable con solo la contraseña. Solo evasión (no fuerza bruta del código). Parámetros: correo, contraseña, endpoint, rutas, campos, envío, Host |

Las pruebas que **envían credenciales, intentos de acceso, tokens forjados o
correos** —de Web y HTTP (inyección, XSS, SSRF, traversal, carga de archivos,
deserialización, host header, smuggling, confianza en IP) y de Autenticación
(recuperación de contraseña)—
**no** están implementadas: deben correrse contra un entorno de pruebas
(Demo), no contra producción.

## Próximos pasos

Cada tipo de prueba del menú (`catalogo.py`) tendrá su ejecución en el probe.
Las que necesiten privilegios (por ejemplo ICMP o escaneo SYN) requerirán
agregar la capacidad puntual (`NET_RAW`) solo al probe.

No confundir con `/root/docker/seguridad` (AIDE, Falco, WAF).
