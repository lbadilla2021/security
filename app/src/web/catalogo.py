"""
Catálogo de tipos de prueba, agrupados por categoría. Por ahora solo se
configuran; ninguno se ejecuta.

nivel     auditoria | escaneo | pentest | redteam  (de menos a más intrusivo)
objetivo  conexion   → se aplica a conexiones con protocolo compatible
          red        → se aplica a las subredes del probe
          plataforma → se aplica a la configuración de Docker/host (no usa conexiones)
seccion   generales  → pruebas genéricas: el usuario elige a qué conexiones aplicarlas
          aplicacion → pruebas propias de un sistema concreto (un grupo por aplicación)
intrusivo puede modificar datos, gatillar bloqueos o degradar el servicio:
          pedirá confirmación y conviene correrla contra Demo o una copia.
"""

HTTP = ["http", "https"]
WEB = ["http", "https", "minio"]
TODOS = ["tcp", "http", "https", "postgres", "redis", "minio", "otro"]

NIVELES = {
    "auditoria": {"nombre": "Auditoría", "descripcion": "Revisa configuración, sin atacar."},
    "escaneo": {"nombre": "Escaneo", "descripcion": "Busca debilidades conocidas de forma automática."},
    "pentest": {"nombre": "Pentest", "descripcion": "Intenta explotar la debilidad para demostrar impacto."},
    "redteam": {"nombre": "Red team", "descripcion": "Simula un ataque y mide si se detecta."},
}


def _t(id, nombre, nivel, objetivo, protocolos, descripcion, verifica, intrusivo=None,
       parametros=None, guia=None):
    return {
        "id": id, "nombre": nombre, "nivel": nivel, "objetivo": objetivo,
        "protocolos": protocolos if objetivo == "conexion" else [],
        "descripcion": descripcion, "verifica": verifica,
        "intrusivo": nivel in ("pentest", "redteam") if intrusivo is None else intrusivo,
        "parametros": parametros or [],
        "guia": guia,
    }


GRUPOS = [
    {"id": "red", "nombre": "Red e infraestructura", "tipos": [
        _t("descubrimiento", "Descubrimiento de hosts", "escaneo", "red", [],
           "Qué hosts responden en cada subred interna, más allá del inventario de Docker.",
           ["Hosts no inventariados", "Contenedores huérfanos o desconocidos"]),
        _t("puertos", "Puertos y servicios", "escaneo", "conexion", TODOS,
           "Qué puertos responde cada contenedor y qué servicio y versión hay detrás.",
           ["Puertos abiertos fuera de lo esperado", "Banners y versiones expuestas"]),
        _t("segmentacion", "Segmentación entre redes", "escaneo", "red", [],
           "Desde qué redes se alcanza cada servicio; detecta bases o cachés visibles desde redes que no deberían.",
           ["Alcanzabilidad entre redes Docker", "Servicios internos visibles desde la red del proxy"]),
        _t("gateway_host", "Exposición hacia el host", "escaneo", "red", [],
           "Servicios del propio servidor alcanzables desde los contenedores por el gateway de cada red. Requiere PERMITIR_GATEWAY=true.",
           ["SSH, Docker API u otros servicios del host visibles desde contenedores"]),
        _t("egress", "Salida a Internet", "auditoria", "plataforma", [],
           "Qué contenedores pueden conectarse a Internet y hacia dónde.",
           ["Bases o cachés con salida libre", "Puertos de salida no necesarios (SMTP, etc.)"]),
        _t("dns_interno", "Resolución DNS interna", "auditoria", "red", [],
           "Qué nombres de servicio resuelve cada red y si revelan más de lo necesario.",
           ["Alias y nombres expuestos entre redes"]),
    ]},
    {"id": "web", "nombre": "Web y HTTP", "tipos": [
        _t("cabeceras_http", "Cabeceras de seguridad", "auditoria", "conexion", WEB,
           "Cabeceras de seguridad en las respuestas HTTP.",
           ["CSP, HSTS, X-Frame-Options, nosniff", "Referrer-Policy, Permissions-Policy"]),
        _t("metodos_http", "Métodos HTTP permitidos", "escaneo", "conexion", WEB,
           "Métodos aceptados más allá de los necesarios.",
           ["TRACE, PUT, DELETE, OPTIONS habilitados"]),
        _t("cors", "CORS", "escaneo", "conexion", WEB,
           "Política de origen cruzado del servicio.",
           ["Access-Control-Allow-Origin: * con credenciales", "Origen reflejado sin validar"]),
        _t("rutas_expuestas", "Rutas y archivos expuestos", "escaneo", "conexion", WEB,
           "Archivos que nunca deberían servirse.",
           ["/.env, /.git/config", "Respaldos (*.sql, *.zip, *.bak)", "/docs, /openapi.json"]),
        _t("fuga_informacion", "Fuga de información", "escaneo", "conexion", WEB,
           "Datos internos en banners, errores y respuestas.",
           ["Cabecera Server / X-Powered-By", "Stack traces y rutas internas en errores", "Modo debug activo"]),
        _t("suplantacion_ip", "Confianza en cabeceras de IP", "pentest", "conexion", HTTP,
           "Si el servicio cree un X-Forwarded-For / X-Real-IP enviado por cualquier contenedor de la red.",
           ["Evasión de rate limit", "Evasión de listas de IP permitidas", "IP falsa en auditoría"]),
        _t("host_header", "Host header injection", "pentest", "conexion", HTTP,
           "Uso del encabezado Host para generar enlaces o decidir el tenant.",
           ["Enlaces de recuperación con dominio del atacante", "Envenenamiento de caché"]),
        _t("smuggling", "Request smuggling", "pentest", "conexion", HTTP,
           "Desincronización entre proxy (NPM/WAF/nginx) y backend.",
           ["CL.TE / TE.CL", "Evasión del WAF"]),
        _t("inyeccion", "Inyección (SQL, comandos, plantillas)", "pentest", "conexion", HTTP,
           "Entradas que llegan sin sanitizar a SQL, shell o motores de plantillas.",
           ["SQLi en filtros y búsquedas", "Inyección de comandos", "SSTI en plantillas de documentos"]),
        _t("xss", "XSS", "pentest", "conexion", HTTP,
           "Contenido de usuario que se ejecuta en el navegador de otro.",
           ["XSS almacenado en nombres y notas", "XSS reflejado en parámetros"]),
        _t("ssrf", "SSRF", "pentest", "conexion", HTTP,
           "Funciones que hacen peticiones a URLs dadas por el usuario.",
           ["Acceso a servicios internos vía la app", "Acceso a metadatos del proveedor"]),
        _t("path_traversal", "Path traversal", "pentest", "conexion", WEB,
           "Lectura de archivos fuera de la carpeta prevista.",
           ["../ en descargas y claves de almacenamiento"]),
        _t("carga_archivos", "Carga de archivos", "pentest", "conexion", HTTP,
           "Validación de los archivos que se suben.",
           ["Tipos no permitidos", "Archivos maliciosos (PDF con JS, polyglots)", "Tamaños excesivos"]),
        _t("deserializacion", "Deserialización insegura", "pentest", "conexion", HTTP,
           "Objetos serializados aceptados desde el cliente.",
           ["pickle / YAML inseguro", "Tokens con payload ejecutable"]),
    ]},
    {"id": "cifrado", "nombre": "Cifrado", "tipos": [
        _t("tls", "TLS: protocolos y cifrados", "auditoria", "conexion", ["https"],
           "Versiones de protocolo y suites de cifrado aceptadas.",
           ["TLS 1.0/1.1 habilitado", "Cifrados débiles"]),
        _t("certificados", "Certificados", "auditoria", "conexion", ["https"],
           "Validez y cadena del certificado.",
           ["Vencido o por vencer", "Autofirmado", "Nombre no coincide"]),
        _t("trafico_claro", "Tráfico interno sin cifrar", "auditoria", "conexion", TODOS,
           "Servicios que transportan credenciales o datos personales en texto plano dentro de la red.",
           ["Postgres sin SSL", "Redis sin TLS", "HTTP interno con tokens"]),
    ]},
    {"id": "autenticacion", "nombre": "Autenticación y sesiones", "tipos": [
        _t("autenticacion", "Endpoints sin autenticación", "escaneo", "conexion", HTTP,
           "Rutas de API que responden sin token.",
           ["Endpoints de datos abiertos", "Endpoints de administración abiertos"]),
        _t("fuerza_bruta", "Fuerza bruta y límite de intentos", "pentest", "conexion", HTTP,
           "Envía varios intentos de login con un correo inexistente para ver si el endpoint frena la fuerza bruta.",
           ["Límite de intentos por IP (429)", "Bloqueo de cuenta (423)", "Bloqueo de red (fail2ban)"],
           parametros=[
             {"id": "email", "etiqueta": "Correo objetivo (debe NO existir)", "tipo": "texto", "requerido": True,
              "generar": "email_falso",
              "ayuda": "Un correo que NO esté en la base de datos. Nunca el de un usuario real: si la cuenta existe, "
                       "la prueba la bloquea y se detiene. Debe tener formato válido (dominio real como gmail.com)."},
             {"id": "intentos", "etiqueta": "Número de intentos", "tipo": "numero", "default": 12, "min": 1, "max": 50,
              "ayuda": "Cuántos intentos enviar. Se detiene antes si aparece el bloqueo."},
             {"id": "host_header", "etiqueta": "Encabezado Host (opcional)", "tipo": "texto", "default": "",
              "ayuda": "Si la app valida el Host, indícalo. Para payroll: app.automatizaml.cl. Vacío = el host de la conexión."},
             {"id": "ruta", "etiqueta": "Ruta del login", "tipo": "texto", "default": "/api/v1/auth/login",
              "ayuda": "Endpoint que recibe el POST de login."},
             {"id": "formato", "etiqueta": "Formato del cuerpo", "tipo": "select", "opciones": ["json", "form"], "default": "json"},
             {"id": "campo_usuario", "etiqueta": "Campo del usuario", "tipo": "texto", "default": "email"},
             {"id": "campo_password", "etiqueta": "Campo de la contraseña", "tipo": "texto", "default": "password"},
           ]),
        _t("enumeracion_usuarios", "Enumeración de usuarios", "escaneo", "conexion", HTTP,
           "Compara la respuesta del login para un correo que existe y otro que no (código, mensaje y tiempo).",
           ["Código distinto según exista la cuenta", "Mensaje distinto", "Tiempo distinto (bcrypt solo si existe)"],
           intrusivo=True,  # envía algunos intentos de login a una cuenta real
           parametros=[
             {"id": "email_existe", "etiqueta": "Correo que SÍ existe (de prueba)", "tipo": "texto", "requerido": True,
              "ayuda": "Una cuenta real, idealmente de prueba/Demo. Recibirá unos pocos intentos fallidos (bajo el "
                       "umbral de bloqueo); si corres la prueba varias veces sin que inicie sesión, podría bloquearse."},
             {"id": "email_no_existe", "etiqueta": "Correo que NO existe", "tipo": "texto", "requerido": True,
              "generar": "email_falso", "ayuda": "Un correo que no esté en la base de datos. Formato válido (gmail.com, etc.)."},
             {"id": "muestras", "etiqueta": "Muestras por correo", "tipo": "numero", "default": 3, "min": 2, "max": 4,
              "ayuda": "Peticiones por correo para medir el tiempo. Bajo a propósito, para no bloquear la cuenta real."},
             {"id": "host_header", "etiqueta": "Encabezado Host (opcional)", "tipo": "texto", "default": "",
              "ayuda": "Si la app valida el Host. Para payroll: app.automatizaml.cl."},
             {"id": "ruta", "etiqueta": "Ruta del login", "tipo": "texto", "default": "/api/v1/auth/login"},
             {"id": "formato", "etiqueta": "Formato del cuerpo", "tipo": "select", "opciones": ["json", "form"], "default": "json"},
             {"id": "campo_usuario", "etiqueta": "Campo del usuario", "tipo": "texto", "default": "email"},
             {"id": "campo_password", "etiqueta": "Campo de la contraseña", "tipo": "texto", "default": "password"},
           ],
           guia={
             "intro": "Detecta si el login revela qué correos están registrados. Compara la respuesta de un correo "
                      "que SÍ existe con la de uno que NO, en tres cosas: el código HTTP, el mensaje de error y el "
                      "tiempo de respuesta. Si alguna difiere, un atacante puede averiguar qué cuentas existen.",
             "pasos": [
               "En «Correo que SÍ existe» pon una cuenta real, idealmente de prueba (por ejemplo una de Demo). "
               "Recibirá unos pocos intentos de login fallidos, siempre por debajo del umbral de bloqueo.",
               "En «Correo que NO existe» deja el que viene precargado, o pon otro que no esté en la base. No se "
               "envía ningún correo: solo se intenta iniciar sesión con una contraseña incorrecta.",
               "Si la aplicación valida el encabezado Host, complétalo. Para payroll: app.automatizaml.cl.",
               "Revisa la ruta del login (por defecto /api/v1/auth/login), el formato y los nombres de los campos.",
               "Abajo, marca la conexión del login que quieres probar y pulsa «Ejecutar prueba». Pedirá confirmación.",
             ],
             "lectura": [
               "Si el código, el mensaje o el tiempo difieren entre los dos correos, hay enumeración y se reporta "
               "como hallazgo (código y mensaje son graves; el tiempo, medio).",
               "«Sin enumeración detectable» significa que las dos respuestas son iguales. Ojo: si el correo que "
               "pusiste como existente en realidad no existe, también saldría «sin diferencia». Verifica que exista.",
               "La fuga por tiempo aparece cuando la app solo calcula el hash de la contraseña si la cuenta existe "
               "(entonces la existente tarda más). La prueba la detecta midiendo varios intentos.",
               "La prueba se detiene sola si ve un bloqueo (423 de cuenta o 429 por IP), para no afectar la cuenta real.",
             ],
           }),
        _t("tokens_jwt", "Tokens y JWT", "pentest", "conexion", HTTP,
           "Analiza un JWT de tu sesión y, si das un endpoint, prueba si el servidor verifica la firma.",
           ["alg=none aceptado", "Firma no verificada", "Token sin expiración o de vida larga", "Datos sensibles en el payload"],
           parametros=[
             {"id": "token", "etiqueta": "JWT (token de tu sesión)", "tipo": "texto", "requerido": True,
              "ayuda": "Pega un token real de tu sesión (en payroll está en la cookie access_token; míralo en el "
                       "navegador → Herramientas de desarrollo → Aplicación → Cookies). Se analiza localmente, no se publica."},
             {"id": "endpoint", "etiqueta": "Endpoint protegido (opcional)", "tipo": "texto", "default": "/api/v1/auth/me",
              "ayuda": "Ruta que exige sesión (devuelve 200 con token válido, 401 sin él). Con esto se prueba si "
                       "acepta tokens falsos. Vacío = solo análisis local, sin enviar nada."},
             {"id": "envio", "etiqueta": "Cómo viaja el token", "tipo": "select", "opciones": ["cookie", "bearer"], "default": "cookie",
              "ayuda": "payroll usa cookie. «bearer» = cabecera Authorization: Bearer."},
             {"id": "nombre_cookie", "etiqueta": "Nombre de la cookie", "tipo": "texto", "default": "access_token",
              "ayuda": "Solo si el token viaja por cookie."},
             {"id": "host_header", "etiqueta": "Encabezado Host (opcional)", "tipo": "texto", "default": "",
              "ayuda": "Si la app valida el Host. Para payroll: app.automatizaml.cl."},
           ],
           guia={
             "intro": "Un JWT tiene tres partes (encabezado.payload.firma) separadas por puntos. El encabezado y el "
                      "payload son solo base64: cualquiera los lee. La seguridad depende de que el servidor verifique "
                      "la firma. Esta prueba revisa el contenido del token y, si le das un endpoint, comprueba si el "
                      "servidor acepta tokens manipulados.",
             "pasos": [
               "Inicia sesión en la aplicación con tu cuenta de prueba.",
               "Copia el token: en payroll está en la cookie «access_token» (navegador → Herramientas de desarrollo "
               "→ Aplicación/Almacenamiento → Cookies). Pégalo en «JWT».",
               "Para la parte activa, deja el endpoint protegido (payroll: /api/v1/auth/me), elige «cookie» y el "
               "nombre access_token, y pon el Host app.automatizaml.cl. Si lo dejas vacío, solo se hace análisis local.",
               "Marca abajo la conexión del servicio y pulsa «Ejecutar prueba».",
             ],
             "lectura": [
               "El análisis local marca: alg=none, token sin expiración, vida demasiado larga o datos sensibles en el payload.",
               "La parte activa envía tu token real (base) y varias versiones falsas (alg=none, firma alterada, payload "
               "alterado con privilegios de admin). Si alguna falsa es «aceptada», es crítico: el servidor no verifica la firma.",
               "«Rechazó todos los tokens manipulados» = el servidor valida bien la firma.",
               "Si el token real no es aceptado (base), revisa que esté vigente y que el endpoint, el envío y el Host sean correctos.",
             ],
           }),
        _t("sesiones_cookies", "Sesiones y cookies", "auditoria", "conexion", HTTP,
           "Atributos y ciclo de vida de las sesiones.",
           ["Secure, HttpOnly, SameSite", "Cierre de sesión efectivo", "Fijación de sesión"]),
        _t("mfa", "MFA y su evasión", "pentest", "conexion", HTTP,
           "Comprueba si se puede saltar el segundo factor usando una cuenta de prueba con MFA activo.",
           ["Sesión entregada antes del segundo factor", "Token intermedio usado como sesión", "Endpoint accesible con solo la contraseña"],
           parametros=[
             {"id": "email", "etiqueta": "Correo (cuenta con MFA activo)", "tipo": "texto", "requerido": True,
              "ayuda": "Una cuenta de prueba que tenga el segundo factor activado. Se usa su contraseña una sola vez."},
             {"id": "password", "etiqueta": "Contraseña", "tipo": "texto", "requerido": True,
              "ayuda": "La contraseña de esa cuenta. No se guarda; solo se usa para el primer paso del login."},
             {"id": "endpoint", "etiqueta": "Endpoint protegido", "tipo": "texto", "default": "/api/v1/auth/me",
              "ayuda": "Ruta que exige sesión completa. Se comprueba que NO se alcance sin pasar el segundo factor."},
             {"id": "ruta_login", "etiqueta": "Ruta del login", "tipo": "texto", "default": "/api/v1/auth/login"},
             {"id": "campo_mfa_requerido", "etiqueta": "Campo «MFA requerido»", "tipo": "texto", "default": "mfa_requerido",
              "ayuda": "Campo del JSON de login que indica que falta el segundo factor."},
             {"id": "campo_mfa_token", "etiqueta": "Campo del token intermedio", "tipo": "texto", "default": "mfa_token",
              "ayuda": "Campo del JSON con el token temporal entre la contraseña y el código."},
             {"id": "envio", "etiqueta": "Cómo viaja el token", "tipo": "select", "opciones": ["cookie", "bearer"], "default": "cookie"},
             {"id": "nombre_cookie", "etiqueta": "Nombre de la cookie", "tipo": "texto", "default": "access_token"},
             {"id": "host_header", "etiqueta": "Encabezado Host (opcional)", "tipo": "texto", "default": "",
              "ayuda": "Para payroll: app.automatizaml.cl."},
           ],
           guia={
             "intro": "El MFA añade un segundo paso (un código) después de la contraseña. Esta prueba verifica que ese "
                      "paso no se pueda saltar: que con solo la contraseña no se obtenga una sesión ni acceso a rutas "
                      "protegidas. Necesita una cuenta de prueba que tenga el MFA activado.",
             "pasos": [
               "Activa el MFA en una cuenta de prueba (en Demo, no en una cuenta real).",
               "Pon su correo y contraseña. El login se hace una sola vez, así que no bloquea la cuenta.",
               "Deja el endpoint protegido (payroll: /api/v1/auth/me) y el Host app.automatizaml.cl.",
               "Marca abajo la conexión del servicio y pulsa «Ejecutar prueba».",
             ],
             "lectura": [
               "La prueba hace el primer paso (contraseña) y verifica tres cosas: que el login no entregue cookie de "
               "sesión antes del código, que el token intermedio no sirva como sesión, y que el endpoint protegido no "
               "se alcance con solo la contraseña.",
               "Cualquiera de esas tres que funcione es crítica: el segundo factor se puede saltar.",
               "«No se encontró forma de evadir el segundo factor» = el MFA se exige correctamente.",
               "Si la cuenta no pide segundo factor, actívalo primero: sin MFA activo no hay nada que evadir.",
               "No cubre fuerza bruta del código ni su reutilización: eso requiere el secreto TOTP de la cuenta.",
             ],
           }),
        _t("recuperacion_clave", "Recuperación de contraseña", "pentest", "conexion", HTTP,
           "Robustez del flujo de recuperación.",
           ["Tokens predecibles o reutilizables", "Vigencia del enlace"]),
    ]},
    {"id": "autorizacion", "nombre": "Autorización", "tipos": [
        _t("rbac", "Control de acceso por rol", "pentest", "conexion", HTTP,
           "Si cada rol solo puede hacer lo que su permiso indica.",
           ["Acciones de admin con rol básico", "Permisos verificados solo en el front"]),
        _t("idor", "IDOR (objetos ajenos)", "pentest", "conexion", HTTP,
           "Acceso a registros de otro usuario cambiando un identificador.",
           ["Documentos o registros de otro usuario", "Descargas por identificador predecible"]),
        _t("aislamiento_tenants", "Aislamiento entre tenants", "pentest", "conexion", HTTP,
           "Si un tenant puede ver o modificar datos de otro (RLS).",
           ["Lectura cruzada entre tenants", "Escritura cruzada entre tenants"]),
        _t("escalada_privilegios", "Escalada de privilegios", "pentest", "conexion", HTTP,
           "Si un usuario puede elevar su propio rol.",
           ["Auto-asignación de roles", "Campos de rol aceptados en el payload"]),
        _t("logica_negocio", "Lógica de negocio", "pentest", "conexion", HTTP,
           "Casos límite que la aplicación no debería permitir.",
           ["Montos o fechas inválidas", "Estados imposibles", "Saltarse pasos o aprobaciones"]),
    ]},
    {"id": "datos", "nombre": "Datos y almacenamiento", "tipos": [
        _t("bases_datos", "Bases de datos", "escaneo", "conexion", ["postgres"],
           "Acceso y privilegios en PostgreSQL.",
           ["Acceso sin contraseña o por defecto", "Usuario de la app con privilegios de más", "Versión expuesta"]),
        _t("cache_colas", "Cachés y colas (Redis)", "escaneo", "conexion", ["redis"],
           "Acceso a Redis y lo que guarda.",
           ["Redis sin contraseña", "Sesiones o tokens legibles", "Comandos peligrosos habilitados"]),
        _t("almacenamiento", "Almacenamiento de objetos", "escaneo", "conexion", ["minio", "http", "https"],
           "Buckets de MinIO/S3 listables o descargables sin credenciales.",
           ["Listado anónimo de buckets", "Objetos públicos", "Consola alcanzable"]),
        _t("vectoriales", "Bases vectoriales (Qdrant)", "escaneo", "conexion", HTTP,
           "Acceso a la API de Qdrant.",
           ["API sin clave", "Colecciones de otros tenants legibles"]),
        _t("respaldos", "Respaldos expuestos o sin cifrar", "auditoria", "plataforma", [],
           "Dónde quedan los respaldos y si están protegidos.",
           ["Dumps sin cifrar en disco", "Respaldos accesibles por web o desde otros contenedores"]),
    ]},
    {"id": "administracion", "nombre": "Administración y observabilidad", "tipos": [
        _t("paneles_admin", "Paneles de administración", "escaneo", "conexion", HTTP,
           "pgAdmin, Grafana, NPM, Portainer y consolas similares.",
           ["Panel accesible sin login", "Credenciales por defecto"]),
        _t("metricas_trazas", "Métricas y trazas", "escaneo", "conexion", HTTP,
           "Prometheus, Jaeger y endpoints /metrics.",
           ["Métricas abiertas", "Trazas con datos personales o tokens"]),
        _t("automatizacion", "Automatización (n8n)", "escaneo", "conexion", HTTP,
           "Webhooks y credenciales de los flujos.",
           ["Webhooks sin autenticación", "Credenciales expuestas en flujos"]),
    ]},
    {"id": "contenedores", "nombre": "Contenedores", "tipos": [
        _t("config_contenedores", "Configuración de contenedores", "auditoria", "plataforma", [],
           "Privilegios con que corre cada contenedor.",
           ["Corre como root", "privileged / capabilities de más", "Sin límites de recursos"]),
        _t("secretos", "Secretos expuestos", "auditoria", "plataforma", [],
           "Claves en variables de entorno, imágenes o logs.",
           ["Secretos en docker inspect", "Secretos en capas de la imagen", "Tokens en logs"]),
        _t("vulnerabilidades_imagenes", "Vulnerabilidades en imágenes", "escaneo", "plataforma", [],
           "CVE conocidos en imágenes y dependencias.",
           ["Paquetes del sistema", "Dependencias Python / Node"]),
        _t("montajes", "Montajes peligrosos", "auditoria", "plataforma", [],
           "Rutas del host montadas en contenedores.",
           ["docker.sock montado", "Rutas sensibles del host con escritura"]),
    ]},
    {"id": "disponibilidad", "nombre": "Disponibilidad y detección", "tipos": [
        _t("rate_limit", "Rate limiting y límites de tamaño", "escaneo", "conexion", HTTP,
           "Si el servicio limita ráfagas y cuerpos grandes.",
           ["Límite de peticiones por IP", "Tamaño máximo de cuerpo"], intrusivo=True),
        _t("conexiones_lentas", "Conexiones lentas", "pentest", "conexion", HTTP,
           "Resistencia a conexiones que se mantienen abiertas (estilo Slowloris), de forma controlada.",
           ["Timeouts de lectura", "Límite de conexiones por cliente"]),
        _t("deteccion", "Validación de alertas", "redteam", "plataforma", [],
           "Si Falco, el WAF y fail2ban detectan y alertan los ataques simulados.",
           ["Alertas generadas", "Tiempo hasta la alerta", "Ataques sin detectar"]),
    ]},
    # ── Pruebas por aplicación ─────────────────────────────────────────────
    {"id": "app_firma", "seccion": "aplicacion", "nombre": "Firma electrónica",
     "descripcion": "firma.automatizaml.cl (módulo firma_cl de payroll).",
     "tipos": [
        _t("integridad_documentos", "Integridad de documentos", "auditoria", "conexion", HTTP,
           "Hash, cadena de firmas y sellado de cierre.",
           ["Verificación pública consistente", "Documento alterado detectado", "Sello PAdES válido"]),
        _t("flujo_firma", "Flujo de firma", "pentest", "conexion", HTTP,
           "Robustez del proceso de firma.",
           ["Reutilización de enlaces u OTP", "Firmar fuera de orden", "Firmar un sobre cancelado"]),
    ]},
]

# Pruebas con ejecución implementada. Las de plataforma necesitan que el host
# recolecte los datos antes (comando en RECOLECCION).
IMPLEMENTADAS = {"descubrimiento", "puertos", "segmentacion", "gateway_host", "egress", "dns_interno",
                 "cabeceras_http", "metodos_http", "cors", "rutas_expuestas", "fuga_informacion",
                 "tls", "certificados", "trafico_claro",
                 "autenticacion", "sesiones_cookies", "fuerza_bruta", "enumeracion_usuarios", "tokens_jwt", "mfa"}
RECOLECCION = {"egress": "./scripts/plataforma.sh egress"}

for _g in GRUPOS:
    _g.setdefault("seccion", "generales")
    for _t in _g["tipos"]:
        _t["implementada"] = _t["id"] in IMPLEMENTADAS
        _t["recoleccion"] = RECOLECCION.get(_t["id"])
        _t.setdefault("parametros", [])
        _t.setdefault("guia", None)

TIPOS = [{**t, "grupo": g["id"]} for g in GRUPOS for t in g["tipos"]]
IDS_TIPOS = {t["id"] for t in TIPOS}
assert len(IDS_TIPOS) == len(TIPOS), "ids de tipo duplicados"
