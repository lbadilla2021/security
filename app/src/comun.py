"""Validaciones, servicios conocidos y formato de resultados (web y probe)."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Literal

# Nombre DNS (contenedor/servicio) o IPv4. Sin esquemas, rutas ni puertos.
# (Sin lookahead: el motor de pydantic no lo soporta; el largo lo limita max_length.)
HOST_RE = r"^([A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*$"
HOST_PATRON = re.compile(HOST_RE)

Protocolo = Literal["tcp", "http", "https", "postgres", "redis", "minio", "otro"]
PROTOCOLOS = ["tcp", "http", "https", "postgres", "redis", "minio", "otro"]


# ── Servicios conocidos por puerto ──────────────────────────────────────────
# clase: bd | cache | vectorial | almacenamiento | docker | admin | metricas |
#        remoto | inseguro | correo | web | otro

SERVICIOS: dict[int, tuple[str, str]] = {
    21: ("FTP", "inseguro"), 22: ("SSH", "remoto"), 23: ("Telnet", "inseguro"),
    25: ("SMTP", "correo"), 53: ("DNS", "otro"), 80: ("HTTP", "web"),
    81: ("Admin NPM", "admin"), 110: ("POP3", "correo"), 111: ("rpcbind", "inseguro"),
    143: ("IMAP", "correo"), 443: ("HTTPS", "web"), 445: ("SMB", "inseguro"),
    465: ("SMTPS", "correo"), 587: ("SMTP submission", "correo"), 993: ("IMAPS", "correo"),
    995: ("POP3S", "correo"), 1433: ("SQL Server", "bd"), 1521: ("Oracle", "bd"),
    2049: ("NFS", "almacenamiento"), 2375: ("Docker API", "docker"),
    2376: ("Docker API TLS", "docker"), 2379: ("etcd", "bd"), 3000: ("HTTP 3000 (Grafana, APIs Node)", "admin"),
    3001: ("HTTP alt", "web"), 3306: ("MySQL", "bd"), 3310: ("ClamAV", "otro"),
    3389: ("RDP", "remoto"), 4317: ("OTLP gRPC", "metricas"), 4318: ("OTLP HTTP", "metricas"),
    5000: ("HTTP alt", "web"), 5050: ("pgAdmin", "admin"), 5432: ("PostgreSQL", "bd"),
    5601: ("Kibana", "admin"), 5672: ("AMQP", "cache"), 5678: ("n8n", "admin"),
    5900: ("VNC", "remoto"), 6333: ("Qdrant", "vectorial"), 6334: ("Qdrant gRPC", "vectorial"),
    6379: ("Redis", "cache"), 6432: ("PgBouncer", "bd"), 6443: ("Kubernetes API", "docker"),
    6831: ("Jaeger agent", "metricas"), 7000: ("HTTP alt", "web"), 8000: ("HTTP alt", "web"),
    8001: ("HTTP alt", "web"), 8008: ("HTTP alt", "web"), 8025: ("MailHog", "admin"),
    8080: ("HTTP alt", "web"), 8081: ("HTTP alt", "web"), 8088: ("HTTP alt", "web"),
    8200: ("Vault", "admin"), 8443: ("HTTPS alt", "web"), 8500: ("Consul", "admin"),
    8888: ("HTTP alt", "web"), 9000: ("MinIO API", "almacenamiento"),
    9001: ("MinIO consola", "admin"), 9042: ("Cassandra", "bd"), 9090: ("Prometheus", "metricas"),
    9093: ("Alertmanager", "metricas"), 9100: ("Node exporter", "metricas"),
    9200: ("Elasticsearch", "bd"), 9300: ("Elasticsearch nodos", "bd"), 9411: ("Zipkin", "metricas"),
    9443: ("Portainer", "admin"), 10250: ("Kubelet", "docker"), 11211: ("Memcached", "cache"),
    14250: ("Jaeger gRPC", "metricas"), 14268: ("Jaeger HTTP", "metricas"),
    15672: ("RabbitMQ admin", "admin"), 16686: ("Jaeger UI", "metricas"), 27017: ("MongoDB", "bd"),
}

PUERTOS_COMUNES = sorted(SERVICIOS)

# Clases que no deberían ser alcanzables desde redes con contenedores expuestos.
CLASES_CRITICAS = {"bd", "cache", "vectorial", "almacenamiento", "docker", "inseguro"}
CLASES_SENSIBLES = {"admin", "metricas", "remoto"}

NOMBRE_CLASE = {
    "bd": "base de datos", "cache": "caché/cola", "vectorial": "base vectorial",
    "almacenamiento": "almacenamiento", "docker": "API de orquestación", "admin": "panel de administración",
    "metricas": "métricas/trazas", "remoto": "acceso remoto", "inseguro": "protocolo inseguro",
    "correo": "correo", "web": "web", "otro": "otro",
}


def servicio(puerto: int) -> tuple[str, str]:
    return SERVICIOS.get(puerto, ("desconocido", "otro"))


# ── Resultado de una prueba ─────────────────────────────────────────────────

SEVERIDADES = ["alta", "media", "baja", "info"]


class ErrorPrueba(Exception):
    """La prueba no puede correr (falta inventario, conexiones, etc.)."""


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Resultado:
    def __init__(self, tipo: str):
        self.tipo = tipo
        self.inicio = _ahora()
        self._t0 = time.monotonic()
        self.resumen = ""
        self.metricas: list[dict] = []
        self.hallazgos: list[dict] = []
        self.tablas: list[dict] = []
        self.notas: list[str] = []

    def metrica(self, nombre: str, valor) -> None:
        self.metricas.append({"nombre": nombre, "valor": valor})

    def hallazgo(self, severidad: str, titulo: str, detalle: str = "",
                 objetivo: str = "", recomendacion: str = "") -> None:
        assert severidad in SEVERIDADES
        self.hallazgos.append({"severidad": severidad, "titulo": titulo, "detalle": detalle,
                               "objetivo": objetivo, "recomendacion": recomendacion})

    def tabla(self, titulo: str, columnas: list[str], filas: list[list]) -> None:
        self.tablas.append({"titulo": titulo, "columnas": columnas, "filas": filas})

    def nota(self, texto: str) -> None:
        self.notas.append(texto)

    def final(self) -> dict:
        orden = {s: i for i, s in enumerate(SEVERIDADES)}
        self.hallazgos.sort(key=lambda h: orden[h["severidad"]])
        conteo = {s: sum(1 for h in self.hallazgos if h["severidad"] == s) for s in SEVERIDADES}
        return {
            "tipo": self.tipo, "inicio": self.inicio, "fin": _ahora(),
            "duracion_s": round(time.monotonic() - self._t0, 1),
            "resumen": self.resumen, "conteo": conteo, "metricas": self.metricas,
            "hallazgos": self.hallazgos, "tablas": self.tablas, "notas": self.notas,
        }
