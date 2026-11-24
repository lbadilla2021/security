#!/usr/bin/env bash
# Recolección de datos de plataforma (pruebas con objetivo "plataforma").
# Corre en el HOST: la web solo analiza lo que este script deja en data/plataforma/.
#
#   ./scripts/plataforma.sh egress     Salida a Internet desde cada red Docker
#
# egress: por cada red Docker definida por el usuario levanta un contenedor
# temporal (imagen security-tools:local, sin privilegios, solo lectura, se
# borra al terminar) y prueba conexiones TCP salientes a destinos públicos
# fijos. No envía datos: solo abre y cierra la conexión.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/data/plataforma"
IMAGEN="security-tools:local"
install -d -o 10001 -g 10001 -m 700 "$OUT"

egress() {
  local py='
import json, socket, concurrent.futures as cf
def tcp(host, port):
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        return {"ok": False, "detalle": "sin DNS"}
    try:
        socket.create_connection((ip, port), timeout=4).close()
        return {"ok": True, "detalle": ip}
    except OSError as e:
        return {"ok": False, "detalle": type(e).__name__}
def dns():
    try:
        return {"ok": True, "detalle": socket.gethostbyname("example.com")}
    except OSError as e:
        return {"ok": False, "detalle": type(e).__name__}
pruebas = {
    "dns": dns,
    "https": lambda: tcp("1.1.1.1", 443),
    "http": lambda: tcp("1.1.1.1", 80),
    "dns_externo_tcp": lambda: tcp("8.8.8.8", 53),
    "smtp_25": lambda: tcp("smtp.gmail.com", 25),
    "smtp_465": lambda: tcp("smtp.gmail.com", 465),
    "smtp_587": lambda: tcp("smtp.gmail.com", 587),
}
with cf.ThreadPoolExecutor(8) as ex:
    fut = {k: ex.submit(f) for k, f in pruebas.items()}
    print(json.dumps({k: f.result() for k, f in fut.items()}))
'
  local tmp; tmp="$(mktemp)"
  echo '{}' > "$tmp"
  while read -r red; do
    [[ -z "$red" || "$red" == "security-ui" ]] && continue
    local nombre="security-egress-$(echo "$red" | tr -c 'a-zA-Z0-9_.-' '-' | cut -c1-40)"
    local info; info="$(docker network inspect "$red" | jq '.[0] | {interna: .Internal, subred: (.IPAM.Config[0].Subnet // null),
                         contenedores: ([(.Containers // {})[] | .Name] | map(select(startswith("security-") | not)) | sort)}')"
    local resultado
    if ! resultado="$(timeout 60 docker run --rm --name "$nombre" --network "$red" \
          --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
          --memory 64m --pids-limit 32 --log-driver none --entrypoint python "$IMAGEN" -c "$py" 2>/dev/null)"; then
      resultado='{"error": {"ok": false, "detalle": "no se pudo ejecutar el contenedor de prueba"}}'
    fi
    jq --arg red "$red" --argjson info "$info" --argjson r "$resultado" '.[$red] = ($info + {resultados: $r})' "$tmp" > "$tmp.n" && mv "$tmp.n" "$tmp"
    echo "  $red: $(echo "$resultado" | jq -r 'to_entries | map("\(.key)=\(if .value.ok then "sí" else "no" end)") | join(" ")')"
  done < <(docker network ls --filter type=custom --format '{{.Name}}' | sort)

  jq --arg fecha "$(date -u +%FT%TZ)" '{generado: $fecha, redes: .}' "$tmp" > "$OUT/egress.json"
  rm -f "$tmp"
  chown 10001:10001 "$OUT/egress.json"; chmod 640 "$OUT/egress.json"
  echo "Resultado → $OUT/egress.json"
}

case "${1:-}" in
  egress) echo "Salida a Internet por red:"; egress ;;
  *) echo "Uso: $0 egress" >&2; exit 2 ;;
esac
