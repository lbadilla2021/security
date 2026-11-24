#!/usr/bin/env bash
# Genera data/inventario.json: redes a las que está unido security-probe, los
# contenedores de cada una (IP, puertos declarados, nombres DNS, puertos
# publicados en el host) y, aparte, los nombres de las redes donde el probe NO
# está (para comprobar que no se ven).
#
# Corre en el HOST a propósito: así ningún contenedor necesita docker.sock
# (que equivale a root en el servidor). Volver a correrlo cuando cambien los
# contenedores:  ./scripts/inventario.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
SALIDA="$DIR/data/inventario.json"
PROBE="security-probe"

if ! docker inspect "$PROBE" >/dev/null 2>&1; then
  echo "El contenedor $PROBE no existe. Levanta primero: docker compose up -d" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

docker inspect "$PROBE" -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' | sed '/^$/d' > "$TMP/unidas"
docker network ls --filter type=custom --format '{{.Name}}' | grep -vxF -f "$TMP/unidas" | grep -v '^security-ui$' > "$TMP/otras" || true

redes_json() { local lista=("$@"); ((${#lista[@]})) && docker network inspect "${lista[@]}" || echo '[]'; }
mapfile -t UNIDAS < "$TMP/unidas"
mapfile -t OTRAS < "$TMP/otras"
redes_json "${UNIDAS[@]}" > "$TMP/redes_unidas.json"
redes_json "${OTRAS[@]+"${OTRAS[@]}"}" > "$TMP/redes_otras.json"

# Detalle de cada contenedor: puertos declarados, DNS por red, publicaciones.
mapfile -t IDS < <(jq -r '.[].Containers // {} | keys[]' "$TMP/redes_unidas.json" "$TMP/redes_otras.json" | sort -u)
if ((${#IDS[@]})); then
  docker inspect "${IDS[@]}" | jq 'map({key: .Id, value: {
      puertos: ((.Config.ExposedPorts // {}) | keys | map(sub("/tcp$"; "")) | unique | sort_by(tonumber? // 0)),
      dns: ((.NetworkSettings.Networks // {}) | with_entries(.value = ((.value.DNSNames // .value.Aliases // []) | unique))),
      publicados: [(.NetworkSettings.Ports // {}) | to_entries[] | select(.value != null) | .key as $p
                   | .value[] | "\(.HostIp):\(.HostPort)->\($p)"],
      publico: ([(.NetworkSettings.Ports // {}) | to_entries[] | select(.value != null) | .value[]
                 | select(.HostIp == "" or .HostIp == "0.0.0.0" or .HostIp == "::")] | length > 0)
    }}) | from_entries' > "$TMP/detalle.json"
else
  echo '{}' > "$TMP/detalle.json"
fi

jq -n --slurpfile u "$TMP/redes_unidas.json" --slurpfile o "$TMP/redes_otras.json" \
      --slurpfile d "$TMP/detalle.json" --arg probe "$PROBE" --arg fecha "$(date -u +%FT%TZ)" '
  def contenedores($red):
    ($red.Containers // {}) | to_entries
    | map(select(.value.Name != $probe) | . as $e | ($d[0][$e.key] // {}) as $x | {
        nombre: $e.value.Name,
        ip: ($e.value.IPv4Address | split("/")[0]),
        puertos: ($x.puertos // []),
        dns: (($x.dns // {})[$red.Name] // [$e.value.Name]),
        publico: ($x.publico // false),
        publicados: ($x.publicados // [])
      })
    | sort_by(.nombre);
  {
    generado: $fecha,
    redes: ($u[0] | map({key: .Name, value: {
      subred: (.IPAM.Config[0].Subnet // null), gateway: (.IPAM.Config[0].Gateway // null),
      interna: .Internal, contenedores: contenedores(.)
    }}) | from_entries),
    otras_redes: ($o[0] | map({key: .Name, value: {
      interna: .Internal,
      contenedores: (contenedores(.) | map({nombre, dns}))
    }}) | from_entries)
  }' > "$SALIDA.tmp"

mv "$SALIDA.tmp" "$SALIDA"
chown 10001:10001 "$SALIDA"
chmod 640 "$SALIDA"
echo "Inventario: $(jq '[.redes[].contenedores | length] | add' "$SALIDA") contenedores en ${#UNIDAS[@]} redes" \
     "(+ $(jq '[.otras_redes[].contenedores | length] | add // 0' "$SALIDA") en ${#OTRAS[@]} redes sin probe) → $SALIDA"
