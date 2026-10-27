#!/bin/sh
set -eu

probe() {
  url="$1"
  [ -n "$url" ] || return 1
  wget -q -O /dev/null -T 2 "${url}/health" 2>/dev/null
}

chosen="${API_UPSTREAM:-}"

if ! probe "$chosen"; then
  for candidate in \
    "http://api.railway.internal:${API_PORT:-8080}" \
    "http://api.railway.internal:8080" \
    "http://api.railway.internal:4000" \
    "http://api.railway.internal:${PORT:-8080}" \
    "http://api:4000" \
    "http://api:8080"
  do
    if probe "$candidate"; then
      chosen="$candidate"
      break
    fi
  done
fi

if [ -z "${chosen}" ]; then
  chosen="${API_UPSTREAM:-http://api.railway.internal:8080}"
  echo "SEAP web: no healthy API found; using ${chosen}" >&2
else
  echo "SEAP web: proxying API at ${chosen}"
fi

export API_UPSTREAM="$chosen"
exec /docker-entrypoint.sh nginx -g "daemon off;"
