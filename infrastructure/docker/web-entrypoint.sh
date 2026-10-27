#!/bin/sh
set -eu

# Nginx requires IPv6 resolver addresses in brackets: resolver [fd12::10];
format_resolver() {
  addr="$1"
  case "$addr" in
    \[*\]) echo "$addr" ;;
    *:*) echo "[$addr]" ;;
    *) echo "$addr" ;;
  esac
}

# Prefer IPv4 nameserver; fall back to bracketed IPv6.
DNS_RAW="$(awk '/^nameserver/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)"
if [ -z "${DNS_RAW}" ]; then
  DNS_RAW="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)"
fi
if [ -z "${DNS_RAW}" ]; then
  DNS_RAW="127.0.0.11"
fi
DNS_RESOLVER="$(format_resolver "$DNS_RAW")"
export DNS_RESOLVER

probe() {
  url="$1"
  [ -n "$url" ] || return 1
  wget -6 -q -O /dev/null -T 2 "${url}/health" 2>/dev/null && return 0
  wget -4 -q -O /dev/null -T 2 "${url}/health" 2>/dev/null && return 0
  wget -q -O /dev/null -T 2 "${url}/health" 2>/dev/null
}

log_dns() {
  host="$1"
  echo "SEAP web: DNS ${host} -> $(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')" >&2 || true
}

chosen="${API_UPSTREAM:-}"
log_dns "api.railway.internal"
echo "SEAP web: resolver ${DNS_RESOLVER}, configured upstream ${chosen:-none}" >&2

if ! probe "$chosen"; then
  for candidate in \
    "$chosen" \
    "http://api.railway.internal:${API_PORT:-8080}" \
    "http://api.railway.internal:8080" \
    "http://api.railway.internal:4000" \
    "${API_PUBLIC_URL:-}" \
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
  echo "SEAP web: no healthy API found at boot; using ${chosen}" >&2
else
  echo "SEAP web: proxying API at ${chosen}"
fi

export API_UPSTREAM="$chosen"
exec /docker-entrypoint.sh nginx -g "daemon off;"
