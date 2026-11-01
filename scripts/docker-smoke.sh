#!/bin/sh
# Start a localsaml image the way the README shows (a mounted config) and check it answers.
# Usage: scripts/docker-smoke.sh [image]   (default: localsaml:smoke)
set -eu
image=${1:-localsaml:smoke}
port=${PORT:-9431}
name=localsaml-smoke-$$
dir=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT

cat > "$dir/localsaml.toml" <<TOML
[[service_providers]]
entity_id = "http://localhost:3000/saml/metadata"
acs_urls = ["http://localhost:3000/saml/acs"]
TOML
chmod 644 "$dir/localsaml.toml"

docker run -d --name "$name" -p "$port:9401" -e "LOCALSAML_BASE_URL=http://localhost:$port" \
  -v "$dir/localsaml.toml:/etc/localsaml.toml:ro" "$image" --config /etc/localsaml.toml >/dev/null

fail() { echo "FAIL: $1"; docker logs "$name" 2>&1 | tail -20; exit 1; }
for _ in $(seq 1 50); do
  curl -sf "http://localhost:$port/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "http://localhost:$port/health" >/dev/null || fail "/health didn't answer"
curl -sf "http://localhost:$port/metadata" | grep -q "entityID=\"http://localhost:$port/metadata\"" \
  || fail "/metadata isn't the root issuer's"
curl -sf "http://localhost:$port/dev/api/service-providers" | grep -q "http://localhost:3000/saml/metadata" \
  || fail "the mounted config's service provider wasn't loaded"
echo "ok: $image answers, with the mounted config"
