#!/usr/bin/env bash
# Runs the SAML Conformance Test Kit (codice/saml-conformance) against localsaml. See README.md.
#
#   ./run.sh                 build localsaml (debug) and run every test
#   BINARY=path ./run.sh     use an existing localsaml binary
#   LENIENT=1 ./run.sh       let error pages use HTTP 4xx/5xx (the kit's -l flag)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
image="codice/samlconf:latest"   # the kit's last release (January 2019), linux/amd64 only
port="${PORT:-9412}"
# The kit runs in Docker and reaches localsaml on the host. Docker Desktop has
# host.docker.internal; on Linux, host networking lets it use localhost.
if [ "$(uname -s)" = "Linux" ]; then
  base="http://localhost:${port}"; network="--network=host"
else
  base="http://host.docker.internal:${port}"; network=""
fi
work="${here}/.work"
rm -rf "$work" && mkdir -p "$work/impl" "$work/data" "$work/out"

if [ -z "${BINARY:-}" ]; then
  (cd "$repo" && cargo build -q)
  BINARY="$repo/target/debug/localsaml"
fi

# The plugin and runner are compiled inside the kit's image, against its own libraries.
compile() {
  local src="$1" jar="$2" extra="${3:-true}"
  docker run --rm --platform linux/amd64 -v "$here:/codice" --entrypoint sh "$image" -c "
    set -e; mkdir -p /tmp/o; javac -nowarn -d /tmp/o -cp '/samlconf/lib/*' \$(find /codice/$src -name '*.java')
    ${extra}; cd /tmp/o && jar cf /codice/.work/$jar ."
}
docker image inspect "$image" >/dev/null 2>&1 || docker pull --platform linux/amd64 -q "$image"
compile plugin/src impl/samlconf-localsaml-impl.jar "cp -r /codice/plugin/META-INF /tmp/o/"
compile runner/src runner.jar

# The kit's two service providers are declared from its own SP metadata (localsaml.toml).
"$BINARY" --config "$here/localsaml.toml" --ephemeral-keys --data-dir "$work/data" \
  --port "$port" --base-url "$base" > "$work/localsaml.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -fs "http://localhost:${port}/health" >/dev/null && break; sleep 0.2; done
curl -fs "http://localhost:${port}/metadata" > "$work/impl/localsaml-idp-metadata.xml"

args="/impl"
[ -n "${LENIENT:-}" ] && args="/impl --lenient"
set +e
docker run --rm --platform linux/amd64 $network -e "LOCALSAML_BASE_URL=$base" \
  -v "$work/impl:/impl" -v "$work:/work" -w /work/out --entrypoint sh "$image" -c \
  "mkdir -p /tmp/xsd && cd /tmp/xsd && unzip -q -o /samlconf/lib/common-1.1-SNAPSHOT.jar '*.xsd' &&
   sed -i 's#\"http://www.w3.org/2001/XMLSchema.dtd\"#\"XMLSchema.dtd\"#' *.xsd && : > XMLSchema.dtd && cd /work/out &&
   java -Dapp.home=/samlconf -cp '/tmp/xsd:/samlconf/lib/*:/work/runner.jar' org.localsaml.ctk.Runner $args" \
  > "$work/results.log" 2>&1
set -e

# (Two workarounds for the kit's schema validation, which otherwise fails with "Cannot resolve the
# name 'ds:Signature'" whatever the IdP sends: it only lets the validator read file: URLs, but in
# its own distribution the XSDs are inside a jar; and the XML-DSig and XML-Enc XSDs load their
# DTD from www.w3.org, which often refuses automated clients. So the XSDs are extracted in front
# of the classpath, with the DTD reference pointed at an empty local file.)

# Compare with the expected failures (name<TAB>reason), so new failures and fixed tests stand out.
{ grep -E '^RESULT (FAILED|ABORTED)' "$work/results.log" || true; } | sed -E 's/^RESULT [A-Z]+ \| ([^|]*[^ |]) *\|.*/\1/' | sort > "$work/failed.txt"
{ grep -vE '^[[:space:]]*(#|$)' "$here/expected-failures.tsv" || true; } | cut -f1 | sort > "$work/expected.txt"
grep -E '^RESULT|^SUMMARY' "$work/results.log" | cut -c1-220 || { echo "The kit didn't run:"; tail -20 "$work/results.log"; exit 1; }
unexpected=$(comm -23 "$work/failed.txt" "$work/expected.txt")
fixed=$(comm -13 "$work/failed.txt" "$work/expected.txt")
[ -n "$fixed" ] && { echo; echo "Expected to fail but passed (remove from expected-failures.tsv):"; echo "$fixed"; }
if [ -n "$unexpected" ]; then
  echo; echo "UNEXPECTED FAILURES:"; echo "$unexpected"
  echo "Details: $work/results.log; localsaml log: $work/localsaml.log"
  exit 1
fi
echo; echo "Only expected failures."
