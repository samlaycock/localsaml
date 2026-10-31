#!/bin/sh
set -e
cp /interop/shibboleth2.xml /interop/attribute-map.xml /interop/*.pem /etc/shibboleth/
cp /interop/idp-*.xml /etc/shibboleth/
mkdir -p /run/shibboleth /var/log/shibboleth
chown -R _shibd /run/shibboleth /var/log/shibboleth /etc/shibboleth/*.pem 2>/dev/null || true
shibd -t -c /etc/shibboleth/shibboleth2.xml
shibd -f -c /etc/shibboleth/shibboleth2.xml -p /run/shibboleth/shibd.pid -F &
for i in $(seq 1 50); do [ -S /run/shibboleth/shibd.sock ] && break; sleep 0.2; done
exec apache2ctl -D FOREGROUND
