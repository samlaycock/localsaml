# Shibboleth SP 3 (Apache mod_shib + shibd: OpenSAML C++ and xml-security-c) for the localsaml
# interop harness. run.mjs mounts the generated configuration (shibboleth2.xml, attribute-map.xml,
# localsaml's metadata, the SP key pair) at /interop and plays the browser on the host.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       apache2=2.4.68-1~deb12u1 \
       libapache2-mod-shib=3.4.1+dfsg-2+deb12u1 \
       shibboleth-sp-utils=3.4.1+dfsg-2+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
COPY site.conf /etc/apache2/sites-available/000-default.conf
COPY start.sh /start.sh
RUN mkdir -p /var/www/html/secure /var/www/html/enc/secure \
    && echo ok > /var/www/html/secure/index.html \
    && echo ok > /var/www/html/enc/secure/index.html \
    && echo home > /var/www/html/index.html \
    && chmod +x /start.sh
EXPOSE 80
ENTRYPOINT ["/start.sh"]
