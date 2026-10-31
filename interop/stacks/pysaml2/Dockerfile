# A pysaml2 service provider (signatures and encryption via the xmlsec1 binary), driven over
# stdin/stdout by interop/run.mjs.
FROM python:3.12-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends xmlsec1=1.2.37-2 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pysaml2==7.5.5
COPY sp.py /sp.py
ENTRYPOINT ["python", "-u", "/sp.py"]
