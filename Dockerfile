# syntax=docker/dockerfile:1

FROM rust:1.99-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY assets assets
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin localsaml \
    && cp target/release/localsaml /usr/local/bin/localsaml
RUN mkdir /data

# Run: distroless as a non-root user. State (signing key, certificate, SQLite) lives in /data.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /usr/local/bin/localsaml /usr/local/bin/localsaml
COPY --from=build --chown=nonroot:nonroot /data /data
ENV LOCALSAML_HOST=0.0.0.0 \
    LOCALSAML_DATA_DIR=/data
VOLUME /data
EXPOSE 9401
ENTRYPOINT ["/usr/local/bin/localsaml"]
