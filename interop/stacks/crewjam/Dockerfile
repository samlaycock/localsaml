# A crewjam/saml (goxmldsig) service provider, driven over stdin/stdout by interop/run.mjs.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /sp .

FROM gcr.io/distroless/static-debian12
COPY --from=build /sp /sp
ENTRYPOINT ["/sp"]
