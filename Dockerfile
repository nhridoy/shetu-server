# syntax=docker/dockerfile:1.7

FROM golang:1.26.8-alpine AS build

WORKDIR /src

# Cache dependencies separately from source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

# glebarez/sqlite and pgx are pure Go, so a static CGO-free binary works.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/terra-server ./cmd/terra-server

FROM alpine:3.24.3 AS runtime

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 terra \
    && adduser -S -D -H -u 10001 -G terra terra \
    && mkdir -p /data \
    && chown terra:terra /data

COPY --from=build /out/terra-server /usr/local/bin/terra-server

# Relative SQLite URLs (sqlite://terra.db) land on the writable data volume.
WORKDIR /data

USER 10001:10001

ENV TERRA_HOST=0.0.0.0 \
    TERRA_PORT=8080 \
    GIN_MODE=release \
    TZ=UTC

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/terra-server"]
