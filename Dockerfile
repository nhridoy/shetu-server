FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build

WORKDIR /src

# Cache dependencies separately from source changes.
COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

# Build for the target platform.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/shetu-server \
    ./cmd/shetu-server

FROM alpine:3.24.3 AS runtime

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 shetu \
    && adduser -S -D -H -u 10001 -G shetu shetu \
    && mkdir -p /data \
    && chown shetu:shetu /data

COPY --from=build --chown=10001:10001 \
    /out/shetu-server \
    /usr/local/bin/shetu-server

WORKDIR /data

USER 10001:10001

ENV SHETU_HOST=0.0.0.0 \
    SHETU_PORT=8080 \
    GIN_MODE=release \
    TZ=UTC

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/shetu-server"]
