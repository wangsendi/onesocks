# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -tags with_utls -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o /out/onesocks ./cmd/onesocks

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /var/lib/onesocks \
    && chown 65532:65532 /var/lib/onesocks
COPY --from=build /out/onesocks /usr/local/bin/onesocks
COPY configs/config.docker.yaml /etc/onesocks/config.yaml
COPY LICENSE /usr/share/licenses/onesocks/LICENSE
LABEL org.opencontainers.image.source="https://github.com/wangsendi/onesocks" \
      org.opencontainers.image.title="OneSocks" \
      org.opencontainers.image.description="One SOCKS5 endpoint, multiple proxy subscriptions."
USER 65532:65532
WORKDIR /var/lib/onesocks
EXPOSE 1080/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/onesocks"]
CMD ["-config", "/etc/onesocks/config.yaml"]
