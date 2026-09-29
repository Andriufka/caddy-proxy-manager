# syntax=docker/dockerfile:1.6@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Always run the builder on the host arch (BUILDPLATFORM) and let xcaddy
# cross-compile Caddy for the target arch via GOOS/GOARCH.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

COPY docker/caddy/go.mod docker/caddy/go.sum docker/caddy/build.sh docker/caddy/update-compatibility-pins.sh ./

RUN sh ./update-compatibility-pins.sh

RUN XCADDY_VERSION="$(go list -m -f '{{.Version}}' github.com/caddyserver/xcaddy)" && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@"${XCADDY_VERSION}"

RUN sh ./build.sh


# ============================================================
# Alpine Linux 3.24.2
# ============================================================

FROM alpine:3.24.2

ARG PUID=10000
ARG PGID=10000

# Runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    wget \
    shadow

# Copy custom Caddy binary
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Create caddy user and directories with configurable IDs
RUN (getent group ${PGID} && groupdel $(getent group ${PGID} | cut -d: -f1) || true) && \
    (getent passwd ${PUID} && userdel $(getent passwd ${PUID} | cut -d: -f1) || true) && \
    groupadd -g ${PGID} caddy && \
    useradd -r -u ${PUID} -g caddy -m -d /home/caddy caddy && \
    mkdir -p /data /config /logs /acme-ca && \
    chown -R caddy:caddy /data /config /logs /home/caddy && \
    chmod 0777 /acme-ca

COPY --chown=caddy:caddy docker/caddy/Caddyfile /etc/caddy/Caddyfile

EXPOSE 80 443 2019

ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data

USER caddy

CMD ["caddy", "run", "--resume", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
