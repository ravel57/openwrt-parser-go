# syntax=docker/dockerfile:1.7

# ---------- global args ----------
ARG NODE_IMAGE=node:22-alpine
ARG GO_IMAGE=golang:1.25.6-alpine

ARG FRONTEND_REPO=https://github.com/ravel57/mikrotik_parser.git
ARG FRONTEND_REF=""
ARG GO_PACKAGE=./cmd/server
ARG GOARM
ARG GOAMD64

# ---------- build frontend ----------
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend

RUN apk add --no-cache git

WORKDIR /usr/src/node/mikrotik_parser

ARG FRONTEND_REPO=https://github.com/ravel57/mikrotik_parser.git
ARG FRONTEND_REF

RUN set -eux; \
    git clone --depth=1 "$FRONTEND_REPO" .; \
    if [ -n "${FRONTEND_REF:-}" ]; then \
      git fetch --depth=1 origin "${FRONTEND_REF}"; \
      git checkout FETCH_HEAD; \
    fi

RUN corepack enable
RUN yarn install --frozen-lockfile || yarn install
RUN yarn build

# ---------- build backend ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

WORKDIR /app
RUN apk add --no-cache ca-certificates git file

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=frontend /usr/src/node/mikrotik_parser/dist /app/web/dist

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG GO_PACKAGE
ARG GOARM
ARG GOAMD64

RUN set -eux; \
    export CGO_ENABLED=0; \
    export GOOS="${TARGETOS:-linux}"; \
    export GOARCH="${TARGETARCH:-amd64}"; \
    if [ "$GOARCH" = "arm" ]; then \
      if [ -n "${GOARM:-}" ]; then \
        export GOARM="$GOARM"; \
      else \
        case "${TARGETVARIANT:-}" in \
          v5) export GOARM=5 ;; \
          v6) export GOARM=6 ;; \
          v7) export GOARM=7 ;; \
          "") export GOARM=6 ;; \
          *) export GOARM="${TARGETVARIANT#v}" ;; \
        esac; \
      fi; \
    fi; \
    if [ "$GOARCH" = "amd64" ] && [ -n "${GOAMD64:-}" ]; then \
      export GOAMD64="$GOAMD64"; \
    fi; \
    go env GOOS GOARCH GOARM GOAMD64 CGO_ENABLED; \
    go build -trimpath -ldflags="-s -w" -o /out/server "$GO_PACKAGE"; \
    file /out/server

# ---------- run ----------
FROM scratch

WORKDIR /app

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /app/server
COPY --from=frontend /usr/src/node/mikrotik_parser/dist /app/web/dist

EXPOSE 8080
ENTRYPOINT ["/app/server"]