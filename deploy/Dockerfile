# syntax=docker/dockerfile:1
# Client_UI build stage. Node 24 index digest read from Docker Hub on 2026-11-21.
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --ignore-scripts
COPY ui/ ./
RUN npm run build
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The built UI replaces ui/dist (which .dockerignore keeps out of the context) before go build embeds it.
COPY --from=ui /ui/dist ./ui/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/bskg ./cmd/bskg

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bskg /bskg
USER 65532:65532
ENTRYPOINT ["/bskg"]
