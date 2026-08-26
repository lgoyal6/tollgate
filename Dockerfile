# Build stage
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tollgate-admin ./cmd/tollgate-admin \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/upstream ./cmd/upstream

# Demo upstream image, built only when asked for by name.
# Kept before the gateway so the gateway is the default (last) stage:
# `docker build .` and any platform that ignores --target get the gateway.
FROM gcr.io/distroless/static-debian12:nonroot AS upstream
COPY --from=build /out/upstream /upstream
EXPOSE 9000
ENTRYPOINT ["/upstream"]

# Gateway image
FROM gcr.io/distroless/static-debian12:nonroot AS gateway
COPY --from=build /out/gateway /gateway
COPY --from=build /out/tollgate-admin /tollgate-admin
EXPOSE 8080 9090
ENTRYPOINT ["/gateway"]

