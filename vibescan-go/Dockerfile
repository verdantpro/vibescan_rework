# Multi-stage build for the VibeScan MVP: builds the UI, embeds it into the Go
# binary, and produces a small runtime image serving UI + APIs from one process.
#
# Build with the repo root (vibescan_rework/) as context:
#   docker build -f vibescan-go/Dockerfile -t vibescan .

# --- stage 1: build the UI (relative API base → served same-origin) ---
FROM node:22-alpine AS ui
WORKDIR /ui
COPY vibescan-ui/package.json vibescan-ui/package-lock.json ./
RUN npm ci
COPY vibescan-ui/ ./
ENV VITE_API_BASE=""
RUN npm run build

# --- stage 2: build the Go binaries with the UI embedded ---
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY vibescan-go/go.mod vibescan-go/go.sum ./
RUN go mod download
COPY vibescan-go/ ./
# Replace the placeholder embed dir with the freshly built UI.
RUN rm -rf internal/web/dist
COPY --from=ui /ui/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -o /out/vibescan ./cmd/collector \
 && CGO_ENABLED=0 go build -trimpath -o /out/migrate  ./cmd/migrate

# --- stage 3: runtime ---
FROM alpine:3.24
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/vibescan /out/migrate /usr/local/bin/
USER app
WORKDIR /app
# GeoLite2-City.mmdb is mounted at runtime (see deploy/docker-compose.yml);
# GEOLITE2_CITY_MMDB points to the mount. GeoIP degrades gracefully if absent.
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["vibescan"]
