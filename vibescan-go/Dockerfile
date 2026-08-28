# Multi-stage build for the Reachable Web Observatory: builds the UI, embeds it into the Go
# binary, and produces a small runtime image serving UI + APIs from one process.
#
# Build with the repository root as context:
#   docker build -f vibescan-go/Dockerfile -t vibescan .

# --- stage 1: build the UI (relative API base → served same-origin) ---
FROM node:26-alpine AS ui
WORKDIR /ui
COPY vibescan-ui/package.json vibescan-ui/package-lock.json ./
RUN npm ci
COPY vibescan-ui/ ./
COPY vibescan-go/internal/web/routes.json /route-data/routes.json
ENV VITE_API_BASE=""
ENV RWO_ROUTES_PATH="/route-data/routes.json"
RUN npm run build

# --- stage 2: build the Go binaries with the UI embedded ---
FROM golang:1.27-alpine AS build
ARG BUILD_COMMIT=dev
ARG BUILD_DATE=unknown
WORKDIR /src
COPY vibescan-go/go.mod vibescan-go/go.sum ./
RUN go mod download
COPY vibescan-go/ ./
# Replace the placeholder embed dir with the freshly built UI.
RUN rm -rf internal/web/dist
COPY --from=ui /ui/dist ./internal/web/dist
RUN BUILD_LDFLAGS="-s -w -X github.com/vibescan/vibescan-go/internal/buildinfo.Commit=${BUILD_COMMIT} -X github.com/vibescan/vibescan-go/internal/buildinfo.BuiltAt=${BUILD_DATE}" \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$BUILD_LDFLAGS" -o /out/vibescan ./cmd/collector \
 && CGO_ENABLED=0 go build -trimpath -ldflags "$BUILD_LDFLAGS" -o /out/migrate ./cmd/migrate

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
