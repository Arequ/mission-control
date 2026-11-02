FROM node:22-bookworm AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27.2-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=build /out/server /app/server
COPY --from=ui /src/web/dist /app/web/dist
ENV MC_WEB_DIR=/app/web/dist \
    MC_STORAGE_DIR=/data \
    MC_HTTP_ADDR=:8080
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/server"]
