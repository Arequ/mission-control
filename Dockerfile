FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/mc-server ./cmd/mc-server \
    && CGO_ENABLED=0 go build -o /out/mcctl ./cmd/mcctl \
    && CGO_ENABLED=0 go build -o /out/mc-runner ./cmd/mc-runner

FROM alpine:3.20
RUN apk add --no-cache ca-certificates git
COPY --from=build /out/mc-server /out/mcctl /out/mc-runner /usr/local/bin/
COPY --from=web /src/web/dist /app/web
ENV MC_WEB_DIR=/app/web
EXPOSE 8080
ENTRYPOINT ["mc-server"]
