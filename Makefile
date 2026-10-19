.PHONY: test server web mcctl runner tidy up down fmt

export GOTOOLCHAIN ?= local

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './web/*')

server:
	go run ./cmd/mc-server

web:
	cd web && npm install && npm run build

mcctl:
	go build -o bin/mcctl ./cmd/mcctl

runner:
	go build -o bin/mc-runner ./cmd/mc-runner

tidy:
	go mod tidy

up:
	docker compose up --build

down:
	docker compose down
