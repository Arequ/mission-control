BIN := bin

.PHONY: build test ui tidy fmt server tf-dev compose

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/server ./cmd/server
	go build -o $(BIN)/mc-runner ./cmd/mc-runner
	go build -o $(BIN)/fake-autopkg ./cmd/fake-autopkg
	cd terraform-provider-missioncontrol && go build -o ../$(BIN)/terraform-provider-missioncontrol .

test:
	go test ./...
	cd terraform-provider-missioncontrol && go test ./...

ui:
	cd web && npm install && npm run build

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './web/*')

tidy:
	go mod tidy
	cd terraform-provider-missioncontrol && go mod tidy

server: build ui
	DATABASE_URL=$${DATABASE_URL:-postgres://missioncontrol:missioncontrol@127.0.0.1:5432/missioncontrol?sslmode=disable} \
	MC_ADMIN_TOKEN=$${MC_ADMIN_TOKEN:-mc_dev_admin_token} \
	MC_BOOTSTRAP_TOKEN=$${MC_BOOTSTRAP_TOKEN:-mc_dev_bootstrap_token} \
	MC_REPO_TOKEN=$${MC_REPO_TOKEN:-mc_dev_repo_token} \
	MC_DEV_SEED=$${MC_DEV_SEED:-1} \
	MC_OFFLINE_AFTER=$${MC_OFFLINE_AFTER:-24h} \
	./$(BIN)/server

tf-dev: build
	mkdir -p $(BIN)
	printf 'provider_installation {\n  dev_overrides {\n    "arequ/missioncontrol" = "%s"\n  }\n  direct {}\n}\n' "$$(cd $(BIN) && pwd)" > $(BIN)/dev.tfrc
	@echo "export TF_CLI_CONFIG_FILE=$$(pwd)/$(BIN)/dev.tfrc"

compose:
	docker compose up --build
