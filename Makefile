.PHONY: build build-release test test-integration fmt lint clean docker-up docker-down migrate-up migrate-down ui-dev ui-dev-ja ui-build ui-test ui-lint ui-i18n-extract

# Variables
BINARY_NAME=mayu
DATABASE_URL?=postgres://mayu:mayu@localhost:5432/mayu?sslmode=disable
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build
build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY_NAME) ./cmd/mayu

build-release:
	go build -ldflags "-s -w -X main.version=$(VERSION)" -o bin/$(BINARY_NAME) ./cmd/mayu

# Test
test:
	go test ./... -v -count=1

test-integration:
	go test ./... -v -count=1 -tags=integration -p 1

# Format
fmt:
	go fmt ./...

# Lint
lint:
	$(shell go env GOBIN)/golangci-lint run ./...

# Clean
clean:
	rm -rf bin/
	go clean

# Docker
docker-up:
	docker compose up -d
	@echo "Waiting for PostgreSQL to be ready..."
	@docker compose exec postgres sh -c 'until pg_isready -U mayu; do sleep 1; done'
	@echo "PostgreSQL is ready."

docker-down:
	docker compose down

docker-clean:
	docker compose down -v

# Migrations
migrate-up:
	migrate -database "$(DATABASE_URL)" -path migrations up

migrate-down:
	migrate -database "$(DATABASE_URL)" -path migrations down

migrate-create:
	@read -p "Migration name: " name; \
	migrate create -ext sql -dir migrations -seq $$name

# UI (Angular)
ui-dev:
	pnpm --prefix ui run start

ui-dev-ja:
	pnpm --prefix ui run start:ja

ui-build:
	pnpm --prefix ui run build

ui-test:
	pnpm --prefix ui run test --watch=false

ui-lint:
	pnpm --prefix ui run ng lint

ui-i18n-extract:
	cd ui && npx ng extract-i18n
