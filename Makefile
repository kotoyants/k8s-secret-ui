BINARY          := secret-manager
IMAGE           ?= ghcr.io/kotoyants/k8s-secret-ui
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOLANGCI_VERSION ?= v2.15.0

# Load local env for `make run` if present.
ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help run build test test-race cover lint fmt tidy docker db-up db-down clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

run: ## Run the app locally (reads .env)
	go run ./cmd/$(BINARY)

build: ## Build a static binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/$(BINARY)

test: ## Run tests
	go test ./...

test-race: ## Run tests with the race detector
	go test -race ./...

cover: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint (local binary, or Docker fallback)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		docker run --rm -v "$(CURDIR)":/app -w /app golangci/golangci-lint:$(GOLANGCI_VERSION) golangci-lint run ./...; \
	fi

fmt: ## Format code
	gofmt -s -w .

tidy: ## Tidy go.mod
	go mod tidy

docker: ## Build the Docker image
	docker build -t $(IMAGE):$(VERSION) .

db-up: ## Start local Postgres
	docker compose up -d postgres

db-down: ## Stop local Postgres
	docker compose down

clean: ## Remove build artifacts
	rm -rf bin coverage.out
