# Near-perfect Makefile for Go project

# Project variables
APP_NAME := gockerize
CMD_DIR := ./cmd/$(APP_NAME)
BUILD_DIR := .
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.date=$(DATE)'
GO := go
GOFMT := gofmt
GOLINT := golint
GOTEST := go test
GOFILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

.PHONY: all build run clean fmt lint test test-verbose test-short test-race coverage install deps help check pre-commit docker-build docker-run

all: check build

build:
	@echo "$(BLUE)Building $(APP_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME) $(CMD_DIR)
	@echo "$(GREEN)Build complete: $(BUILD_DIR)/$(APP_NAME)$(NC)"

run: build
	@echo "$(BLUE)Running $(APP_NAME)...$(NC)"
	$(BUILD_DIR)/$(APP_NAME)

clean:
	@echo "$(YELLOW)Cleaning up...$(NC)"
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "$(GREEN)Clean complete$(NC)"

fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	$(GOFMT) -s -w $(GOFILES)
	@echo "$(GREEN)Format complete$(NC)"

lint:
	@echo "$(BLUE)Linting code...$(NC)"
	@if command -v golint >/dev/null 2>&1; then \
		$(GOLINT) ./...; \
	else \
		echo "$(YELLOW)golint not installed, skipping lint check$(NC)"; \
	fi
	@if command -v go >/dev/null 2>&1; then \
		$(GO) vet ./...; \
	fi
	@echo "$(GREEN)Lint complete$(NC)"

test:
	@echo "$(BLUE)Running tests...$(NC)"
	$(GOTEST) -v ./...

test-verbose:
	@echo "$(BLUE)Running tests with verbose output...$(NC)"
	$(GOTEST) -v -count=1 ./...

test-short:
	@echo "$(BLUE)Running short tests...$(NC)"
	$(GOTEST) -short ./...

test-race:
	@echo "$(BLUE)Running tests with race detection...$(NC)"
	$(GOTEST) -race ./...

coverage:
	@echo "$(BLUE)Generating coverage report...$(NC)"
	$(GOTEST) -coverprofile=coverage.out ./...
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"
	@$(GO) tool cover -func=coverage.out | tail -1

install:
	@echo "$(BLUE)Installing $(APP_NAME)...$(NC)"
	$(GO) install -ldflags="$(LDFLAGS)" $(CMD_DIR)
	@echo "$(GREEN)Install complete$(NC)"

deps:
	@echo "$(BLUE)Tidying dependencies...$(NC)"
	$(GO) mod tidy
	$(GO) mod download
	@echo "$(GREEN)Dependencies updated$(NC)"

check: fmt lint test
	@echo "$(GREEN)All checks passed!$(NC)"

pre-commit: clean fmt lint test-race coverage
	@echo "$(GREEN)Pre-commit checks complete!$(NC)"

# Development targets
dev-setup:
	@echo "$(BLUE)Setting up development environment...$(NC)"
	@if ! command -v golint >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golint...$(NC)"; \
		$(GO) install golang.org/x/lint/golint@latest; \
	fi
	@echo "$(GREEN)Development setup complete$(NC)"

help:
	@echo "$(BLUE)Makefile commands:$(NC)"
	@echo "  $(GREEN)build$(NC)        Build the application"
	@echo "  $(GREEN)run$(NC)          Build and run the application"
	@echo "  $(GREEN)clean$(NC)        Remove build artifacts"
	@echo "  $(GREEN)fmt$(NC)          Format the codebase"
	@echo "  $(GREEN)lint$(NC)         Lint the codebase"
	@echo "  $(GREEN)test$(NC)         Run tests"
	@echo "  $(GREEN)test-verbose$(NC) Run tests with verbose output"
	@echo "  $(GREEN)test-short$(NC)   Run short tests"
	@echo "  $(GREEN)test-race$(NC)    Run tests with race detection"
	@echo "  $(GREEN)coverage$(NC)     Generate test coverage report"
	@echo "  $(GREEN)install$(NC)      Install the application"
	@echo "  $(GREEN)deps$(NC)         Tidy go.mod dependencies"
	@echo "  $(GREEN)check$(NC)        Run fmt, lint, and test"
	@echo "  $(GREEN)pre-commit$(NC)   Run all pre-commit checks"
	@echo "  $(GREEN)dev-setup$(NC)    Setup development environment"
	@echo "  $(GREEN)help$(NC)         Show this help message"
