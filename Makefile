# gockerize Container Runtime Makefile

# Build variables
BINARY_NAME = gockerize
BUILD_DIR = build
CMD_DIR = ./cmd/gockerize
PKG = ./...

# Go build flags
LDFLAGS = -ldflags="-s -w"
BUILD_FLAGS = -v $(LDFLAGS)

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME = $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Enhanced LDFLAGS with version info
LDFLAGS = -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

.PHONY: all build clean test lint install deps setup-dev check fmt vet

# Default target
all: clean build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build with debug symbols
build-debug:
	@echo "Building $(BINARY_NAME) with debug symbols..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -v -race -o $(BUILD_DIR)/$(BINARY_NAME)-debug $(CMD_DIR)

# Install binary to system
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installation complete"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	go test -v $(PKG)

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out $(PKG)
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. $(PKG)

# Format code
fmt:
	@echo "Formatting code..."
	go fmt $(PKG)

# Vet code
vet:
	@echo "Vetting code..."
	go vet $(PKG)

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Check code quality
check: fmt vet lint test

# Setup development environment
setup-dev:
	@echo "Setting up development environment..."
	@# Install useful development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "Development setup complete"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	
	# Linux arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	
	# Darwin amd64 (for development on Intel Macs)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	
	# Darwin arm64 (for development on Apple Silicon Macs)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	
	@echo "Multi-platform build complete"

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@cd $(BUILD_DIR) && \
	for binary in $(BINARY_NAME)-*; do \
		if [[ "$$binary" != *".tar.gz" ]]; then \
			tar -czf "$$binary.tar.gz" "$$binary"; \
			echo "Created $$binary.tar.gz"; \
		fi \
	done
	@echo "Release archives created"

# Run the binary
run: build
	sudo $(BUILD_DIR)/$(BINARY_NAME)

# Quick development cycle: format, vet, test, and build
dev: fmt vet test build

# Show help
help:
	@echo "gockerize Container Runtime - Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Clean and build (default)"
	@echo "  build        - Build the binary"
	@echo "  build-debug  - Build with debug symbols and race detection"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  install      - Install binary to /usr/local/bin"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  bench        - Run benchmarks"
	@echo "  fmt          - Format code"
	@echo "  vet          - Vet code"
	@echo "  lint         - Lint code (requires golangci-lint)"
	@echo "  check        - Format, vet, lint, and test"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  setup-dev    - Setup development environment"
	@echo "  release      - Create release archives"
	@echo "  run          - Build and run the binary"
	@echo "  dev          - Quick development cycle"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  VERSION      - Version string (default: git describe or 'dev')"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make test"
	@echo "  make install"
	@echo "  VERSION=1.0.0 make release"