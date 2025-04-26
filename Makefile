# Makefile for passforge project

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOLINT=golangci-lint
GOIMPORTS=goimports

# Binary name
BINARY_NAME=passforge

# Build directory
BUILD_DIR=build

# Main package path
MAIN_PACKAGE=.

.PHONY: all build test clean lint deps help goimports

all: test goimports fmt build

# Build the project
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run linter
lint:
	$(GOLINT) run

# Format code
fmt:
	$(GOCMD) fmt ./...

# Run goimports
goimports:
	@which $(GOIMPORTS) > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	$(GOIMPORTS) -w ./

# Verify dependencies
verify:
	$(GOMOD) verify

# Show help
help:
	@echo "Make targets:"
	@echo "  all          - Run tests and build"
	@echo "  build        - Build the binary"
	@echo "  test         - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Install dependencies"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  goimports    - Run goimports to format code and update imports"
	@echo "  verify       - Verify dependencies"
	@echo "  help         - Show this help"
