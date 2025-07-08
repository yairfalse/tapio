.PHONY: build test lint clean install dev-setup generate-ebpf

# Build variables
VERSION ?= dev
GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -X github.com/falseyair/tapio/internal/cli.version=$(VERSION) \
          -X github.com/falseyair/tapio/internal/cli.gitCommit=$(GIT_COMMIT) \
          -X github.com/falseyair/tapio/internal/cli.buildDate=$(BUILD_DATE)

# eBPF variables
BPF_CFLAGS = -O2 -g -Wall -Werror
CLANG ?= clang
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g')

# eBPF
generate-ebpf:
	@echo "🔄 Generating eBPF bindings..."
	@if [ "$(shell uname)" = "Linux" ]; then \
		echo "Downloading vmlinux headers..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h 2>/dev/null || \
		wget -q -O ebpf/headers/vmlinux.h https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/master/vmlinux/vmlinux.h; \
		echo "Generating Go bindings..."; \
		go generate ./pkg/ebpf/...; \
	else \
		echo "eBPF generation requires Linux. Skipping on $(shell uname)"; \
	fi

# Build
build: generate-ebpf
	@echo "🔨 Building Tapio..."
	go build -ldflags "$(LDFLAGS)" -o bin/tapio ./cmd/tapio

build-enhanced: generate-ebpf
	@echo "🔨 Building Tapio with eBPF support..."
	go build -tags ebpf -ldflags "$(LDFLAGS)" -o bin/tapio-ebpf ./cmd/tapio

build-all:
	@echo "🔨 Building for all platforms..."
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/tapio-linux-amd64 ./cmd/tapio
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/tapio-darwin-amd64 ./cmd/tapio
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/tapio-darwin-arm64 ./cmd/tapio
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/tapio-windows-amd64.exe ./cmd/tapio

# Testing
test:
	@echo "🧪 Running tests..."
	go test ./...

test-unit:
	@echo "🧪 Running unit tests..."
	go test -short ./test/unit/...

test-coverage:
	@echo "📊 Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Code quality
lint:
	@echo "🔍 Running linter..."
	golangci-lint run

lint-fix:
	@echo "🔧 Fixing linting issues..."
	golangci-lint run --fix

# Development
dev-setup:
	@echo "🛠️  Setting up development environment..."
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

clean:
	@echo "🧹 Cleaning up..."
	rm -rf bin/ dist/ coverage.out coverage.html

install: build
	@echo "📦 Installing Tapio..."
	cp bin/tapio /usr/local/bin/

# Quick development cycle
dev: clean build
	@echo "✅ Development build complete!"
	@echo "Try: ./bin/tapio check"

# CI targets
ci: lint test build
	@echo "✅ CI pipeline complete!"

# Remove old build artifacts and rebuild completely
rebuild: clean build