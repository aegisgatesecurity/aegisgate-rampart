.PHONY: build test clean lint coverage test-coverage

BINARY_NAME=rampart
VERSION=$(shell cat VERSION)
BUILD_DIR=bin
LDFLAGS=-ldflags "-s -w -X main.versionFlag=$(VERSION)"

# Packages that are inherently difficult to test in CI
# (platform-specific, GUI, main entry points)
COVERAGE_EXCLUDE=cmd/rampart,internal/tray

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rampart

test:
	go test -v -race ./...

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	@echo "=== Coverage by Package ==="
	@go tool cover -func=coverage.out | grep -E '^github.com|^total'
	@echo ""
	@echo "=== Total Coverage ==="
	@go tool cover -func=coverage.out | grep total

test-coverage: coverage
	@mkdir -p .workingdirectory
	@echo ""
	@echo "=== Checking total coverage (excluding untestable packages) ==="
	@go test -count=1 -coverprofile=.workingdirectory/coverage-filtered.out -covermode=atomic \
		$$(go list ./... | grep -v "cmd/rampart" | grep -v "internal/tray") 2>/dev/null
	@TOTAL=$$(go tool cover -func=.workingdirectory/coverage-filtered.out | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Coverage (excluding cmd/rampart, internal/tray): $${TOTAL}%"; \
	if [ "$$(echo "$$TOTAL >= 80" | bc)" != "1" ]; then \
		echo "FAIL: coverage $${TOTAL}% < 80%"; \
		exit 1; \
	fi; \
	echo "PASS: coverage $${TOTAL}% >= 80%"

lint:
	gofmt -l -s .
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)
