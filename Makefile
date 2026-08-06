.PHONY: build test clean lint

BINARY_NAME=rampart
VERSION=$(shell cat VERSION)
BUILD_DIR=bin
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/rampart

test:
	go test -v -race ./...

lint:
	gofmt -l -s .
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)
