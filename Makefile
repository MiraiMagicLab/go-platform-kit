.PHONY: all test lint build clean generate fmt vet

all: fmt lint test build

## Build
build:
	go build ./...

## Test
test:
	go test ./... -v -count=1

test-short:
	go test ./... -short -count=1

test-coverage:
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Lint
lint:
	golangci-lint run ./...

## Format
fmt:
	gofmt -w -s .
	goimports -w -local github.com/MiraiMagicLab/go-auth-lib .

## Vet
vet:
	go vet ./...

## Generate mocks
generate:
	go generate ./...

## Clean
clean:
	rm -f coverage.out coverage.html

## Check (CI target)
check: fmt vet lint test build
