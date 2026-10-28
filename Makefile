SHELL := /bin/bash

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/dotfrankruan/tracecat/internal/version.Version=$(VERSION) \
	-X github.com/dotfrankruan/tracecat/internal/version.Commit=$(COMMIT) \
	-X github.com/dotfrankruan/tracecat/internal/version.BuildDate=$(BUILD_DATE)

GO ?= go
PNPM ?= pnpm

.PHONY: all build build-backend ui ui-deps test test-race vet fmt check clean dev-controller dev-agent

all: build

## build: build the web dashboard and both Go binaries (single-binary deployable).
build: ui build-backend

## build-backend: build Controller and Agent only.
build-backend:
	@mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/tracecat-controller ./cmd/tracecat-controller
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/tracecat-agent ./cmd/tracecat-agent

## ui-deps: install frontend dependencies.
ui-deps:
	$(PNPM) --dir web install

## ui: build the React dashboard into internal/webui/public (embedded by the Controller).
ui: ui-deps
	$(PNPM) --dir web build

## test: run the Go test suite.
test:
	$(GO) test ./...

## test-race: run the Go test suite with the race detector.
test-race:
	$(GO) test -race ./...

## vet: run static analysis.
vet:
	$(GO) vet ./...

## fmt: format Go sources.
fmt:
	gofmt -w $$(find . -name '*.go' -not -path './web/*')

## check: everything CI runs.
check: vet test
	@test -f web/package.json && $(PNPM) --dir web install --frozen-lockfile && $(PNPM) --dir web build || true

## clean: remove build artifacts (keeps embedded UI placeholder).
clean:
	rm -rf bin web/dist
	rm -rf internal/webui/public/assets internal/webui/public/index.html

## dev-controller: run the Controller against the example dev config.
dev-controller:
	$(GO) run ./cmd/tracecat-controller -config configs/controller.dev.json

## dev-agent: run the Agent against the example dev config.
dev-agent:
	$(GO) run ./cmd/tracecat-agent -config configs/agent.dev.json
