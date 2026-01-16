SHELL := /bin/bash

GO            ?= go
PKG           := ./cmd/server
BIN_DIR       := bin
APP_NAME      := rocnav
VERSION       ?= $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS_BASE  := -X github.com/rochael/RocNav/internal/version.buildVersion=$(VERSION) -s -w
STATIC_FLAGS  := -linkmode external -extldflags "-static"
LINUX_CC      ?= x86_64-linux-musl-gcc

.PHONY: build build-linux

build:
	@mkdir -p $(BIN_DIR)
	@$(GO) build -ldflags "$(LDFLAGS_BASE)" -o $(BIN_DIR)/$(APP_NAME) $(PKG)

build-linux:
	@mkdir -p $(BIN_DIR)
	@CC=$(LINUX_CC) CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS_BASE) $(STATIC_FLAGS)" -o $(BIN_DIR)/$(APP_NAME)-linux $(PKG)
	@md5sum $(BIN_DIR)/$(APP_NAME)-linux
