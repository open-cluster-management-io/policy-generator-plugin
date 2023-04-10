# Copyright (c) 2021 Red Hat, Inc.
# Copyright Contributors to the Open Cluster Management project

PWD := $(shell pwd)
LOCAL_BIN ?= $(PWD)/bin

# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)
export PATH := $(LOCAL_BIN):$(GOBIN):$(PATH)
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
export DEPENDENCY_OVERRIDE ?= false

# Kustomize plugin configuration
XDG_CONFIG_HOME ?= ${HOME}/.config
KUSTOMIZE_PLUGIN_HOME ?= $(XDG_CONFIG_HOME)/kustomize/plugin
API_PLUGIN_PATH ?= $(KUSTOMIZE_PLUGIN_HOME)/policy.open-cluster-management.io/v1/policygenerator

# Kustomize arguments
SOURCE_DIR ?= examples/

# go-get-tool will 'go install' any package $1 and install it to LOCAL_BIN.
define go-get-tool
@set -e ;\
echo "Checking installation of $(1)" ;\
GOBIN=$(LOCAL_BIN) go install $(1)
endef

include build/common/Makefile.common.mk

############################################################
# clean section
############################################################

.PHONY: clean
clean:
	-rm $(LOCAL_BIN)/*
	-rm $(API_PLUGIN_PATH)/PolicyGenerator
	-rm build_output/*
	-rm PolicyGenerator

############################################################
# build section
############################################################

.PHONY: build
build: layout
	go build -o $(API_PLUGIN_PATH)/ ./cmd/PolicyGenerator

.PHONY: build-binary
build-binary:
	go build ./cmd/PolicyGenerator

.PHONY: build-release
build-release:
	@if [[ $(shell git status --porcelain | wc -l) -gt 0 ]]; \
		then \
			echo "There are local modifications in the repo" > /dev/stderr; \
			exit 1; \
	fi
	@mkdir -p build_output
	GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/linux-amd64-PolicyGenerator ./cmd/PolicyGenerator
	GOOS=darwin CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/darwin-amd64-PolicyGenerator ./cmd/PolicyGenerator
	GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/windows-amd64-PolicyGenerator.exe ./cmd/PolicyGenerator

.PHONY: generate
generate:
	@KUSTOMIZE_PLUGIN_HOME=$(KUSTOMIZE_PLUGIN_HOME) kustomize build --enable-alpha-plugins $(SOURCE_DIR)

.PHONY: layout
layout:
	mkdir -p $(API_PLUGIN_PATH)

############################################################
# format section
############################################################

.PHONY: fmt
fmt:
	go fmt ./...

############################################################
# lint section
############################################################

.PHONY: lint-dependencies
lint-dependencies:
	$(call go-get-tool,github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2)

.PHONY: lint
lint: lint-dependencies lint-all

############################################################
# test section
############################################################
GOSEC = $(LOCAL_BIN)/gosec

.PHONY: test
test:
	@go test $(TESTARGS) ./...

.PHONY: test-coverage
test-coverage: TESTARGS = -json -cover -covermode=atomic -coverprofile=coverage.out
test-coverage: test

.PHONY: gosec
gosec:
	$(call go-get-tool,github.com/securego/gosec/v2/cmd/gosec@v2.15.0)

.PHONY: gosec-scan
gosec-scan: gosec
	$(GOSEC) -fmt sonarqube -out gosec.json -no-fail -exclude-dir=.go ./...
