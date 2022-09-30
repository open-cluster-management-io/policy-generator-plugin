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

.PHONY: build build-binary build-release generate layout fmt lint lint-dependencies test

include build/common/Makefile.common.mk

############################################################
# build section
############################################################

build: layout
	go build -o $(API_PLUGIN_PATH)/PolicyGenerator cmd/main.go

build-binary:
	go build -o PolicyGenerator cmd/main.go

build-release:
	@if [[ $(shell git status --porcelain | wc -l) -gt 0 ]]; \
		then \
			echo "There are local modifications in the repo" > /dev/stderr; \
			exit 1; \
	fi
	@mkdir -p build_output
	GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/linux-amd64-PolicyGenerator cmd/main.go
	GOOS=darwin CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/darwin-amd64-PolicyGenerator cmd/main.go
	GOOS=windows CGO_ENABLED=0 GOARCH=amd64 go build -o build_output/windows-amd64-PolicyGenerator.exe cmd/main.go

generate:
	@KUSTOMIZE_PLUGIN_HOME=$(KUSTOMIZE_PLUGIN_HOME) kustomize build --enable-alpha-plugins $(SOURCE_DIR)

layout:
	mkdir -p $(API_PLUGIN_PATH)

############################################################
# format section
############################################################

fmt:
	go fmt ./...

############################################################
# lint section
############################################################

.PHONY: lint-dependencies
lint-dependencies:
	$(call go-get-tool,github.com/golangci/golangci-lint/cmd/golangci-lint@v1.46.2)

lint: lint-dependencies lint-all

############################################################
# test section
############################################################
GOSEC = $(LOCAL_BIN)/gosec

test:
	@go test $(TESTARGS) ./...

.PHONY: test-coverage
test-coverage: TESTARGS = -json -cover -covermode=atomic -coverprofile=coverage.out
test-coverage: test

.PHONY: gosec
gosec:
	$(call go-get-tool,github.com/securego/gosec/v2/cmd/gosec@v2.9.6)

.PHONY: gosec-scan
gosec-scan: gosec
	$(GOSEC) -fmt sonarqube -out gosec.json -no-fail -exclude-dir=.go ./...
