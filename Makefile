# Copyright (c) 2021 Red Hat, Inc.
# Copyright Contributors to the Open Cluster Management project

PWD := $(shell pwd)
BASE_DIR := $(shell basename $(PWD))

# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)
export PATH := $(PATH):$(GOBIN)
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
export DEPENDENCY_OVERRIDE ?= false
export OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
export ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g')

# Kustomize plugin configuration
XDG_CONFIG_HOME ?= ${HOME}/.config
KUSTOMIZE_PLUGIN_HOME ?= $(XDG_CONFIG_HOME)/kustomize/plugin
API_PLUGIN_PATH ?= $(KUSTOMIZE_PLUGIN_HOME)/policy.open-cluster-management.io/v1/policygenerator

# Kustomize arguments
SOURCE_DIR ?= examples/

.PHONY: build build-binary build-release generate layout fmt lint lint-dependencies test

include build/common/Makefile.common.mk

############################################################
# build section
############################################################

build: layout
	go build -o $(API_PLUGIN_PATH)/PolicyGenerator cmd/main.go

build-binary:
	go build -o PolicyGenerator cmd/main.go

build-so:
	@mkdir -p build_output
	go build -buildmode=c-shared -o build_output/_processGeneratorConfigC_$(OS)_$(ARCH).so cmd/main.go

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

lint-dependencies:
	@if [ ! -f $(GOBIN)/golangci-lint ] || [ "$(DEPENDENCY_OVERRIDE)" = "true" ]; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/v1.41.1/install.sh | sh -s -- -b $(GOBIN) v1.41.1; \
	else \
		echo "Folder '$(GOBIN)/golangci-lint' already exists--skipping dependency install (export DEPENDENCY_OVERRIDE=true to override this and run install anyway)"; \
	fi

lint: lint-dependencies lint-all

############################################################
# test section
############################################################

test:
	@go test $(TESTARGS) ./...
