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
# Parse the version using git, with fallbacks as follows:
# - git describe (i.e. vX.Y.Z-<extra_commits>-<sha>)
# - <branch>-<sha>
# - <sha>-dev
# - Go BuildInfo version
# - Unversioned binary
GIT_VERSION := $(shell git describe --dirty 2>/dev/null)
ifndef GIT_VERSION
  GIT_BRANCH := $(shell git branch --show-current)
  GIT_SHA := $(shell git rev-parse --short HEAD)
  ifdef GIT_BRANCH
    GIT_VERSION := $(GIT_BRANCH)-$(GIT_SHA)
  else ifdef GIT_SHA
    GIT_VERSION := $(GIT_SHA)-dev
  endif
endif
GO_LDFLAGS ?= -X 'main.Version=$(GIT_VERSION)'

.PHONY: build
build: layout
	go build -ldflags="$(GO_LDFLAGS)" -o $(API_PLUGIN_PATH)/ ./cmd/PolicyGenerator

.PHONY: build-binary
build-binary:
	CGO_ENABLED=1 go build -mod=readonly -ldflags="$(GO_LDFLAGS)" ./cmd/PolicyGenerator

.PHONY: build-release
build-release:
	@if [ $(shell git status --porcelain | wc -l) -gt 0 ]; then \
			echo "There are local modifications in the repo" > /dev/stderr; \
			exit 1; \
	fi
	@for ARCH in amd64 arm64 ppc64le s390x; do \
		NAME="linux-$${ARCH}-PolicyGenerator"; \
		echo "# Building $${NAME}"; \
		GOOS=linux GOARCH=$${ARCH} CGO_ENABLED=0 \
			go build -mod=readonly -ldflags="$(GO_LDFLAGS)" -o build_output/$${NAME} ./cmd/PolicyGenerator \
			|| exit 1; \
	done
	@for ARCH in amd64 arm64; do \
		NAME="darwin-$${ARCH}-PolicyGenerator"; \
		echo "# Building $${NAME}"; \
		GOOS=darwin GOARCH=$${ARCH} CGO_ENABLED=0 \
			go build -mod=readonly -ldflags="$(GO_LDFLAGS)" -o build_output/$${NAME} ./cmd/PolicyGenerator \
			|| exit 1; \
	done
	@for ARCH in amd64 arm64; do \
		NAME="windows-$${ARCH}-PolicyGenerator.exe"; \
		echo "# Building $${NAME}"; \
		GOOS=windows GOARCH=$${ARCH} CGO_ENABLED=0 \
			go build -mod=readonly -ldflags="$(GO_LDFLAGS)" -o build_output/$${NAME} ./cmd/PolicyGenerator \
			|| exit 1; \
	done

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

############################################################
# lint section
############################################################

.PHONY: lint
lint:

############################################################
# test section
############################################################

.PHONY: test
test:
	@go test $(TESTARGS) ./...

.PHONY: test-coverage
test-coverage: TESTARGS = -json -cover -covermode=atomic -coverprofile=coverage.out
test-coverage: test

.PHONY: gosec-scan
gosec-scan:
