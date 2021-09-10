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

# Kustomize plugin configuration
XDG_CONFIG_HOME ?= ${HOME}/.config
KUSTOMIZE_PLUGIN_HOME ?= $(XDG_CONFIG_HOME)/kustomize/plugin
API_PLUGIN_PATH ?= $(KUSTOMIZE_PLUGIN_HOME)/policy.open-cluster-management.io/v1/policygenerator

# Kustomize arguments
SOURCE_DIR ?= examples/

.PHONY: build build-binary generate layout fmt lint lint-dependencies test

include build/common/Makefile.common.mk

############################################################
# build section
############################################################

build: layout
	go build -o $(API_PLUGIN_PATH)/PolicyGenerator cmd/main.go

build-binary:
	go build -o PolicyGenerator cmd/main.go

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
	@if [ ! -f $(GOBIN)/golangci-lint ]; then\
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/v1.41.1/install.sh | sh -s -- -b $(GOBIN) v1.41.1;\
    fi

lint: lint-dependencies lint-all

############################################################
# test section
############################################################

test:
	@go test $(TESTARGS) ./...
