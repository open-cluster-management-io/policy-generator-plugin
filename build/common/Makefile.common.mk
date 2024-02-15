# Copyright (c) 2022 Red Hat, Inc.
# Copyright Contributors to the Open Cluster Management project

## CLI versions (with links to the latest releases)
# https://github.com/kubernetes-sigs/controller-tools/releases/latest
CONTROLLER_GEN_VERSION := v0.6.1
# https://github.com/kubernetes-sigs/kustomize/releases/latest
KUSTOMIZE_VERSION := v5.3.0
# https://github.com/golangci/golangci-lint/releases/latest
GOLANGCI_VERSION := v1.52.2
# https://github.com/mvdan/gofumpt/releases/latest
GOFUMPT_VERSION := v0.6.0
# https://github.com/daixiang0/gci/releases/latest
GCI_VERSION := v0.12.1
# https://github.com/securego/gosec/releases/latest
GOSEC_VERSION := v2.18.2
# https://github.com/kubernetes-sigs/kubebuilder/releases/latest
KBVERSION := 3.12.0
# https://github.com/kubernetes/kubernetes/releases/latest
ENVTEST_K8S_VERSION := 1.26.x

LOCAL_BIN ?= $(error LOCAL_BIN is not set.)
ifneq ($(findstring $(LOCAL_BIN), $(PATH)), $(LOCAL_BIN))
  $(error LOCAL_BIN is not in PATH.)
endif

# go-get-tool will 'go install' any package $1 and install it to LOCAL_BIN.
define go-get-tool
  @set -e ;\
  echo "Checking installation of $(1)" ;\
  GOBIN=$(LOCAL_BIN) go install $(1)
endef

# Handle base64 OS differences
OS = $(shell uname -s | tr '[:upper:]' '[:lower:]')
BASE64 = base64 -w 0
ifeq ($(OS), darwin)
  BASE64 = base64
endif

############################################################
#  Work
############################################################

$(LOCAL_BIN):
	@mkdir -p $(LOCAL_BIN)

############################################################
#  Generate manifests
############################################################
CONTROLLER_GEN = $(LOCAL_BIN)/controller-gen
KUSTOMIZE = $(LOCAL_BIN)/kustomize

.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION))

.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION))

############################################################
#  Lint
############################################################
FINDFILES=find . \( -path ./.git -o -path ./.github -o -path ./.go \) -prune -o -type f
XARGS = xargs -0 ${XARGS_FLAGS}
CLEANXARGS = xargs ${XARGS_FLAGS}

.PHONY: lint
lint: lint-dependencies lint-yaml lint-go

.PHONY: lint-dependencies
lint-dependencies:
	$(call go-get-tool,github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_VERSION))

.PHONY: lint-yaml
lint-yaml:
	# Linting YAML 
	@$(FINDFILES) \( -name '*.yml' -o -name '*.yaml' \) -print0 | $(XARGS) grep -L -e "{{" | $(CLEANXARGS) yamllint -c ./build/common/config/.yamllint.yml

.PHONY: lint-go
lint-go:
	# Linting Golang
	@$(FINDFILES) -name '*.go' \( ! \( -name '*.gen.go' -o -name '*.pb.go' \) \) -print0 | $(XARGS) build/common/scripts/lint_go.sh

.PHONY: fmt-dependencies
fmt-dependencies:
	$(call go-get-tool,github.com/daixiang0/gci@$(GCI_VERSION))
	$(call go-get-tool,mvdan.cc/gofumpt@$(GOFUMPT_VERSION))

.PHONY: fmt
fmt: fmt-dependencies
	find . -not \( -path "./.go" -prune \) -name "*.go" | xargs gofmt -s -w
	find . -not \( -path "./.go" -prune \) -name "*.go" | xargs gofumpt -l -w
	find . -not \( -path "./.go" -prune \) -name "*.go" | xargs gci write --skip-generated -s standard -s default -s "prefix($(shell cat go.mod | head -1 | cut -d " " -f 2))"
	go mod tidy

############################################################
#  Unit Test
############################################################
GOSEC = $(LOCAL_BIN)/gosec
KUBEBUILDER = $(LOCAL_BIN)/kubebuilder
ENVTEST = $(LOCAL_BIN)/setup-envtest

.PHONY: kubebuilder
kubebuilder:
	@if [ "$$($(KUBEBUILDER) version 2>/dev/null | grep -o KubeBuilderVersion:\"[0-9]*\.[0-9]\.[0-9]*\")" != "KubeBuilderVersion:\"$(KBVERSION)\"" ]; then \
		echo "Installing Kubebuilder"; \
		curl -L https://github.com/kubernetes-sigs/kubebuilder/releases/download/v$(KBVERSION)/kubebuilder_$(GOOS)_$(GOARCH) -o $(KUBEBUILDER); \
		chmod +x $(KUBEBUILDER); \
	fi

.PHONY: envtest
envtest:
	$(call go-get-tool,sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

.PHONY: gosec
gosec:
	$(call go-get-tool,github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION))

.PHONY: gosec-scan
gosec-scan: gosec
	$(GOSEC) -fmt sonarqube -out gosec.json -stdout -exclude-dir=.go -exclude-dir=test $(GOSEC_ARGS) ./...

############################################################
#  E2E Test
############################################################
GINKGO = $(LOCAL_BIN)/ginkgo
CLUSTER_NAME ?= $(error CLUSTER_NAME is not set.)
CONTROLLER_NAME ?= $(error CONTROLLER_NAME is not set.)
KIND_NAME ?= test-$(CLUSTER_NAME)
KIND_CLUSTER_NAME = kind-$(KIND_NAME)
CONTROLLER_NAMESPACE ?= open-cluster-management-agent-addon
KIND_VERSION ?= latest
# Set the Kind version tag
ifdef KIND_VERSION
  ifeq ($(KIND_VERSION), minimum)
    KIND_ARGS = --image kindest/node:v1.25.16
  else ifneq ($(KIND_VERSION), latest)
    KIND_ARGS = --image kindest/node:$(KIND_VERSION)
  endif
endif

.PHONY: kind-create-cluster
kind-create-cluster:
	# Ensuring cluster $(KIND_NAME)
	-kind create cluster --name $(KIND_NAME) $(KIND_ARGS)
	kubectl config use-context $(KIND_CLUSTER_NAME)
	kind get kubeconfig --name $(KIND_NAME) > kubeconfig_$(CLUSTER_NAME)_e2e

.PHONY: kind-ensure-sa
kind-ensure-sa:
	@KUBECONFIG_TOKEN="$$(kubectl config view --raw -o jsonpath='{.users[].user.token}')"; \
	KUBECONFIG_USER="$$(echo "$${KUBECONFIG_TOKEN}" | jq -rR 'split(".") | .[1] | select(. != null) | @base64d | fromjson | .sub')"; \
	echo "Kubeconfig user detected from token: $${KUBECONFIG_USER}"; \
	[ "$${KUBECONFIG_USER}" = "system:serviceaccount:$(CONTROLLER_NAMESPACE):$(CONTROLLER_NAME)" ]

.PHONY: kind-controller-kubeconfig
kind-controller-kubeconfig: install-resources
	kubectl -n $(CONTROLLER_NAMESPACE) apply -f test/resources/e2e_controller_secret.yaml --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME)_e2e
	-rm kubeconfig_$(CLUSTER_NAME)
	@kubectl config view --minify -o jsonpath='{.clusters[].cluster.certificate-authority-data}' --kubeconfig=kubeconfig_$(CLUSTER_NAME)_e2e --raw | base64 -d > temp-ca.crt
	@kubectl config set-cluster $(KIND_CLUSTER_NAME) --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME) \
		--server=$(shell kubectl config view --minify -o jsonpath='{.clusters[].cluster.server}' --kubeconfig=kubeconfig_$(CLUSTER_NAME)_e2e) \
		--certificate-authority=temp-ca.crt --embed-certs=true
	@rm -f temp-ca.crt
	@kubectl config set-credentials $(KIND_CLUSTER_NAME) --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME) \
		--token=$$(kubectl get secret -n $(CONTROLLER_NAMESPACE) $(CONTROLLER_NAME) -o jsonpath='{.data.token}' --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME)_e2e | $(BASE64) --decode)
	@kubectl config set-context $(KIND_CLUSTER_NAME) --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME) \
		--user=$(KIND_CLUSTER_NAME) --cluster=$(KIND_CLUSTER_NAME)
	@kubectl config use-context $(KIND_CLUSTER_NAME) --kubeconfig=$(PWD)/kubeconfig_$(CLUSTER_NAME)

.PHONY: e2e-dependencies
e2e-dependencies:
	$(call go-get-tool,github.com/onsi/ginkgo/v2/ginkgo@$(shell awk '/github.com\/onsi\/ginkgo\/v2/ {print $$2}' go.mod))

############################################################
#  Test coverage
############################################################
GOCOVMERGE = $(LOCAL_BIN)/gocovmerge
.PHONY: coverage-dependencies
coverage-dependencies:
	$(call go-get-tool,github.com/wadey/gocovmerge@v0.0.0-20160331181800-b5bfa59ec0ad)
