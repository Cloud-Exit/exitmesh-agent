GO ?= go
HELM ?= helm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell git log -1 --format=%cI 2>/dev/null)
GOLANGCI_LINT_VERSION ?= v2.14.0
GORELEASER_VERSION ?= v2.18.2
FUZZTIME ?= 15s
CHART := deploy/helm/exitmesh-agent
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

export CGO_ENABLED := 0

KUBE_VERSIONS ?= 1.27.0 1.30.0 1.34.0 1.37.0

.PHONY: all build test test-race vet lint fuzz vectors chart-test chart-validate check-deps licenses vuln reproducible release-snapshot release-check packages package-smoke kind-e2e next-version clean

all: vet test build

build:
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/exitmesh-agent ./cmd/exitmesh-agent

test:
	$(GO) test ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

fuzz:
	FUZZTIME=$(FUZZTIME) .github/scripts/fuzz-smoke.sh

vectors:
	$(GO) test -count=1 ./pkg/protocol/...
	python3 -m unittest discover -s protocol/reference

chart-test:
	$(HELM) lint --strict $(CHART)
	$(GO) test -count=1 ./internal/deploytest/

check-deps:
	.github/scripts/check-forbidden-modules.sh

licenses:
	$(GO) run github.com/google/go-licenses/v2@v2.0.1 check ./... --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC --ignore github.com/cloud-exit/exitmesh-agent --ignore github.com/cyphar/filepath-securejoin --ignore github.com/hashicorp/go-envparse

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

reproducible:
	.github/scripts/reproducible-build.sh

release-snapshot:
	eval "$$($(GO) run ./internal/deploytest/releaseinfo | sed 's/^/export /')" && $(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean --skip=sign,sbom,publish

release-check:
	EXITMESH_PROTOCOL_VERSION=1 EXITMESH_SCHEMA_VERSION=1 EXITMESH_ENGINE_VERSION=1 $(GO) run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) check

packages: release-snapshot

# Runs the package smoke test for the snapshot packages in dist/ inside IMAGE (default debian:12); needs docker.
package-smoke:
	docker run --rm -v "$(CURDIR):/src" -w /src $(or $(IMAGE),debian:12) sh .github/scripts/package-smoke.sh dist $(OLD)

chart-validate:
	KUBE_VERSIONS="$(KUBE_VERSIONS)" .github/scripts/chart-validate.sh

# Installs the chart into the kind cluster named by KIND_CLUSTER_NAME (default exitmesh); needs kind, ko, helm, docker.
kind-e2e:
	.github/scripts/kind-integration.sh

next-version:
	@.github/scripts/next-version.sh $(or $(BUMP),patch)

clean:
	rm -rf bin dist dist-chart dist-tools
