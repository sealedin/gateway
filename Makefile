BINARY := build/gateway-identity
RPCPROXY_BINARY := build/gateway-rpcproxy
SALES_BINARY := build/gateway-sales
DRAIN_BINARY := build/gateway-drain
SYNC_BINARY := build/sync-measurements

.PHONY: tidy fmt fmt-check lint test build build-egress build-rpcproxy build-sales build-drain build-sync-measurements sync-measurements build-reproducible e2e-stream-billing vuln static audit-image all

tidy:
	go mod tidy && git diff --exit-code go.mod go.sum

fmt:
	goimports -w cmd internal

fmt-check:
	@out=$$(gofmt -l -s cmd internal); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

lint:
	go vet ./... && golangci-lint run -c .golangci.yml
	./scripts/check-isolation.sh
	./scripts/check-image-pins.sh

test:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

build:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o $(BINARY) ./cmd/identity

build-egress:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o build/gateway-egress ./cmd/egress

build-rpcproxy:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o $(RPCPROXY_BINARY) ./cmd/rpcproxy

build-sales:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o $(SALES_BINARY) ./cmd/sales

build-drain:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o $(DRAIN_BINARY) ./cmd/drain

build-sync-measurements:
	go build -trimpath -buildvcs=false -ldflags "-s -w -buildid=" -o $(SYNC_BINARY) ./cmd/sync-measurements

# make maps every failure to 2; CI runs the binary itself to tell the exit codes apart (internal/measurements).
sync-measurements: build-sync-measurements
	./$(SYNC_BINARY)

e2e-stream-billing:
	./scripts/e2e/stream-billing.sh

build-reproducible:
	$(MAKE) build BINARY=build/a && $(MAKE) build BINARY=build/b
	@shasum -a 256 build/a build/b
	@test "$$(shasum -a 256 build/a | cut -d' ' -f1)" = "$$(shasum -a 256 build/b | cut -d' ' -f1)"
	$(MAKE) build-rpcproxy RPCPROXY_BINARY=build/c && $(MAKE) build-rpcproxy RPCPROXY_BINARY=build/d
	@shasum -a 256 build/c build/d
	@test "$$(shasum -a 256 build/c | cut -d' ' -f1)" = "$$(shasum -a 256 build/d | cut -d' ' -f1)"
	$(MAKE) build-sales SALES_BINARY=build/e && $(MAKE) build-sales SALES_BINARY=build/f
	@shasum -a 256 build/e build/f
	@test "$$(shasum -a 256 build/e | cut -d' ' -f1)" = "$$(shasum -a 256 build/f | cut -d' ' -f1)"
	$(MAKE) build-drain DRAIN_BINARY=build/g && $(MAKE) build-drain DRAIN_BINARY=build/h
	@shasum -a 256 build/g build/h
	@test "$$(shasum -a 256 build/g | cut -d' ' -f1)" = "$$(shasum -a 256 build/h | cut -d' ' -f1)"

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# shellcheck, hadolint, actionlint, zizmor and ruff from digest-pinned images; needs a Docker daemon.
static:
	./scripts/static-checks.sh

# Report only: known vulnerabilities in the pinned LiteLLM image, an input to the next upgrade (docs/litellm-pin.md).
audit-image:
	./scripts/audit-litellm-image.sh

all: tidy fmt-check lint test build build-egress build-rpcproxy build-sales build-drain build-sync-measurements
