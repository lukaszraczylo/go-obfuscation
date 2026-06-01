APP_NAME      := demoapp
SRC_DIR       := cmd/demoapp
BUILD_DIR     := build
OBFUSCATED    := $(BUILD_DIR)/obfuscated
BINARY        := $(BUILD_DIR)/$(APP_NAME)
BINARY_NORMAL := $(BUILD_DIR)/$(APP_NAME)-normal
BINARY_GARBLE := $(BUILD_DIR)/$(APP_NAME)-garbled
SEED          := $(shell date +%s%N)

GARBLE        := $(shell go env GOPATH)/bin/garble

.PHONY: all clean normal obfuscated compare transformer inthash pure-syscall help run run-normal test verify lint vet fmt

help:
	@echo "Targets:"
	@echo "  make obfuscated  - Full pipeline: transform + garble + integrity"
	@echo "  make normal      - Build normal binary for comparison"
	@echo "  make compare     - Build both and compare"
	@echo "  make transformer - Build only the transformer tool"
	@echo "  make inthash     - Build only the integrity hash tool"
	@echo "  make run         - Run the obfuscated binary"
	@echo "  make run-normal  - Run the normal binary"
	@echo "  make test        - Run all package tests"
	@echo "  make verify      - go vet + go test (CI gate)"
	@echo "  make lint        - gofmt + go vet"
	@echo "  make fmt         - gofmt -w on all sources"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make pure-syscall - Build with minimal libc linkage (CGO_ENABLED=0)"

all: obfuscated

transformer:
	@echo "=== Building transformer ==="
	go build -buildvcs=false -o $(BUILD_DIR)/transformer ./cmd/transformer

obfuscated: transformer
	@echo ""
	@echo "=== Stage 1: AST Transformation ==="
	@rm -rf $(OBFUSCATED)
	$(BUILD_DIR)/transformer -src $(SRC_DIR) -dst $(OBFUSCATED)/$(APP_NAME) -seed=$(SEED)
	@echo ""
	@echo "=== Stage 2: Garble compilation ==="
	@mkdir -p $(BUILD_DIR)
	$(GARBLE) -literals -tiny build \
		-buildvcs=false \
		-trimpath \
		-ldflags="-s -w -buildid=" \
		-o $(BINARY_GARBLE) \
		./$(OBFUSCATED)/$(APP_NAME)
	@echo ""
	@echo "=== Stage 3: Compute integrity hash ==="
	@$$(go env GOPATH)/bin/garble version >/dev/null 2>&1 || true
	@HASH=$$(go run -buildvcs=false ./cmd/inthash $(BINARY_GARBLE) 2>/dev/null); \
	if [ -n "$$HASH" ]; then \
		echo "Integrity hash: $$HASH"; \
	else \
		echo "Note: integrity hash tool not built (run 'make inthash' first)"; \
	fi
	@echo ""
	@echo "=== Stage 4: Analysis ==="
	@echo "Size: $$(wc -c < $(BINARY_GARBLE) | tr -d ' ') bytes"
	@echo "Symbols: $$(nm $(BINARY_GARBLE) 2>/dev/null | wc -l | tr -d ' ')"
	@echo "Readable strings: $$(strings $(BINARY_GARBLE) | wc -l | tr -d ' ')"
	@echo ""
	@echo "=== Secret leakage scan ==="
	@for s in "sk-proj-FAKE" "super-secret" "P@ssw0rd" "jwt-signing" "LIC-XXXX" "postgres://"; do \
		count=$$(strings $(BINARY_GARBLE) | grep -c "$$s" || true); \
		if [ "$$count" != "0" ]; then \
			echo "  LEAKED: $$s"; \
		else \
			echo "  clean:  $$s"; \
		fi; \
	done
	@echo ""
	@echo "=== Anti-analysis check ==="
	@echo "Function names visible:"
	@nm $(BINARY_GARBLE) 2>/dev/null | grep -c "main\." || echo "  0 (good)"
	@echo ""
	@echo "=== Done. Binary: $(BINARY_GARBLE) ==="

inthash:
	@echo "=== Building integrity hash tool ==="
	go build -buildvcs=false -o $(BUILD_DIR)/inthash ./cmd/inthash

pure-syscall: transformer
	@echo "=== Pure-syscall build (minimal libc linkage) ==="
	@mkdir -p $(BUILD_DIR)
	@rm -rf $(OBFUSCATED)
	$(BUILD_DIR)/transformer -src $(SRC_DIR) -dst $(OBFUSCATED)/$(APP_NAME) -seed=$(SEED)
	CGO_ENABLED=0 go build -buildvcs=false -trimpath \
		-ldflags="-s -w -buildid= -extldflags=-Wl,--exclude-libs,ALL" \
		-o $(BUILD_DIR)/$(APP_NAME)-syscall \
		./$(OBFUSCATED)/$(APP_NAME)
	@echo "Built: $(BUILD_DIR)/$(APP_NAME)-syscall"

normal:
	@echo "=== Building normal (unobfuscated) binary ==="
	@mkdir -p $(BUILD_DIR)
	go build -buildvcs=false -o $(BINARY_NORMAL) ./$(SRC_DIR)
	@echo "Size: $$(wc -c < $(BINARY_NORMAL) | tr -d ' ') bytes"
	@echo "Symbols: $$(nm $(BINARY_NORMAL) 2>/dev/null | wc -l | tr -d ' ')"
	@echo "Readable strings: $$(strings $(BINARY_NORMAL) | wc -l | tr -d ' ')"
	@echo ""
	@echo "=== Secret leakage scan ==="
	@for s in "sk-proj-FAKE" "super-secret" "P@ssw0rd" "jwt-signing" "LIC-XXXX" "postgres://"; do \
		count=$$(strings $(BINARY_NORMAL) | grep -c "$$s" || true); \
		if [ "$$count" != "0" ]; then \
			echo "  LEAKED: $$s"; \
		else \
			echo "  clean:  $$s"; \
		fi; \
	done

compare: normal obfuscated
	@echo ""
	@echo "========================================="
	@echo "         COMPARISON SUMMARY"
	@echo "========================================="
	@echo "                 Normal      Obfuscated"
	@echo "Size:            $$(wc -c < $(BINARY_NORMAL) | tr -d ' ')    $$(wc -c < $(BINARY_GARBLE) | tr -d ' ')"
	@echo "Symbols:         $$(nm $(BINARY_NORMAL) 2>/dev/null | wc -l | tr -d ' ')        $$(nm $(BINARY_GARBLE) 2>/dev/null | wc -l | tr -d ' ')"
	@echo "Strings:         $$(strings $(BINARY_NORMAL) | wc -l | tr -d ' ')      $$(strings $(BINARY_GARBLE) | wc -l | tr -d ' ')"
	@echo "========================================="

run: obfuscated
	@$(BINARY_GARBLE)

run-normal: normal
	@$(BINARY_NORMAL)

clean:
	rm -rf $(BUILD_DIR)

fmt:
	@echo "=== gofmt ==="
	@find . -name '*.go' -not -path './build/*' -print0 | xargs -0 gofmt -l -w

vet:
	@echo "=== go vet ==="
	go vet -unsafeptr=false ./...

test:
	@echo "=== go test ==="
	go test ./...

lint: fmt vet

verify: vet test
