# mailkey — the MKDP1 reference implementation.
#
# Every target here is what CI runs, so a green `make all` locally is a green
# build. GOWORK=off throughout: a developer's go.work may point this module at
# sibling checkouts, and CI resolves from go.mod alone — the two must agree, or
# a missing requirement only surfaces for whoever clones the repo on its own.

.PHONY: all build vet test race check fmt fuzz tidy verify

GOWORK := off
export GOWORK

# How long each fuzz target runs in `make fuzz`. Fuzzing has found four real
# defects in this repository, so it is a build step rather than a ritual.
FUZZTIME ?= 30s

all: check fmt vet build test

## build: compile all packages
build:
	go build ./...

## vet: run go vet
vet:
	go vet ./...

## test: run tests with the race detector
##
## -race is not optional here: the peer service runs background workers and the
## resolver coalesces concurrent lookups, which is exactly the code a
## single-threaded test run cannot judge.
test:
	go test -race ./...

## race: alias for test, kept explicit for anyone looking for it by name
race: test

## check: the protocol packages must not depend on glue or zap
check:
	@bash scripts/check-core-deps.sh

## fmt: fail if anything is unformatted (CI must not rewrite the tree)
fmt:
	@unformatted="$$(gofmt -l . 2>/dev/null)"; \
	if [ -n "$$unformatted" ]; then \
		echo "✗ unformatted files:"; echo "$$unformatted" | sed 's/^/    /'; \
		echo "run: gofmt -w ."; exit 1; \
	fi; \
	echo "✓ gofmt clean"

## verify: the module graph is intact and go.mod/go.sum are tidy
verify:
	go mod verify
	@cp go.mod /tmp/mailkey.go.mod.bak; cp go.sum /tmp/mailkey.go.sum.bak; \
	go mod tidy; \
	if ! diff -q go.mod /tmp/mailkey.go.mod.bak >/dev/null || ! diff -q go.sum /tmp/mailkey.go.sum.bak >/dev/null; then \
		cp /tmp/mailkey.go.mod.bak go.mod; cp /tmp/mailkey.go.sum.bak go.sum; \
		echo "✗ go.mod/go.sum are not tidy — run: go mod tidy"; exit 1; \
	fi; \
	echo "✓ go.mod/go.sum tidy"

## fuzz: run every fuzz target briefly, on top of the committed seed corpora
fuzz:
	go test ./manifest/  -run '^$$' -fuzz FuzzParseCanonical -fuzztime $(FUZZTIME)
	go test ./manifest/  -run '^$$' -fuzz FuzzDecodeID       -fuzztime $(FUZZTIME)
	go test ./discovery/ -run '^$$' -fuzz FuzzNormalize      -fuzztime $(FUZZTIME)
	go test ./discovery/ -run '^$$' -fuzz FuzzParseHeader    -fuzztime $(FUZZTIME)
	go test ./discovery/ -run '^$$' -fuzz FuzzParseDNS       -fuzztime $(FUZZTIME)
	go test ./envelope/  -run '^$$' -fuzz FuzzUnmarshal      -fuzztime $(FUZZTIME)

## tidy: tidy go.mod
tidy:
	go mod tidy
