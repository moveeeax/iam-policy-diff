BINARY := iam-policy-diff
PKG := ./...

.PHONY: all build test race vet fmt fmtcheck smoke clean

all: fmtcheck vet race build

build:
	go build -o $(BINARY) .

test:
	go test $(PKG)

race:
	go test -race $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w .

fmtcheck:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-ed:"; echo "$$unformatted"; exit 1; \
	fi

smoke: build
	./$(BINARY) examples/old.json examples/new.json || true
	./$(BINARY) --json --fail-on-risk examples/old.json examples/new.json > /dev/null; \
		test $$? -eq 2 && echo "smoke ok"

clean:
	rm -f $(BINARY) out.json coverage.out
