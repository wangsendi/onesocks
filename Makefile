GO ?= go
VERSION ?= dev
TAGS ?= with_utls

.PHONY: build run test race clean

build:
	mkdir -p bin
	$(GO) build -tags '$(TAGS)' -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/onesocks ./cmd/onesocks

run:
	$(GO) run -tags '$(TAGS)' ./cmd/onesocks -config configs/config.example.yaml

test:
	$(GO) test -tags '$(TAGS)' ./...

race:
	$(GO) test -race -tags '$(TAGS)' ./...

clean:
	rm -f bin/onesocks
