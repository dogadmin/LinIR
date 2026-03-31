VERSION := 0.1.0
MODULE  := github.com/dogadmin/LinIR
LDFLAGS := -ldflags="-s -w -X $(MODULE)/internal/config.Version=$(VERSION)"
STATIC  := CGO_ENABLED=0

.PHONY: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-all clean test vet

build-linux:
	$(STATIC) GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/linir-linux-amd64 ./cmd/linir

build-linux-arm64:
	$(STATIC) GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/linir-linux-arm64 ./cmd/linir

build-darwin:
	$(STATIC) GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/linir-darwin-amd64 ./cmd/linir

build-darwin-arm64:
	$(STATIC) GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/linir-darwin-arm64 ./cmd/linir

build-linux-yara:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags yara $(LDFLAGS) -o bin/linir-linux-amd64-yara ./cmd/linir

build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64

clean:
	rm -rf bin/

test:
	go test ./...

vet:
	go vet ./...
