BIN := work/bin/bofbench
WINBIN := work/bin/bofbench.exe

.PHONY: generate verify-generated test build build-windows native-loader docs doctor release clean

generate:
	go generate ./internal/capability

verify-generated:
	go run ./cmd/capgen -check -out native/loader/capabilities.generated.h

test: verify-generated
	go test ./...

build:
	go build -o $(BIN) ./cmd/bofbench

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(WINBIN) ./cmd/bofbench

native-loader: verify-generated
	$(MAKE) -C native/loader clean all

docs:
	mkdocs build --strict

doctor: build
	$(BIN) doctor

release:
	scripts/release.sh

clean:
	rm -rf work/bin dist/release site
	$(MAKE) -C native/loader clean
