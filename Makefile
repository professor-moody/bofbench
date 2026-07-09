BIN := work/bin/bofbench
WINBIN := work/bin/bofbench.exe

.PHONY: test build build-windows native-loader docs doctor release clean

test:
	go test ./...

build:
	go build -o $(BIN) ./cmd/bofbench

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(WINBIN) ./cmd/bofbench

native-loader:
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
