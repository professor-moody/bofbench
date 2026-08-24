BIN := work/bin/bofbench
WINBIN := work/bin/bofbench.exe

.PHONY: generate verify-generated test build build-windows native-loader docs docs-check docs-media doctor verify-release-manifest release clean

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
	@private="$${BOFBENCH_PRIVATE_CATALOG:-$(abspath ../bofbench-packs-internal)}"; \
	if [ -f "$$private/mkdocs.yml" ]; then \
		(cd "$$private" && mkdocs build --strict); \
	else \
		echo "private handbook unavailable: $$private"; \
	fi

docs-check:
	scripts/docs-check.sh

docs-media:
	scripts/docs-media.sh

doctor: build
	$(BIN) doctor

verify-release-manifest:
	python3 scripts/verify-release-manifest.py

release:
	scripts/release.sh

clean:
	rm -rf work/bin dist/release site
	$(MAKE) -C native/loader clean
