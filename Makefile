BIN := work/bin/bofbench
WINBIN := work/bin/bofbench.exe
ANALYZER_CORPUS ?= testdata/analyzer-corpus-v1.json
ANALYZER_CORPUS_REPORT ?= work/analyzer-corpus-evaluation.json

.PHONY: generate verify-generated test build build-windows native-loader docs docs-check docs-media doctor analyzer-corpus analyzer-corpus-v2 analyzer-corpus-v3 verify-release-manifest release clean

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

analyzer-corpus:
	@commit="$$(git rev-parse HEAD)"; \
	build_time="$$(git show -s --format=%cI HEAD)"; \
	go build -trimpath -ldflags "-X github.com/professor-moody/bofbench/internal/evidence.Version=dev -X github.com/professor-moody/bofbench/internal/evidence.Commit=$$commit -X github.com/professor-moody/bofbench/internal/evidence.BuildTime=$$build_time" -o $(BIN) ./cmd/bofbench; \
	python3 scripts/evaluate-analyzer-corpus.py --bin $(BIN) --corpus $(ANALYZER_CORPUS) --output $(ANALYZER_CORPUS_REPORT)

analyzer-corpus-v2:
	$(MAKE) analyzer-corpus \
		ANALYZER_CORPUS=testdata/analyzer-corpus-v2.json \
		ANALYZER_CORPUS_REPORT=work/analyzer-corpus-v2-evaluation.json

analyzer-corpus-v3:
	$(MAKE) analyzer-corpus \
		ANALYZER_CORPUS=testdata/analyzer-corpus-v3.json \
		ANALYZER_CORPUS_REPORT=work/analyzer-corpus-v3-evaluation.json

verify-release-manifest:
	python3 scripts/verify-release-manifest.py

release:
	scripts/release.sh

clean:
	rm -rf work/bin dist/release site
	$(MAKE) -C native/loader clean
