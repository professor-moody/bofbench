#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

go test ./internal/lab ./internal/runtimeadapter ./internal/app
go test -race ./internal/lab ./internal/runtimeadapter ./internal/app
go vet ./internal/lab ./internal/runtimeadapter ./internal/app

echo "BOFBench operator-lab and EDR export offline qualification passed"
