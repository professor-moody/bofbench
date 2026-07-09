package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"bofbench/internal/capability"
)

func main() {
	out := flag.String("out", "native/loader/capabilities.generated.h", "generated C header path")
	check := flag.Bool("check", false, "verify that the output already matches without writing it")
	flag.Parse()
	data, err := capability.NativeHeader(capability.WindowsCOFF())
	if err != nil {
		fmt.Fprintln(os.Stderr, "capgen:", err)
		os.Exit(1)
	}
	if *check {
		existing, readErr := os.ReadFile(*out)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, "capgen:", readErr)
			os.Exit(1)
		}
		if !bytes.Equal(existing, data) {
			fmt.Fprintf(os.Stderr, "capgen: %s is stale; run go generate ./internal/capability\n", *out)
			os.Exit(1)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "capgen:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "capgen:", err)
		os.Exit(1)
	}
}
