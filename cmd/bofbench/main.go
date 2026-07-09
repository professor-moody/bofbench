package main

import (
	"fmt"
	"os"

	"bofbench/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(app.ExitCode(err))
	}
}
