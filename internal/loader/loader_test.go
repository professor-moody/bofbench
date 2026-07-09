package loader

import (
	"errors"
	"runtime"
	"testing"
)

func TestRunRequiresWindowsOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows behavior only")
	}
	res, err := Run(Request{Object: "missing.o", Entry: "go"})
	if !errors.Is(err, ErrRequiresWindows) {
		t.Fatalf("err = %v, want ErrRequiresWindows", err)
	}
	if res.Status != "setup_error" || res.ExitState != "requires_windows" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
