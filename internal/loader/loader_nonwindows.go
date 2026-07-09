//go:build !windows

package loader

import "time"

func Run(req Request) (Result, error) {
	start := time.Now()
	res := NewResult(req, "setup_error", "requires_windows", start)
	res.ErrorCode = "requires_windows"
	res.Errors = []string{ErrRequiresWindows.Error()}
	return res, ErrRequiresWindows
}
