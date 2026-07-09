package loader

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

var ErrRequiresWindows = errors.New("native BOF execution requires Windows x64")

type Request struct {
	Object    string
	Entry     string
	ArgHex    string
	TimeoutMS int
}

type Result struct {
	Object     string           `json:"object"`
	Entry      string           `json:"entry"`
	Status     string           `json:"status"`
	ExitState  string           `json:"exit_state"`
	ErrorCode  string           `json:"error_code,omitempty"`
	Output     []string         `json:"output,omitempty"`
	Errors     []string         `json:"errors,omitempty"`
	DurationMS int64            `json:"duration_ms"`
	Loader     string           `json:"loader,omitempty"`
	Process    *ProcessEvidence `json:"process,omitempty"`
}

type ProcessEvidence struct {
	ExitCode        *int     `json:"exit_code,omitempty"`
	ExceptionCode   string   `json:"exception_code,omitempty"`
	Stdout          []string `json:"stdout,omitempty"`
	Stderr          []string `json:"stderr,omitempty"`
	StdoutTruncated bool     `json:"stdout_truncated,omitempty"`
	StderrTruncated bool     `json:"stderr_truncated,omitempty"`
}

func (r Result) WriteJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func NewResult(req Request, status, exit string, start time.Time) Result {
	return Result{
		Object:     req.Object,
		Entry:      req.Entry,
		Status:     status,
		ExitState:  exit,
		DurationMS: time.Since(start).Milliseconds(),
	}
}
