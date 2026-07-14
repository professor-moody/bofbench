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
	Arch      string
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
	Memory     *MemoryEvidence  `json:"memory,omitempty"`
}

type ProcessEvidence struct {
	ExitCode        *int     `json:"exit_code,omitempty"`
	ExceptionCode   string   `json:"exception_code,omitempty"`
	Stdout          []string `json:"stdout,omitempty"`
	Stderr          []string `json:"stderr,omitempty"`
	StdoutTruncated bool     `json:"stdout_truncated,omitempty"`
	StderrTruncated bool     `json:"stderr_truncated,omitempty"`
}

type MemoryEvidence struct {
	InitialProtection          string                  `json:"initial_protection"`
	Sections                   []SectionMemoryEvidence `json:"sections"`
	StubRegion                 RegionMemoryEvidence    `json:"stub_region"`
	WritableExecutableSections int                     `json:"writable_executable_sections"`
}

type SectionMemoryEvidence struct {
	Index           int    `json:"index"`
	Name            string `json:"name"`
	Offset          uint64 `json:"offset"`
	MappedSize      uint64 `json:"mapped_size"`
	AllocationSize  uint64 `json:"allocation_size"`
	Characteristics uint32 `json:"characteristics"`
	Protection      string `json:"protection"`
}

type RegionMemoryEvidence struct {
	Offset         uint64 `json:"offset"`
	AllocationSize uint64 `json:"allocation_size"`
	Protection     string `json:"protection"`
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
