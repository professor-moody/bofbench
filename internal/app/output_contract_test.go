package app

import (
	"strings"
	"testing"

	"github.com/professor-moody/bofbench/internal/config"
	"github.com/professor-moody/bofbench/internal/loader"
	runtimesvc "github.com/professor-moody/bofbench/internal/runtime"
)

func TestApplyOutputChecks(t *testing.T) {
	res := runtimesvc.Result{Status: "pass", Output: []string{"operator hello"}}
	if err := applyOutputChecks(&res, []string{"hello"}, []string{"panic"}); err != nil {
		t.Fatal(err)
	}
	if res.Status != "pass" {
		t.Fatalf("status = %s", res.Status)
	}

	res = runtimesvc.Result{Status: "pass", Output: []string{"panic"}}
	err := applyOutputChecks(&res, []string{"hello"}, []string{"panic"})
	if err == nil || res.ExitState != "output_contract_failed" {
		t.Fatalf("expected output contract failure: res=%+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), "missing expected output") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRuntimeEvent(res, "api_event") {
		t.Fatalf("expected output contract event: %+v", res.Events)
	}
	if got := lastTerminalEvent(res); got.Message != "exit_state=output_contract_failed" {
		t.Fatalf("terminal event not updated: %+v", res.Events)
	}
}

func TestRunMarkdownIncludesLoaderProcessEvidence(t *testing.T) {
	exitCode := 3221225477
	markdown := runMarkdown(runtimesvc.Result{
		Object:          "crash.o",
		Kind:            "coff",
		Runtime:         "windows-coff",
		Entry:           "go",
		Status:          "fail",
		ExitState:       "crash",
		LoaderErrorCode: "windows_exception",
		LoaderProcess: &loader.ProcessEvidence{
			ExitCode:        &exitCode,
			ExceptionCode:   "0xc0000005",
			Stderr:          []string{"native stderr"},
			StdoutTruncated: true,
		},
	}, nil)
	for _, want := range []string{"Loader error code: `windows_exception`", "Windows exception: `0xc0000005`", "Loader Process Streams", "native stderr", "stdout=true"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("run Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestRunMarkdownIncludesLoaderMemoryEvidence(t *testing.T) {
	markdown := runMarkdown(runtimesvc.Result{
		LoaderMemory: &loader.MemoryEvidence{
			InitialProtection:          "readwrite",
			WritableExecutableSections: 0,
			Sections: []loader.SectionMemoryEvidence{{
				Index:           0,
				Name:            ".text",
				Offset:          0x1000,
				MappedSize:      144,
				AllocationSize:  4096,
				Characteristics: 0x60500020,
				Protection:      "execute_read",
			}},
			StubRegion: loader.RegionMemoryEvidence{
				Offset:         0x2000,
				AllocationSize: 4096,
				Protection:     "execute_read",
			},
		},
	}, nil)
	for _, want := range []string{"Loader Memory", "Initial protection: `readwrite`", "Writable/executable sections: `0`", "`.text`", "`0x60500020`", "Stub Region", "Protection: `execute_read`"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("run Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestApplyExpectedResult(t *testing.T) {
	res := runtimesvc.Result{Status: "fail", ExitState: "relocation_error"}
	expected, err := applyExpectedResult(&res, config.Project{ExpectedExit: "relocation_error"})
	if err != nil {
		t.Fatal(err)
	}
	if !expected {
		t.Fatal("expected result was not recognized")
	}

	res = runtimesvc.Result{Status: "fail", ExitState: "timeout"}
	expected, err = applyExpectedResult(&res, config.Project{ExpectedExit: "relocation_error"})
	if err == nil || expected {
		t.Fatalf("expected mismatch error, expected=%v err=%v", expected, err)
	}
	if !strings.Contains(err.Error(), "expected exit") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRuntimeEvent(res, "api_event") {
		t.Fatalf("expected mismatch event: %+v", res.Events)
	}
}

func hasRuntimeEvent(res runtimesvc.Result, eventType string) bool {
	for _, event := range res.Events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func lastTerminalEvent(res runtimesvc.Result) runtimesvc.Event {
	for i := len(res.Events) - 1; i >= 0; i-- {
		switch res.Events[i].Type {
		case "exit", "timeout", "crash":
			return res.Events[i]
		}
	}
	return runtimesvc.Event{}
}
