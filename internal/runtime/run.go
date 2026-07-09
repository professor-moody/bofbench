package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"
	"time"

	"bofbench/internal/artifact"
	"bofbench/internal/loader"
)

type Request struct {
	Path      string
	Entry     string
	ArgHex    string
	Tokens    []string
	TimeoutMS int
	Runtime   string
}

type Result struct {
	Object     string   `json:"object"`
	Kind       string   `json:"kind"`
	Runtime    string   `json:"runtime"`
	Entry      string   `json:"entry"`
	Status     string   `json:"status"`
	ExitState  string   `json:"exit_state"`
	Output     []string `json:"output,omitempty"`
	Errors     []string `json:"errors,omitempty"`
	Events     []Event  `json:"events,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	Loader     string   `json:"loader,omitempty"`
}

type Event struct {
	Type    string `json:"type"`
	TimeMS  int64  `json:"time_ms"`
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

func Run(req Request) (Result, error) {
	start := time.Now()
	if req.Entry == "" {
		req.Entry = "go"
	}
	kind, err := artifact.Detect(req.Path)
	if err != nil {
		return Result{}, err
	}
	runtimeName := req.Runtime
	if runtimeName == "" || runtimeName == "auto" {
		runtimeName = SelectRuntime(kind)
	}
	base := baseResult(req, kind, runtimeName, start)
	switch runtimeName {
	case "windows-coff":
		if kind != artifact.KindCOFF {
			return fail(base, "wrong_artifact", fmt.Errorf("windows-coff requires COFF artifact, got %s", kind), start)
		}
		res, err := loader.Run(loader.Request{Object: req.Path, Entry: req.Entry, ArgHex: req.ArgHex, TimeoutMS: req.TimeoutMS})
		out := base
		out.Object = res.Object
		out.Entry = res.Entry
		out.Status = res.Status
		out.ExitState = res.ExitState
		out.Output = res.Output
		out.Errors = res.Errors
		out.DurationMS = res.DurationMS
		out.Loader = res.Loader
		finalizeEvents(&out, start)
		return out, err
	case "wine-coff":
		if kind != artifact.KindCOFF {
			return fail(base, "wrong_artifact", fmt.Errorf("wine-coff requires COFF artifact, got %s", kind), start)
		}
		if _, err := exec.LookPath("wine"); err != nil {
			return fail(base, "requires_wine", errors.New("wine runtime requested but wine is not on PATH"), start)
		}
		return fail(base, "not_implemented", errors.New("wine-coff runner is planned but not implemented yet"), start)
	case "linux-elf":
		if kind != artifact.KindELF {
			return fail(base, "wrong_artifact", fmt.Errorf("linux-elf requires ELF artifact, got %s", kind), start)
		}
		if goruntime.GOOS != "linux" {
			return fail(base, "requires_linux", errors.New("linux-elf runtime requires Linux host"), start)
		}
		return runLinkedNativeObject(req, kind, runtimeName, start, base)
	case "darwin-macho":
		if kind != artifact.KindMachO {
			return fail(base, "wrong_artifact", fmt.Errorf("darwin-macho requires Mach-O artifact, got %s", kind), start)
		}
		if goruntime.GOOS != "darwin" {
			return fail(base, "requires_darwin", errors.New("darwin-macho runtime requires macOS host"), start)
		}
		return runLinkedNativeObject(req, kind, runtimeName, start, base)
	default:
		return fail(base, "unknown_runtime", fmt.Errorf("unknown runtime %q", runtimeName), start)
	}
}

func baseResult(req Request, kind artifact.Kind, runtimeName string, start time.Time) Result {
	res := Result{Object: req.Path, Kind: string(kind), Runtime: runtimeName, Entry: req.Entry}
	addTimedEvent(&res, start, "artifact", "detected", fmt.Sprintf("kind=%s path=%s", kind, req.Path))
	addTimedEvent(&res, start, "arg_pack", "pass", fmt.Sprintf("tokens=%d packed_bytes=%d", len(req.Tokens), packedBytes(req.ArgHex)))
	return res
}

func packedBytes(hexValue string) int {
	if hexValue == "" {
		return 0
	}
	return len(hexValue) / 2
}

func AddEvent(res *Result, eventType, status, message string) {
	if res == nil {
		return
	}
	if terminalEventType(eventType) {
		for i := len(res.Events) - 1; i >= 0; i-- {
			if terminalEventType(res.Events[i].Type) {
				res.Events[i] = Event{Type: eventType, TimeMS: res.DurationMS, Status: status, Message: message}
				return
			}
		}
	}
	res.Events = append(res.Events, Event{Type: eventType, TimeMS: res.DurationMS, Status: status, Message: message})
}

func addTimedEvent(res *Result, start time.Time, eventType, status, message string) {
	if res == nil {
		return
	}
	res.Events = append(res.Events, Event{Type: eventType, TimeMS: time.Since(start).Milliseconds(), Status: status, Message: message})
}

func finalizeEvents(res *Result, start time.Time) {
	if res == nil {
		return
	}
	loadStatus := "pass"
	if res.Status != "pass" {
		loadStatus = res.Status
	}
	if !updateEvent(&res.Events, "load", loadStatus, loadMessage(*res)) {
		addTimedEvent(res, start, "load", loadStatus, loadMessage(*res))
	}
	if shouldMarkEntryCall(*res) {
		entryStatus := res.Status
		if res.ExitState == "timeout" {
			entryStatus = "timeout"
		}
		if !updateEvent(&res.Events, "entry_call", entryStatus, fmt.Sprintf("entry=%s", res.Entry)) {
			addTimedEvent(res, start, "entry_call", entryStatus, fmt.Sprintf("entry=%s", res.Entry))
		}
	}
	for _, line := range res.Output {
		addTimedEvent(res, start, "beacon_output", "line", line)
	}
	for _, line := range res.Errors {
		addTimedEvent(res, start, "beacon_error", "line", line)
	}
	switch res.ExitState {
	case "timeout":
		addTimedEvent(res, start, "timeout", res.Status, "loader timed out")
	case "crash":
		addTimedEvent(res, start, "crash", res.Status, "runner reported crash")
	default:
		addTimedEvent(res, start, "exit", res.Status, fmt.Sprintf("exit_state=%s", res.ExitState))
	}
}

func hasEvent(events []Event, eventType string) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func updateEvent(events *[]Event, eventType, status, message string) bool {
	if events == nil {
		return false
	}
	for i := range *events {
		if (*events)[i].Type == eventType {
			(*events)[i].Status = status
			(*events)[i].Message = message
			return true
		}
	}
	return false
}

func terminalEventType(eventType string) bool {
	return eventType == "exit" || eventType == "timeout" || eventType == "crash"
}

func loadMessage(res Result) string {
	if res.Loader != "" {
		return "loader=" + res.Loader
	}
	if len(res.Errors) > 0 {
		return res.Errors[0]
	}
	return "runtime=" + res.Runtime
}

func shouldMarkEntryCall(res Result) bool {
	switch res.ExitState {
	case "loader_missing", "requires_windows", "requires_linux", "requires_darwin", "requires_wine", "wrong_artifact", "unknown_runtime", "not_implemented", "bad_entry", "compiler_missing", "link_error", "relocation_error":
		return false
	default:
		return res.Entry != ""
	}
}

func SelectRuntime(kind artifact.Kind) string {
	switch kind {
	case artifact.KindCOFF:
		return "windows-coff"
	case artifact.KindELF:
		return "linux-elf"
	case artifact.KindMachO:
		return "darwin-macho"
	default:
		return "unknown"
	}
}

func fail(base Result, exit string, err error, start time.Time) (Result, error) {
	base.Status = "setup_error"
	if exit == "not_implemented" || exit == "wrong_artifact" || exit == "unknown_runtime" {
		base.Status = "fail"
	}
	base.ExitState = exit
	base.Errors = []string{err.Error()}
	base.DurationMS = time.Since(start).Milliseconds()
	finalizeEvents(&base, start)
	return base, err
}

var cIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func runLinkedNativeObject(req Request, kind artifact.Kind, runtimeName string, start time.Time, base Result) (Result, error) {
	if !cIdentifier.MatchString(req.Entry) {
		return fail(base, "bad_entry", fmt.Errorf("entrypoint %q is not a C identifier", req.Entry), start)
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		return fail(base, "compiler_missing", fmt.Errorf("%s not found on PATH", cc), start)
	}
	timeout := req.TimeoutMS
	if timeout <= 0 {
		timeout = 5000
	}
	tmp, err := os.MkdirTemp("", "bofbench-native-*")
	if err != nil {
		return fail(base, "setup_error", err, start)
	}
	defer os.RemoveAll(tmp)
	harness := filepath.Join(tmp, "harness.c")
	exe := filepath.Join(tmp, "runner")
	if goruntime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(harness, []byte(nativeHarness(req.Entry)), 0o644); err != nil {
		return fail(base, "setup_error", err, start)
	}
	addTimedEvent(&base, start, "load", "link", fmt.Sprintf("compiler=%s", cc))
	linkCmd := exec.Command(cc, harness, req.Path, "-o", exe)
	var linkOut bytes.Buffer
	linkCmd.Stdout = &linkOut
	linkCmd.Stderr = &linkOut
	if err := linkCmd.Run(); err != nil {
		res := base
		res.Status = "fail"
		res.ExitState = "link_error"
		res.Errors = splitLines(strings.TrimSpace(linkOut.String()))
		if len(res.Errors) == 0 {
			res.Errors = []string{err.Error()}
		}
		res.DurationMS = time.Since(start).Milliseconds()
		res.Loader = cc
		finalizeEvents(&res, start)
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	addTimedEvent(&base, start, "entry_call", "start", fmt.Sprintf("entry=%s", req.Entry))
	runCmd := exec.CommandContext(ctx, exe, tokenValues(req.Tokens)...)
	var stdout, stderr bytes.Buffer
	runCmd.Stdout = &stdout
	runCmd.Stderr = &stderr
	err = runCmd.Run()
	res := base
	res.Output = splitLines(strings.TrimRight(stdout.String(), "\r\n"))
	res.Errors = splitLines(strings.TrimRight(stderr.String(), "\r\n"))
	res.DurationMS = time.Since(start).Milliseconds()
	res.Loader = exe
	if ctx.Err() != nil {
		res.Status = "fail"
		res.ExitState = "timeout"
		res.Errors = append(res.Errors, "native object runner timed out")
		finalizeEvents(&res, start)
		return res, ctx.Err()
	}
	if err != nil {
		res.Status = "fail"
		res.ExitState = "process_error"
		if len(res.Errors) == 0 {
			res.Errors = []string{err.Error()}
		} else {
			res.Errors = append(res.Errors, err.Error())
		}
		finalizeEvents(&res, start)
		return res, err
	}
	res.Status = "pass"
	res.ExitState = "success"
	finalizeEvents(&res, start)
	return res, nil
}

func nativeHarness(entry string) string {
	return fmt.Sprintf(`#include <stdio.h>
extern void %s(int argc, char **argv);
int main(int argc, char **argv) {
    %s(argc - 1, argv + 1);
    return 0;
}
`, entry, entry)
}

func tokenValues(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		_, value, ok := strings.Cut(token, ":")
		if !ok {
			out = append(out, token)
			continue
		}
		out = append(out, trimTokenQuotes(value))
	}
	return out
}

func trimTokenQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func splitLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
