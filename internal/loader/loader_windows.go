//go:build windows

package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func Run(req Request) (Result, error) {
	start := time.Now()
	if req.TimeoutMS <= 0 {
		req.TimeoutMS = 5000
	}
	path, err := loaderPath()
	if err != nil {
		res := NewResult(req, "setup_error", "loader_missing", start)
		res.ErrorCode = "loader_missing"
		res.Errors = []string{err.Error()}
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMS)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--object", req.Object, "--entry", req.Entry, "--arg-hex", req.ArgHex)
	stdout := newBoundedBuffer(maxProcessStreamBytes)
	stderr := newBoundedBuffer(maxProcessStreamBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	process := &ProcessEvidence{
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		Stderr:          processLines(stderr.Bytes()),
	}
	if cmd.ProcessState != nil {
		exitCode := cmd.ProcessState.ExitCode()
		process.ExitCode = &exitCode
	}
	if cmd.ProcessState == nil && err != nil {
		res := NewResult(req, "setup_error", "loader_start_error", start)
		res.Loader = path
		res.ErrorCode = "process_start"
		res.Process = process
		res.Errors = []string{err.Error()}
		return res, err
	}
	if ctx.Err() != nil {
		res := NewResult(req, "fail", "timeout", start)
		res.Loader = path
		res.ErrorCode = "loader_timeout"
		res.Process = process
		process.Stdout = processLines(stdout.Bytes())
		res.Errors = []string{"loader timed out"}
		if process.StdoutTruncated || process.StderrTruncated {
			res.Errors = append(res.Errors, "loader process output was truncated")
		}
		return res, ctx.Err()
	}
	var res Result
	resultErr := err
	prefix, decoded := decodeLoaderOutput(stdout.Bytes(), &res)
	protocolValid := decoded
	process.Stdout = prefix
	if !decoded {
		res = NewResult(req, "fail", "loader_protocol_error", start)
		res.ErrorCode = "invalid_loader_json"
		process.Stdout = processLines(stdout.Bytes())
		res.Errors = append([]string(nil), process.Stderr...)
		res.Errors = append(res.Errors, process.Stdout...)
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if exception, crashed := windowsExceptionCode(exitErr.ExitCode()); crashed {
					res.ExitState = "crash"
					res.ErrorCode = "windows_exception"
					process.ExceptionCode = exception
					res.Errors = append(res.Errors, "loader terminated with Windows exception "+exception)
				}
			}
		}
		if len(res.Errors) == 0 {
			res.Errors = []string{"loader did not emit a valid JSON result"}
		}
		if resultErr == nil {
			resultErr = errors.New("loader did not emit a valid JSON result")
		}
	} else if res.Status == "" || res.ExitState == "" {
		protocolValid = false
		res = NewResult(req, "fail", "loader_protocol_error", start)
		res.ErrorCode = "incomplete_loader_json"
		res.Errors = []string{"loader JSON result is missing status or exit_state"}
		resultErr = errors.New(res.Errors[0])
	} else if res.Status != "pass" && res.Status != "fail" && res.Status != "setup_error" {
		protocolValid = false
		res = NewResult(req, "fail", "loader_protocol_error", start)
		res.ErrorCode = "invalid_loader_status"
		res.Errors = []string{"loader JSON result has an invalid status"}
		resultErr = errors.New(res.Errors[0])
	}
	res.Loader = path
	res.Process = process
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil && protocolValid && res.Status == "pass" {
		res.Status = "fail"
		res.ExitState = "loader_protocol_error"
		res.ErrorCode = "exit_status_mismatch"
		res.Errors = append(res.Errors, err.Error())
	} else if err == nil && protocolValid && res.Status != "pass" {
		res.Status = "fail"
		res.ExitState = "loader_protocol_error"
		res.ErrorCode = "exit_status_mismatch"
		res.Errors = append(res.Errors, "loader returned a failure result with a successful process exit")
		resultErr = errors.New(res.Errors[len(res.Errors)-1])
	}
	if process.StdoutTruncated || process.StderrTruncated {
		res.Errors = append(res.Errors, "loader process output was truncated")
		if resultErr == nil {
			resultErr = errors.New("loader process output exceeded the capture limit")
		}
		if res.Status == "pass" {
			res.Status = "fail"
			res.ExitState = "loader_output_limit"
			res.ErrorCode = "process_output_truncated"
		}
	}
	return res, resultErr
}

func loaderPath() (string, error) {
	if p := os.Getenv("BOFBENCH_LOADER"); p != "" {
		info, err := os.Stat(p)
		if err != nil {
			return "", fmt.Errorf("BOFBENCH_LOADER %s: %w", p, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("BOFBENCH_LOADER %s is not a regular file", p)
		}
		return p, nil
	}
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "bofbench-loader.exe")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	candidate := filepath.Join("native", "loader", "bofbench-loader.exe")
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		return candidate, nil
	}
	return "", fmt.Errorf("bofbench-loader.exe not found; build native/loader/loader.c and set BOFBENCH_LOADER")
}
