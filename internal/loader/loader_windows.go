//go:build windows

package loader

import (
	"bytes"
	"context"
	"encoding/json"
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
		res.Errors = []string{err.Error()}
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMS)*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--object", req.Object, "--entry", req.Entry, "--arg-hex", req.ArgHex)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		res := NewResult(req, "fail", "timeout", start)
		res.Loader = path
		res.Errors = []string{"loader timed out"}
		return res, ctx.Err()
	}
	var res Result
	if json.Unmarshal(stdout.Bytes(), &res) != nil {
		res = NewResult(req, "fail", "loader_error", start)
		res.Errors = []string{stderr.String(), stdout.String()}
	}
	res.Loader = path
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil && res.Status == "" {
		res.Status = "fail"
		res.ExitState = "loader_error"
		res.Errors = append(res.Errors, err.Error())
	}
	return res, err
}

func loaderPath() (string, error) {
	if p := os.Getenv("BOFBENCH_LOADER"); p != "" {
		return p, nil
	}
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "bofbench-loader.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	candidate := filepath.Join("native", "loader", "bofbench-loader.exe")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	}
	return "", fmt.Errorf("bofbench-loader.exe not found; build native/loader/loader.c and set BOFBENCH_LOADER")
}
