package lab

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

func startRemoteProgressPoller(parent context.Context, opts RemoteOptions, path string, progress func(string)) func() {
	if progress == nil || path == "" {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	var wait sync.WaitGroup
	wait.Add(1)
	seen := 0
	poll := func(pollContext context.Context) {
		stdout, _, err := remoteExecute(pollContext, opts, fmt.Sprintf(`if(Test-Path -LiteralPath %s){[Console]::Out.Write([IO.File]::ReadAllText(%s))}`, powerShellQuote(path), powerShellQuote(path)))
		if err != nil || len(stdout) <= seen {
			return
		}
		text := string(stdout[seen:])
		seen = len(stdout)
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				progress(line)
			}
		}
	}
	go func() {
		defer wait.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				poll(ctx)
			}
		}
	}()
	return func() {
		poll(context.Background())
		cancel()
		wait.Wait()
	}
}

type winRMTransportFunc func(context.Context, RemoteOptions, string, string) ([]byte, []byte, error)

var executeWinRMTransport winRMTransportFunc = runWinRMTransport

// ExecutePowerShell runs a bounded PowerShell operation through the profile's
// selected transport. It is used by independent state verification and lab
// probes that do not need project synchronization.
func ExecutePowerShell(ctx context.Context, opts RemoteOptions, script string) ([]byte, []byte, error) {
	normalized, err := normalizeRemoteOptions(opts)
	if err != nil {
		return nil, nil, err
	}
	return remoteExecute(ctx, normalized, script)
}

// UploadFile copies one local artifact to an exact path through the selected
// SSH or WinRM transport. It is intentionally low level: callers own process
// launch, lifecycle, and cleanup semantics.
func UploadFile(ctx context.Context, opts RemoteOptions, localPath, remotePath string) ([]byte, []byte, error) {
	normalized, err := normalizeRemoteOptions(opts)
	if err != nil {
		return nil, nil, err
	}
	return remoteUploadFile(ctx, normalized, localPath, remotePath)
}

func remoteExecute(ctx context.Context, opts RemoteOptions, script string) ([]byte, []byte, error) {
	if opts.Transport == "winrm" {
		return executeWinRMTransport(ctx, opts, script, "")
	}
	args := sshBaseArgs(opts)
	args = append(args, sshTarget(opts), script)
	return executeRemoteTransport(ctx, opts.SSH, args...)
}

func remoteUploadFile(ctx context.Context, opts RemoteOptions, localPath, remotePath string) ([]byte, []byte, error) {
	if opts.Transport == "winrm" {
		data, err := os.ReadFile(localPath)
		if err != nil {
			return nil, nil, err
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $parent=Split-Path -Parent %s; if($parent){New-Item -ItemType Directory -Force -Path $parent | Out-Null}; $encoded=[Console]::In.ReadToEnd(); [IO.File]::WriteAllBytes(%s,[Convert]::FromBase64String($encoded))`, powerShellQuote(remotePath), powerShellQuote(remotePath))
		return executeWinRMTransport(ctx, opts, script, encoded)
	}
	args := scpBaseArgs(opts)
	args = append(args, localPath, remoteSpec(sshTarget(opts), remotePath))
	return executeRemoteTransport(ctx, opts.SCP, args...)
}

func remoteDownloadFile(ctx context.Context, opts RemoteOptions, remotePath, localPath string) ([]byte, []byte, error) {
	if opts.Transport == "winrm" {
		script := fmt.Sprintf(`$ErrorActionPreference='Stop'; [Convert]::ToBase64String([IO.File]::ReadAllBytes(%s))`, powerShellQuote(remotePath))
		stdout, stderr, err := executeWinRMTransport(ctx, opts, script, "")
		if err != nil {
			return stdout, stderr, err
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stdout)))
		if err != nil {
			return stdout, stderr, fmt.Errorf("decode WinRM download %s: %w", remotePath, err)
		}
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			return stdout, stderr, err
		}
		if err := os.WriteFile(localPath, data, 0o600); err != nil {
			return stdout, stderr, err
		}
		return stdout, stderr, nil
	}
	args := scpBaseArgs(opts)
	args = append(args, remoteSpec(sshTarget(opts), remotePath), localPath)
	return executeRemoteTransport(ctx, opts.SCP, args...)
}

func remoteUploadDirectory(ctx context.Context, opts RemoteOptions, localDirectory, remoteDirectory string) ([]byte, []byte, error) {
	if opts.Transport != "winrm" {
		args := scpBaseArgs(opts)
		args = append(args, "-r", localDirectory, remoteSpec(sshTarget(opts), windowsDir(remoteDirectory)))
		return executeRemoteTransport(ctx, opts.SCP, args...)
	}
	temporary, err := os.CreateTemp("", "bofbench-upload-*.zip")
	if err != nil {
		return nil, nil, err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return nil, nil, err
	}
	defer os.Remove(temporaryPath)
	if err := zipDirectory(localDirectory, temporaryPath); err != nil {
		return nil, nil, err
	}
	remoteArchive := remoteDirectory + ".bofbench.zip"
	stdout, stderr, err := remoteUploadFile(ctx, opts, temporaryPath, remoteArchive)
	if err != nil {
		return stdout, stderr, err
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}; New-Item -ItemType Directory -Force -Path %s | Out-Null; Expand-Archive -LiteralPath %s -DestinationPath %s -Force; Remove-Item -LiteralPath %s -Force`, powerShellQuote(remoteDirectory), powerShellQuote(remoteDirectory), powerShellQuote(remoteDirectory), powerShellQuote(remoteArchive), powerShellQuote(remoteDirectory), powerShellQuote(remoteArchive))
	return remoteExecute(ctx, opts, script)
}

func remoteDownloadDirectory(ctx context.Context, opts RemoteOptions, remoteDirectory, localDirectory string) ([]byte, []byte, error) {
	if opts.Transport != "winrm" {
		args := scpBaseArgs(opts)
		args = append(args, "-r", remoteSpec(sshTarget(opts), remoteDirectory), localDirectory)
		return executeRemoteTransport(ctx, opts.SCP, args...)
	}
	remoteArchive := remoteDirectory + ".bofbench-download.zip"
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; if(Test-Path %s){Remove-Item -LiteralPath %s -Force}; Compress-Archive -Path (%s + '\*') -DestinationPath %s -Force`, powerShellQuote(remoteArchive), powerShellQuote(remoteArchive), powerShellQuote(remoteDirectory), powerShellQuote(remoteArchive))
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		return stdout, stderr, err
	}
	localArchive := localDirectory + ".zip"
	defer os.Remove(localArchive)
	stdout, stderr, err = remoteDownloadFile(ctx, opts, remoteArchive, localArchive)
	_, _, _ = remoteExecute(ctx, opts, fmt.Sprintf(`Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue`, powerShellQuote(remoteArchive)))
	if err != nil {
		return stdout, stderr, err
	}
	if err := unzipDirectory(localArchive, localDirectory); err != nil {
		return stdout, stderr, err
	}
	return stdout, stderr, nil
}

func sshBaseArgs(opts RemoteOptions) []string {
	args := []string{}
	if opts.JumpHost != "" {
		args = append(args, "-o", "ProxyJump="+opts.JumpHost)
	}
	if opts.Port != 0 && opts.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", opts.Port))
	}
	if opts.IdentityFile != "" {
		args = append(args, "-i", opts.IdentityFile)
	}
	if opts.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+opts.KnownHosts)
	}
	return args
}

func scpBaseArgs(opts RemoteOptions) []string {
	args := []string{}
	if opts.JumpHost != "" {
		args = append(args, "-o", "ProxyJump="+opts.JumpHost)
	}
	if opts.Port != 0 && opts.Port != 22 {
		args = append(args, "-P", fmt.Sprintf("%d", opts.Port))
	}
	if opts.IdentityFile != "" {
		args = append(args, "-i", opts.IdentityFile)
	}
	if opts.KnownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+opts.KnownHosts)
	}
	return args
}

func sshTarget(opts RemoteOptions) string {
	if opts.User != "" {
		return opts.User + "@" + opts.Host
	}
	return opts.Host
}

func runWinRMTransport(ctx context.Context, opts RemoteOptions, script, stdin string) ([]byte, []byte, error) {
	if opts.User == "" {
		return nil, nil, fmt.Errorf("WinRM profile %q requires user", opts.ProfileName)
	}
	if opts.WinRMPassword == "" {
		return nil, nil, fmt.Errorf("WinRM password is not set; export %s", WinRMPasswordEnvironment(opts.ProfileName))
	}
	endpoint := winrm.NewEndpoint(opts.Host, opts.Port, opts.WinRMHTTPS, false, nil, nil, nil, 60*time.Second)
	parameters := winrm.NewParameters("PT60S", "en-US", 0)
	parameters.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(endpoint, opts.User, opts.WinRMPassword, parameters)
	if err != nil {
		return nil, nil, err
	}
	stdout, stderr, exitCode, err := client.RunPSWithContextWithString(ctx, script, stdin)
	if err == nil && exitCode != 0 {
		err = fmt.Errorf("WinRM PowerShell exited %d", exitCode)
	}
	return []byte(stdout), []byte(stderr), err
}

func zipDirectory(root, destination string) error {
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(output)
	walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		writer, err := archive.Create(filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	closeErr := archive.Close()
	fileCloseErr := output.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeErr != nil {
		return closeErr
	}
	return fileCloseErr
}

func unzipDirectory(archivePath, destination string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	cleanDestination := filepath.Clean(destination) + string(os.PathSeparator)
	for _, file := range reader.File {
		path := filepath.Join(destination, filepath.FromSlash(file.Name))
		if !strings.HasPrefix(filepath.Clean(path), cleanDestination) {
			return fmt.Errorf("archive entry escapes destination: %s", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		input, err := file.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		input.Close()
		output.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func expandUserPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
