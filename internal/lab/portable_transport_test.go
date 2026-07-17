package lab

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSSHArgumentsRetainHostVerificationAndIdentity(t *testing.T) {
	opts := RemoteOptions{Host: "lab.example", User: "operator", Port: 2222, IdentityFile: "/keys/lab", KnownHosts: "/keys/known_hosts", JumpHost: "pve-lab"}
	if got, want := sshBaseArgs(opts), []string{"-o", "ProxyJump=pve-lab", "-p", "2222", "-i", "/keys/lab", "-o", "UserKnownHostsFile=/keys/known_hosts"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ssh args=%v want=%v", got, want)
	}
	if got := sshTarget(opts); got != "operator@lab.example" {
		t.Fatalf("ssh target=%q", got)
	}
}

func TestWinRMExecuteUploadAndDownloadWithFake(t *testing.T) {
	original := executeWinRMTransport
	t.Cleanup(func() { executeWinRMTransport = original })
	var calls int
	executeWinRMTransport = func(_ context.Context, opts RemoteOptions, script, stdin string) ([]byte, []byte, error) {
		calls++
		if opts.Host != "lab.example" || opts.User != "operator" || opts.WinRMPassword != "secret" {
			t.Fatalf("options=%+v", opts)
		}
		switch {
		case strings.Contains(script, "WriteAllBytes"):
			decoded, err := base64.StdEncoding.DecodeString(stdin)
			if err != nil || string(decoded) != "upload-data" {
				t.Fatalf("upload stdin=%q decoded=%q err=%v", stdin, decoded, err)
			}
			return nil, nil, nil
		case strings.Contains(script, "ToBase64String"):
			return []byte(base64.StdEncoding.EncodeToString([]byte("download-data"))), nil, nil
		default:
			return []byte("ok"), nil, nil
		}
	}
	opts := RemoteOptions{ProfileName: "winrm", Transport: "winrm", Host: "lab.example", User: "operator", Port: 5985, WinRMPassword: "secret", RemoteRoot: `C:\bofbench`}
	stdout, _, err := ExecutePowerShell(context.Background(), opts, "Write-Output ok")
	if err != nil || string(stdout) != "ok" {
		t.Fatalf("execute stdout=%q err=%v", stdout, err)
	}
	local := filepath.Join(t.TempDir(), "upload.bin")
	if err := os.WriteFile(local, []byte("upload-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := remoteUploadFile(context.Background(), opts, local, `C:\bofbench\upload.bin`); err != nil {
		t.Fatal(err)
	}
	download := filepath.Join(t.TempDir(), "download.bin")
	if _, _, err := remoteDownloadFile(context.Background(), opts, `C:\bofbench\download.bin`, download); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(download)
	if err != nil || string(data) != "download-data" {
		t.Fatalf("download=%q err=%v", data, err)
	}
	if calls != 3 {
		t.Fatalf("WinRM calls=%d", calls)
	}
}

func TestWinRMReportsAuthenticationAndTransportFailures(t *testing.T) {
	_, _, err := runWinRMTransport(context.Background(), RemoteOptions{ProfileName: "dedicated", Host: "lab", User: "operator", Port: 5985}, "hostname", "")
	if err == nil || !strings.Contains(err.Error(), WinRMPasswordEnvironment("dedicated")) {
		t.Fatalf("missing password error=%v", err)
	}
	original := executeWinRMTransport
	t.Cleanup(func() { executeWinRMTransport = original })
	executeWinRMTransport = func(context.Context, RemoteOptions, string, string) ([]byte, []byte, error) {
		return nil, []byte("authentication failed"), errors.New("unauthorized")
	}
	_, _, err = ExecutePowerShell(context.Background(), RemoteOptions{ProfileName: "dedicated", Transport: "winrm", Host: "lab", User: "operator", Port: 5985, WinRMPassword: "bad", RemoteRoot: `C:\bofbench`}, "hostname")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("transport error=%v", err)
	}
}
