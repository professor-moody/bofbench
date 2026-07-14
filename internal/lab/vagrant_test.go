package lab

import (
	"context"
	"testing"
)

func TestResolveRemoteOptionsFromVagrant(t *testing.T) {
	original := executeVagrantCommand
	t.Cleanup(func() { executeVagrantCommand = original })
	executeVagrantCommand = func(_ context.Context, profile Profile, args ...string) ([]byte, error) {
		if profile.VagrantMachine != "member" || len(args) != 1 || args[0] != "winrm-config" {
			t.Fatalf("profile=%+v args=%v", profile, args)
		}
		return []byte("Host: 127.0.0.1\nPort: 55985\nUsername: vagrant\nPassword: temporary\n"), nil
	}
	profile := DefaultProfile("vagrant")
	profile.VagrantMachine = "member"
	opts, err := ResolveRemoteOptions(context.Background(), "domain-member", profile)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != "127.0.0.1" || opts.Port != 55985 || opts.User != "vagrant" || opts.WinRMPassword != "temporary" || opts.Transport != "winrm" || !opts.SnapshotSupport {
		t.Fatalf("options=%+v", opts)
	}
}

func TestParseVagrantConnectionSSHStyle(t *testing.T) {
	values := parseVagrantConnection("HostName 127.0.0.1\nUser vagrant\nPort 5985\nPassword secret\n")
	if firstValue(values, "host", "hostname") != "127.0.0.1" || values["username"] != "" || values["user"] != "vagrant" {
		t.Fatalf("values=%v", values)
	}
}
