package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorLabProfileAndPinnedLeaseTransport(t *testing.T) {
	profile := DefaultProfile("operator-lab")
	profile.OperatorLab.Profile = "bofbench-dev-x64"
	profile.OperatorLab.IdentityFile = filepath.Join(t.TempDir(), "id_bofbench")
	if err := os.WriteFile(profile.OperatorLab.IdentityFile, []byte("test identity path"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfile(profile); err != nil {
		t.Fatal(err)
	}
	lease := OperatorLabLease{Version: operatorLabAPIVersion, ID: "lease-1", Profile: "bofbench-dev-x64", ProfileIdentity: "sha256:test", VMID: 5101, Address: "10.12.60.44", SSHHostKey: "ssh-ed25519 AAAATEST operator-lab", State: "active"}
	opts, err := OperatorLabRemoteOptions("shared-x64", profile, lease, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != lease.Address || opts.BuildMode != "local" || opts.Transport != "ssh" {
		t.Fatalf("remote options = %+v", opts)
	}
	known, err := os.ReadFile(opts.KnownHosts)
	if err != nil {
		t.Fatal(err)
	}
	if string(known) != "[10.12.60.44]:22 ssh-ed25519 AAAATEST operator-lab\n" {
		t.Fatalf("known_hosts = %q", known)
	}
	info, _ := os.Stat(opts.KnownHosts)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("known_hosts mode = %o", info.Mode().Perm())
	}
}

func TestOperatorLabRejectsStaticHostAndMissingProfile(t *testing.T) {
	profile := DefaultProfile("operator-lab")
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "exact neutral-lab profile") {
		t.Fatalf("missing profile error = %v", err)
	}
	profile.OperatorLab.Profile = "bofbench-dev-x64"
	profile.Host = "stale.example"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "supplied by each lease") {
		t.Fatalf("static host error = %v", err)
	}
}
