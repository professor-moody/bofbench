package lab

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	// OpenSSH looks up a bare hostname at port 22; a "[host]:22" entry never
	// matches and every StrictHostKeyChecking=yes connection is refused.
	if string(known) != "10.12.60.44 ssh-ed25519 AAAATEST operator-lab\n" {
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

// TestOperatorLabDoctorDecodesTheFullControllerResponse pins the wire contract.
// do() decodes with DisallowUnknownFields and labd emits every Doctor field
// without omitempty, so any field missing from operatorLabDoctor makes the
// availability probe fail unconditionally and reports the whole provider
// unavailable. The body below is the literal response captured from labd.
func TestOperatorLabDoctorDecodesTheFullControllerResponse(t *testing.T) {
	const body = `{"version":"operator-lab/v1","store":"/var/lib/operator-lab/lab.sqlite3","backend":"proxmox","active_leases":0,"quarantined":0,"ready":true,"capacity":{"total_memory_mib":65536,"free_memory_mib":32768},"paired_leases_enabled":false}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/doctor" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	client := &OperatorLabClient{endpoint: server.URL, http: server.Client()}
	if err := client.Doctor(context.Background()); err != nil {
		t.Fatalf("doctor probe must accept the controller response: %v", err)
	}
}
