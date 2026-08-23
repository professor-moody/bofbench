package runtimecontrol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTripAndResolve(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-controls.json")
	config := NewConfig()
	control := Control{Runtime: "sliver", Provider: "proxmox", ProxmoxPrep: "/tmp/prep.json", VMID: 4120, TemplateVMID: 4104}
	if err := Add(&config, "sliver-lab", control, false); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	name, resolved, err := Resolve(loaded, "")
	if err != nil {
		t.Fatal(err)
	}
	if name != "sliver-lab" || resolved.VMID != 4120 || resolved.CloneMode != "full" {
		t.Fatalf("unexpected control: %s %#v", name, resolved)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestValidationRejectsSecretsAndUnsupportedProviders(t *testing.T) {
	config := NewConfig()
	if err := Add(&config, "bad", Control{Runtime: "sliver", Provider: "existing", ProxmoxPrep: "/tmp/prep", VMID: 1}, false); err == nil {
		t.Fatal("expected unsupported provider rejection")
	}
	path := filepath.Join(t.TempDir(), "runtime-controls.json")
	if err := os.WriteFile(path, []byte(`{"schema":"bofbench.runtime-controls","schema_version":1,"controls":{},"password":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown secret-like field rejection")
	}
}

func TestRemoteClientRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-controls.json")
	config := NewConfig()
	control := Control{
		Runtime: "sliver", Provider: "proxmox", ProxmoxPrep: "/tmp/prep.json", VMID: 4120,
		Client: &Client{
			Transport: "ssh", User: "bofbench", Port: 22,
			IdentityFile: "/tmp/sliver-identity", KnownHosts: "/tmp/sliver-known-hosts",
			Path: "/usr/local/bin/sliver-client", Home: "/home/bofbench/.sliver-client",
			ConfigPath: "/home/bofbench/.sliver-client/configs/bofbench.cfg",
		},
	}
	if err := Add(&config, "sliver-lab", control, false); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	client := loaded.Controls["sliver-lab"].Client
	if client == nil || client.Transport != "ssh" || client.ConfigPath != "/home/bofbench/.sliver-client/configs/bofbench.cfg" {
		t.Fatalf("unexpected client: %#v", client)
	}
}

func TestRemoteClientRejectsConfigOutsideDedicatedHome(t *testing.T) {
	client := Client{
		Transport: "ssh", User: "bofbench", Port: 22,
		IdentityFile: "/tmp/id", KnownHosts: "/tmp/known-hosts",
		Path: "/usr/local/bin/sliver-client", Home: "/home/bofbench/.sliver-client",
		ConfigPath: "/tmp/operator.cfg",
	}
	if err := ValidateClient(client); err == nil {
		t.Fatal("expected config path outside dedicated client home to be rejected")
	}
}
