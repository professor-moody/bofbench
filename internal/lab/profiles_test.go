package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfilesRoundTripCloneAndAuthEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "labs.json")
	config := NewProfilesConfig()
	profile := DefaultProfile("existing")
	profile.Host = "winlab.example"
	profile.User = "operator"
	profile.IdentityFile = "~/.ssh/bofbench"
	if err := AddProfile(&config, "dev-box", profile, false); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfiles(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Active != "dev-box" || loaded.Profiles["dev-box"].Host != "winlab.example" {
		t.Fatalf("loaded profiles = %+v", loaded)
	}
	if got := WinRMPasswordEnvironment("domain/lab.one"); got != "BOFBENCH_LAB_DOMAIN_LAB_ONE_WINRM_PASSWORD" {
		t.Fatalf("password environment = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("profiles mode = %o", info.Mode().Perm())
	}
}

func TestResolveProfilePrecedence(t *testing.T) {
	root := t.TempDir()
	profilesPath := filepath.Join(root, "labs.json")
	project := filepath.Join(root, "project")
	config := NewProfilesConfig()
	for _, name := range []string{"explicit", "environment", "project", "active"} {
		profile := DefaultProfile("existing")
		profile.Host = name + ".example"
		if err := AddProfile(&config, name, profile, false); err != nil {
			t.Fatal(err)
		}
	}
	config.Active = "active"
	if err := SaveProfiles(profilesPath, config); err != nil {
		t.Fatal(err)
	}
	if err := SaveProjectSelection(ProjectSelectionPath(project), "project"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_LAB", "environment")
	resolved, err := ResolveProfile("explicit", project, profilesPath)
	if err != nil || resolved.Name != "explicit" || resolved.Source != "--lab" {
		t.Fatalf("explicit resolution = %+v, %v", resolved, err)
	}
	resolved, err = ResolveProfile("", project, profilesPath)
	if err != nil || resolved.Name != "environment" {
		t.Fatalf("environment resolution = %+v, %v", resolved, err)
	}
	t.Setenv("BOFBENCH_LAB", "")
	resolved, err = ResolveProfile("", project, profilesPath)
	if err != nil || resolved.Name != "project" {
		t.Fatalf("project resolution = %+v, %v", resolved, err)
	}
	if err := os.Remove(ProjectSelectionPath(project)); err != nil {
		t.Fatal(err)
	}
	resolved, err = ResolveProfile("", project, profilesPath)
	if err != nil || resolved.Name != "active" {
		t.Fatalf("active resolution = %+v, %v", resolved, err)
	}
}

func TestResolveOnlyProfileAndAmbiguousProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labs.json")
	config := NewProfilesConfig()
	profile := DefaultProfile("existing")
	profile.Host = "only.example"
	if err := AddProfile(&config, "only", profile, false); err != nil {
		t.Fatal(err)
	}
	config.Active = ""
	if err := SaveProfiles(path, config); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveProfile("", t.TempDir(), path)
	if err != nil || resolved.Name != "only" || resolved.Source != "only-profile" {
		t.Fatalf("only resolution = %+v, %v", resolved, err)
	}
	second := DefaultProfile("existing")
	second.Host = "second.example"
	if err := AddProfile(&config, "second", second, false); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfiles(path, config); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProfile("", t.TempDir(), path); err == nil || !strings.Contains(err.Error(), "only, second") {
		t.Fatalf("ambiguous resolution error = %v", err)
	}
}

func TestLegacyProjectConfigMigratesAndRetainsBackup(t *testing.T) {
	root := t.TempDir()
	profilesPath := filepath.Join(root, "config", "labs.json")
	project := filepath.Join(root, "project")
	legacyPath := ProjectSelectionPath(project)
	legacy := DefaultConfig("existing")
	legacy.Host = "legacy.example"
	if err := SaveConfig(legacyPath, legacy); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveProfile("", project, profilesPath)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != "default" || resolved.Source != "project-migration" || resolved.Profile.Host != "legacy.example" {
		t.Fatalf("migrated resolution = %+v", resolved)
	}
	if _, err := os.Stat(legacyPath + ".v1.bak"); err != nil {
		t.Fatalf("legacy backup: %v", err)
	}
	selection, err := LoadProjectSelection(legacyPath)
	if err != nil || selection.Profile != "default" {
		t.Fatalf("selection = %+v, %v", selection, err)
	}
	profiles, err := LoadProfiles(profilesPath)
	if err != nil || profiles.Profiles["default"].Host != "legacy.example" {
		t.Fatalf("profiles = %+v, %v", profiles, err)
	}
}

func TestProfileValidationRejectsSecretsAndBadValues(t *testing.T) {
	profile := DefaultProfile("existing")
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "requires host") {
		t.Fatalf("missing host error = %v", err)
	}
	profile.Host = "lab"
	profile.BuildMode = "sometimes"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "build_mode") {
		t.Fatalf("build mode error = %v", err)
	}
	if err := ValidateProfileName("../escape"); err == nil {
		t.Fatal("expected invalid profile name")
	}
	profile = DefaultProfile("vagrant")
	profile.Transport = "ssh"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "use WinRM") {
		t.Fatalf("Vagrant transport error = %v", err)
	}
	profile = DefaultProfile("existing")
	profile.Host = "lab"
	profile.RemoteRoot = "/tmp/not-windows"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "Windows path") {
		t.Fatalf("remote root error = %v", err)
	}
	profile = DefaultProfile("existing")
	profile.Host = "lab"
	profile.Transport = "winrm"
	profile.IdentityFile = "~/.ssh/lab"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "only to SSH") {
		t.Fatalf("transport field error = %v", err)
	}
}

func TestTopologyLifecycleResolutionAndProfileProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labs.json")
	config := NewProfilesConfig()
	for _, name := range []string{"execution", "target", "dc"} {
		profile := DefaultProfile("existing")
		profile.Host = name + ".example"
		if err := AddProfile(&config, name, profile, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddTopology(&config, "domain", ProfileTopology{Execution: "execution", Target: "target", DomainController: "dc"}, false); err != nil {
		t.Fatal(err)
	}
	if err := UseTopology(&config, "domain"); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfiles(path, config); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveTopology("", path)
	if err != nil || resolved.Name != "domain" || resolved.Execution.Name != "execution" || resolved.Target == nil || resolved.Target.Name != "target" || resolved.DomainController == nil || resolved.DomainController.Name != "dc" {
		t.Fatalf("resolved topology = %+v, %v", resolved, err)
	}
	if err := RemoveProfile(&config, "target"); err == nil || !strings.Contains(err.Error(), "topology") {
		t.Fatalf("referenced profile removal error = %v", err)
	}
	if err := RemoveTopology(&config, "domain"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProfile(&config, "target"); err != nil {
		t.Fatal(err)
	}
}

func TestProfilesV3MigratesToV6AndRetainsBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labs.json")
	data := []byte(`{"schema":"bofbench.labs","schema_version":3,"active":"devbox","profiles":{"devbox":{"provider":"existing","topology":"standalone","transport":"ssh","host":"devbox","port":22,"remote_root":"C:\\bofbench","build_mode":"auto"}},"topologies":{}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.SchemaVersion != 6 || config.Profiles["devbox"].Host != "devbox" {
		t.Fatalf("config=%+v", config)
	}
	if _, err := os.Stat(path + ".v3.bak"); err != nil {
		t.Fatalf("migration backup: %v", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), `"schema_version": 6`) {
		t.Fatalf("migration was not persisted: %s", persisted)
	}
}

func TestTopologyTargetSetsPreserveOrderAndRejectDuplicates(t *testing.T) {
	config := NewProfilesConfig()
	for _, name := range []string{"execution", "target-a", "target-b"} {
		if err := AddProfile(&config, name, Profile{Provider: "existing", Transport: "ssh", Host: name, RemoteRoot: `C:\bofbench`, BuildMode: "local"}, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddTopology(&config, "standalone", ProfileTopology{Execution: "execution", Target: "target-a"}, false); err != nil {
		t.Fatal(err)
	}
	if err := AddTopologyTarget(&config, "standalone", "windows", "target-b"); err != nil {
		t.Fatal(err)
	}
	if err := AddTopologyTarget(&config, "standalone", "windows", "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := AddTopologyTarget(&config, "standalone", "windows", "target-a"); err == nil {
		t.Fatal("expected duplicate target rejection")
	}
	path := filepath.Join(t.TempDir(), "labs.json")
	if err := SaveProfiles(path, config); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveTopology("standalone", path)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolved.TargetSets["windows"]; len(got) != 2 || got[0].Name != "target-b" || got[1].Name != "target-a" {
		t.Fatalf("unexpected ordered targets: %#v", got)
	}
}

func TestProxmoxProfileValidationAndPreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prep.json")
	data := []byte(`{"schema":"bofbench.proxmox-preparation","schema_version":1,"endpoint":"https://pve:8006/api2/json","node":"gr9","pool":"bofbench","storage":"local-lvm","iso_storage":"local","token_id":"bofbench@pve!provider","token_secret_source":{"kind":"env","name":"BOFBENCH_TEST_TOKEN"},"ca_file":"/tmp/ca.pem","resource_plan":{"management_bridge":"vmbr0","lab_bridge":"vmbr290","lab_subnet":"10.12.90.0/24"}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	prep, err := LoadProxmoxPreparation(path)
	if err != nil {
		t.Fatal(err)
	}
	profile := DefaultProfile("proxmox")
	profile.Proxmox = &ProxmoxProfile{Endpoint: prep.Endpoint, Node: prep.Node, VMID: 4101, Pool: prep.Pool, Storage: prep.Storage, ISOStorage: prep.ISOStorage, TokenID: prep.TokenID, TokenSecretSource: prep.TokenSecretSource, CAFile: prep.CAFile, CloneMode: "full", Bridge: prep.ResourcePlan.LabBridge, GuestIPv4CIDR: prep.ResourcePlan.LabSubnet, GuestAgent: true}
	if err := ValidateProfile(profile); err != nil {
		t.Fatal(err)
	}
	profile.Proxmox.SSHProxy = "pve -oProxyCommand=bad"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "ssh_proxy") {
		t.Fatalf("ssh proxy error=%v", err)
	}
	profile.Proxmox.SSHProxy = "bofbench-proxmox"
	profile.Proxmox.TokenID = "bad"
	if err := ValidateProfile(profile); err == nil || !strings.Contains(err.Error(), "user@realm!token") {
		t.Fatalf("token id error=%v", err)
	}
}
