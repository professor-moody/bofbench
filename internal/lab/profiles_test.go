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
