package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

func TestSSHSetupScriptConfiguresPowerShellDefaultShell(t *testing.T) {
	var output bytes.Buffer
	cmd := labSetupScriptCommand(&output)
	cmd.SetArgs([]string{"--transport", "ssh"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"HKLM:\\SOFTWARE\\OpenSSH", "DefaultShell", "WindowsPowerShell\\v1.0\\powershell.exe"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("SSH setup script is missing %q:\n%s", expected, text)
		}
	}
}

func TestProfileClonePreservesTransportWhenProviderIsUnchanged(t *testing.T) {
	flags := labProfileFlags{Provider: "existing"}
	cmd := &cobra.Command{Use: "test"}
	bindLabProfileFlags(cmd, &flags)
	if err := cmd.ParseFlags([]string{"--provider", "proxmox"}); err != nil {
		t.Fatal(err)
	}
	profile := lab.DefaultProfile("proxmox")
	profile.Transport, profile.Port = "ssh", 22
	profile.IdentityFile = "/tmp/id"
	applyProfileFlagChanges(cmd, &profile, flags)
	if profile.Transport != "ssh" || profile.Port != 22 {
		t.Fatalf("unchanged provider reset cloned transport: %+v", profile)
	}
}

func TestProfileCloneProxmoxOverridesDoNotMutateSource(t *testing.T) {
	source := lab.DefaultProfile("proxmox")
	source.Proxmox.VMID = 4110
	clone := cloneLabProfile(source)
	clone.Proxmox.VMID = 4111
	if source.Proxmox.VMID != 4110 {
		t.Fatalf("source Proxmox VMID mutated through clone: %d", source.Proxmox.VMID)
	}
}

func TestOperatorLabQuickProfileNeedsOnlyNeutralProfileName(t *testing.T) {
	flags := labProfileFlags{Provider: "existing"}
	cmd := &cobra.Command{Use: "test"}
	bindLabProfileFlags(cmd, &flags)
	if err := cmd.ParseFlags([]string{"--provider", "operator-lab", "--profile", "bofbench-dev-x64"}); err != nil {
		t.Fatal(err)
	}
	profile := lab.DefaultProfile("existing")
	applyProfileFlagChanges(cmd, &profile, flags)
	if err := lab.ValidateProfile(profile); err != nil {
		t.Fatal(err)
	}
	if profile.Provider != "operator-lab" || profile.Transport != "ssh" || profile.OperatorLab == nil || profile.OperatorLab.Profile != "bofbench-dev-x64" || profile.Host != "" {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestTemplateStatusUsesProfileSourceTemplateAndHonorsOverride(t *testing.T) {
	profile := lab.DefaultProfile("proxmox")
	profile.Proxmox.VMID = 4130
	profile.Proxmox.TemplateVMID = 4102
	selected := templateStatusProfile(profile, 0)
	if selected.Proxmox.VMID != 4102 || profile.Proxmox.VMID != 4130 {
		t.Fatalf("selected=%d source=%d", selected.Proxmox.VMID, profile.Proxmox.VMID)
	}
	overridden := templateStatusProfile(profile, 4104)
	if overridden.Proxmox.VMID != 4104 {
		t.Fatalf("override=%d", overridden.Proxmox.VMID)
	}
}
