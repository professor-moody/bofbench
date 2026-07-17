package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

func labMediaCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "media", Short: "Inspect installation media available to a lab provider"}
	cmd.AddCommand(labMediaListCommand(stdout))
	return cmd
}

func labMediaListCommand(stdout io.Writer) *cobra.Command {
	var provider, preparation, format string
	cmd := &cobra.Command{Use: "list", Short: "List provider ISO media without changing any VM", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if strings.ToLower(provider) != "proxmox" {
			return fmt.Errorf("lab media list currently supports provider proxmox")
		}
		media, err := lab.ListProxmoxMedia(cmd.Context(), preparation)
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, map[string]any{"provider": "proxmox", "media": media})
		}
		if format != "text" {
			return fmt.Errorf("lab media list format must be text or json")
		}
		if len(media) == 0 {
			fmt.Fprintln(stdout, "No ISO media is available in the configured Proxmox ISO storage.")
			return nil
		}
		fmt.Fprintln(stdout, "VOLUME                                                        SIZE       FORMAT")
		for _, item := range media {
			fmt.Fprintf(stdout, "%-61s %-10d %s\n", item.VolumeID, item.Size, item.Format)
		}
		return nil
	}
	cmd.Flags().StringVar(&provider, "provider", "proxmox", "infrastructure provider")
	cmd.Flags().StringVar(&preparation, "proxmox-prep", defaultProxmoxPreparationPath(), "secret-free Proxmox preparation file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTemplateCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "template", Short: "Inspect and prepare BOFBench-owned provider templates"}
	convert := labProviderCommand(stdout, "template")
	convert.Use = "convert"
	convert.Short = "Convert an installed provider VM into a reusable template"
	cmd.AddCommand(labTemplateStatusCommand(stdout), labTemplateBuildCommand(stdout), convert)
	return cmd
}

func labTemplateStatusCommand(stdout io.Writer) *cobra.Command {
	var labName, profilesPath, preparation, format string
	var vmid int
	cmd := &cobra.Command{Use: "status", Short: "Inspect one exact Proxmox template VMID", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if labName != "" {
			resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
			if err != nil {
				return err
			}
			if resolved.Profile.Proxmox == nil {
				return fmt.Errorf("lab %s is not Proxmox-backed", resolved.Name)
			}
			receipt, err := lab.RunProviderAction(cmd.Context(), resolved.Name, resolved.Profile, "status", lab.ProviderActionOptions{})
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, receipt)
			}
			fmt.Fprintf(stdout, "Template status\nlab       %s\nvmid      %d\nstate     %s\ntemplate  %t\nreceipt   %s\n", resolved.Name, receipt.Resource.VMID, receipt.Resource.State, receipt.Resource.Template, receipt.EvidencePath)
			return nil
		}
		if vmid <= 0 {
			return fmt.Errorf("set --lab or --vmid")
		}
		resource, err := lab.ProxmoxTemplateStatus(cmd.Context(), preparation, vmid)
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, resource)
		}
		fmt.Fprintf(stdout, "Template status\nvmid      %d\nname      %s\nstate     %s\ntemplate  %t\n", resource.VMID, emptyText(resource.Name, "-"), resource.State, resource.Template)
		return nil
	}
	cmd.Flags().StringVar(&labName, "lab", "", "Proxmox-backed lab profile")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&preparation, "proxmox-prep", defaultProxmoxPreparationPath(), "secret-free Proxmox preparation file")
	cmd.Flags().IntVar(&vmid, "vmid", 0, "exact BOFBench-owned VMID")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTemplateBuildCommand(stdout io.Writer) *cobra.Command {
	var labName, profilesPath, preparation, iso, name, bridge, osType, format string
	var vmid, cores, memoryMB, diskGB int
	var start bool
	cmd := &cobra.Command{Use: "build", Short: "Create a BOFBench-owned Windows installation VM from an exact ISO", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		cleanup := func() {}
		if labName != "" {
			resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
			if err != nil {
				return err
			}
			if resolved.Profile.Proxmox == nil {
				return fmt.Errorf("lab %s is not Proxmox-backed", resolved.Name)
			}
			if vmid == 0 {
				vmid = resolved.Profile.Proxmox.VMID
			}
			preparation, cleanup, err = temporaryPreparationForProfile(resolved.Profile)
			if err != nil {
				return err
			}
			defer cleanup()
		}
		receipt, err := lab.BuildProxmoxTemplate(cmd.Context(), preparation, lab.ProxmoxTemplateSpec{VMID: vmid, Name: name, ISO: iso, Cores: cores, MemoryMB: memoryMB, DiskGB: diskGB, Bridge: bridge, OSType: osType, Start: start})
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, receipt)
		}
		fmt.Fprintf(stdout, "Template installation VM prepared\nvmid     %d\nstate    %s\niso      %s\nreceipt  %s\nnext     install Windows, enable the guest agent/transport, then run 'bofbench lab template --lab %s'\n", receipt.Resource.VMID, receipt.Resource.State, iso, receipt.EvidencePath, labName)
		return nil
	}
	cmd.Flags().StringVar(&labName, "lab", "", "Proxmox-backed template lab profile")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&preparation, "proxmox-prep", defaultProxmoxPreparationPath(), "secret-free Proxmox preparation file")
	cmd.Flags().StringVar(&iso, "iso", "", "exact Proxmox ISO volume, for example local:iso/windows-server.iso")
	cmd.Flags().StringVar(&name, "name", "", "installation VM name")
	cmd.Flags().StringVar(&bridge, "bridge", "", "network bridge; defaults to the preparation lab bridge")
	cmd.Flags().StringVar(&osType, "os-type", "win11", "Proxmox guest OS type")
	cmd.Flags().IntVar(&vmid, "vmid", 0, "exact BOFBench-owned VMID")
	cmd.Flags().IntVar(&cores, "cores", 4, "virtual CPU count")
	cmd.Flags().IntVar(&memoryMB, "memory-mb", 4096, "memory in MiB")
	cmd.Flags().IntVar(&diskGB, "disk-gb", 64, "primary disk size in GiB")
	cmd.Flags().BoolVar(&start, "start", true, "start the installation VM after creation")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	_ = cmd.MarkFlagRequired("iso")
	return cmd
}

func temporaryPreparationForProfile(profile lab.Profile) (string, func(), error) {
	if profile.Proxmox == nil {
		return "", func() {}, fmt.Errorf("profile is not Proxmox-backed")
	}
	p := profile.Proxmox
	prep := lab.ProxmoxPreparation{Schema: "bofbench.proxmox-preparation", SchemaVersion: 1, Endpoint: p.Endpoint, Node: p.Node, Pool: p.Pool, Storage: p.Storage, ISOStorage: p.ISOStorage, TokenID: p.TokenID, TokenSecretSource: p.TokenSecretSource, CAFile: p.CAFile, SSHAlias: p.SSHProxy}
	prep.ResourcePlan.VMIDMin, prep.ResourcePlan.VMIDMax = 4100, 4199
	prep.ResourcePlan.LabBridge, prep.ResourcePlan.LabSubnet = p.Bridge, p.GuestIPv4CIDR
	data, err := json.Marshal(prep)
	if err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp("", "bofbench-proxmox-prep-*.json")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err == nil {
		_, err = file.Write(data)
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return "", func() {}, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func defaultProxmoxPreparationPath() string {
	if value := strings.TrimSpace(os.Getenv("BOFBENCH_PROXMOX_PREPARATION")); value != "" {
		return value
	}
	return "~/.config/bofbench/proxmox-gr9.json"
}
