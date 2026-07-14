package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

type labProfileFlags struct {
	Provider       string
	Topology       string
	Transport      string
	Host           string
	User           string
	Port           int
	Identity       string
	KnownHosts     string
	RemoteRoot     string
	BuildMode      string
	VagrantFile    string
	VagrantMachine string
	SliverSession  string
	WinRMHTTPS     bool
}

func labAddCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var from string
	var replace bool
	flags := labProfileFlags{Provider: "existing"}
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Register or clone a portable Windows lab profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			var profile lab.Profile
			if from != "" {
				var ok bool
				profile, ok = config.Profiles[from]
				if !ok {
					return fmt.Errorf("source profile %q does not exist; available: %s", from, strings.Join(lab.ProfileNames(config), ", "))
				}
			} else {
				profile = lab.DefaultProfile(flags.Provider)
			}
			applyProfileFlagChanges(cmd, &profile, flags)
			if err := lab.AddProfile(&config, name, profile, replace); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			profile = config.Profiles[name]
			fmt.Fprintf(stdout, "Lab profile %q saved\nTarget      %s\nTransport   %s\nBuild mode  %s\nConfig      %s\nNext        bofbench lab bootstrap --lab %s\n", name, profileTarget(profile), profile.Transport, profile.BuildMode, absolutePath(profilesPath), name)
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&from, "from", "", "clone an existing profile before applying overrides")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace an existing profile")
	bindLabProfileFlags(cmd, &flags)
	return cmd
}

func labListCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var format string
	cmd := &cobra.Command{
		Use: "list", Short: "List configured Windows lab profiles", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, config)
			}
			if format != "text" {
				return fmt.Errorf("lab list format must be text or json")
			}
			if len(config.Profiles) == 0 {
				fmt.Fprintln(stdout, "No lab profiles configured. Add one with: bofbench lab add <name> --host <host>")
				return nil
			}
			fmt.Fprintln(stdout, "ACTIVE  NAME                 TARGET                         TRANSPORT  BUILD")
			for _, name := range lab.ProfileNames(config) {
				profile := lab.NormalizeProfile(config.Profiles[name])
				active := ""
				if config.Active == name {
					active = "*"
				}
				fmt.Fprintf(stdout, "%-7s %-20s %-30s %-10s %s\n", active, name, truncate(profileTarget(profile), 30), profile.Transport, profile.BuildMode)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labShowCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var format string
	cmd := &cobra.Command{
		Use: "show <name>", Short: "Show one lab profile and its portable connection settings", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			profile, ok := config.Profiles[args[0]]
			if !ok {
				return fmt.Errorf("profile %q does not exist; available: %s", args[0], strings.Join(lab.ProfileNames(config), ", "))
			}
			profile = lab.NormalizeProfile(profile)
			if format == "json" {
				return printJSON(stdout, lab.ResolvedProfile{Name: args[0], Source: activeLabel(config.Active == args[0]), Profile: profile})
			}
			if format != "text" {
				return fmt.Errorf("lab show format must be text or json")
			}
			fmt.Fprintf(stdout, "Lab profile %s%s\nProvider       %s\nTopology       %s\nTransport      %s\nTarget         %s\nRemote root    %s\nBuild mode     %s\n", args[0], activeSuffix(config.Active == args[0]), profile.Provider, profile.Topology, profile.Transport, profileTarget(profile), profile.RemoteRoot, profile.BuildMode)
			if profile.IdentityFile != "" {
				fmt.Fprintf(stdout, "SSH identity   %s\n", profile.IdentityFile)
			}
			if profile.KnownHosts != "" {
				fmt.Fprintf(stdout, "Known hosts    %s\n", profile.KnownHosts)
			}
			if profile.SliverSession != "" {
				fmt.Fprintf(stdout, "Sliver target  %s\n", profile.SliverSession)
			}
			if profile.Transport == "winrm" {
				fmt.Fprintf(stdout, "Password env   %s\n", lab.WinRMPasswordEnvironment(args[0]))
			}
			fmt.Fprintf(stdout, "Profiles file  %s\n", absolutePath(profilesPath))
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labUseCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var project string
	cmd := &cobra.Command{
		Use: "use <name>", Short: "Select the active lab globally or for one project", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if _, ok := config.Profiles[args[0]]; !ok {
				return fmt.Errorf("profile %q does not exist; available: %s", args[0], strings.Join(lab.ProfileNames(config), ", "))
			}
			if project != "" {
				selectionPath := lab.ProjectSelectionPath(project)
				if err := lab.SaveProjectSelection(selectionPath, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "Project %s now uses lab %q\n", absolutePath(project), args[0])
				return nil
			}
			if err := lab.UseProfile(&config, args[0]); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Active lab is now %q\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&project, "project", "", "store only this profile name in the project's .bofbench/lab.json")
	return cmd
}

func labRemoveCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var force bool
	cmd := &cobra.Command{
		Use: "remove <name>", Short: "Remove a lab profile without touching the target", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if config.Active == args[0] && !force {
				return fmt.Errorf("profile %q is active; select another profile or use --force", args[0])
			}
			if err := lab.RemoveProfile(&config, args[0]); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Lab profile %q removed; the Windows target was not changed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().BoolVar(&force, "force", false, "remove the active profile")
	return cmd
}

func labImportCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	var name string
	var replace bool
	cmd := &cobra.Command{
		Use: "import <labs.json|legacy-lab.json>", Short: "Import portable profiles or a version-1 lab config", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			destination, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var header struct {
				Schema string `json:"schema"`
			}
			if err := json.Unmarshal(data, &header); err != nil {
				return fmt.Errorf("parse %s: %w", args[0], err)
			}
			imported := []string{}
			switch header.Schema {
			case lab.ProfilesSchema:
				source, err := lab.LoadProfiles(args[0])
				if err != nil {
					return err
				}
				if name != "" && len(source.Profiles) != 1 {
					return fmt.Errorf("--name can only rename an import containing one profile")
				}
				for _, sourceName := range lab.ProfileNames(source) {
					targetName := sourceName
					if name != "" {
						targetName = name
					}
					if err := lab.AddProfile(&destination, targetName, source.Profiles[sourceName], replace); err != nil {
						return err
					}
					imported = append(imported, targetName)
				}
			case lab.ConfigSchema:
				legacy, err := lab.LoadConfig(args[0])
				if err != nil {
					return err
				}
				if name == "" {
					name = strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(args[0]))
					if name == "lab" {
						name = "default"
					}
				}
				if err := lab.AddProfile(&destination, name, lab.ProfileFromLegacy(legacy), replace); err != nil {
					return err
				}
				imported = append(imported, name)
			default:
				return fmt.Errorf("unsupported lab configuration schema %q", header.Schema)
			}
			if err := lab.SaveProfiles(profilesPath, destination); err != nil {
				return err
			}
			sort.Strings(imported)
			fmt.Fprintf(stdout, "Imported lab profiles: %s\n", strings.Join(imported, ", "))
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&name, "name", "", "name for a legacy or single-profile import")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace matching profile names")
	return cmd
}

func labSetupScriptCommand(stdout io.Writer) *cobra.Command {
	var transport string
	var remoteRoot string
	cmd := &cobra.Command{
		Use: "setup-script", Short: "Print the one-time elevated PowerShell for a fresh Windows target", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			transport = strings.ToLower(strings.TrimSpace(transport))
			if len(remoteRoot) < 3 || remoteRoot[1] != ':' || (remoteRoot[2] != '\\' && remoteRoot[2] != '/') || strings.ContainsAny(remoteRoot, "\r\n") {
				return fmt.Errorf("remote-root must be an absolute Windows path")
			}
			quotedRoot := "'" + strings.ReplaceAll(remoteRoot, "'", "''") + "'"
			switch transport {
			case "ssh":
				fmt.Fprintf(stdout, sshSetupScript, quotedRoot)
			case "winrm":
				fmt.Fprintf(stdout, winRMSetupScript, quotedRoot)
			default:
				return fmt.Errorf("transport must be ssh or winrm")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&transport, "transport", "ssh", "transport to enable: ssh or winrm")
	cmd.Flags().StringVar(&remoteRoot, "remote-root", `C:\bofbench`, "managed BOFBench directory")
	return cmd
}

func bindLabProfileFlags(cmd *cobra.Command, flags *labProfileFlags) {
	cmd.Flags().StringVar(&flags.Provider, "provider", flags.Provider, "provider: existing or vagrant")
	cmd.Flags().StringVar(&flags.Topology, "topology", "", "topology: standalone or domain")
	cmd.Flags().StringVar(&flags.Transport, "transport", "", "transport: ssh or winrm")
	cmd.Flags().StringVar(&flags.Host, "host", "", "SSH alias, DNS name, or IP address")
	cmd.Flags().StringVar(&flags.User, "user", "", "remote Windows user")
	cmd.Flags().IntVar(&flags.Port, "port", 0, "transport port; default 22, 5985, or 5986")
	cmd.Flags().StringVar(&flags.Identity, "identity", "", "SSH private-key path; key contents are never stored")
	cmd.Flags().StringVar(&flags.KnownHosts, "known-hosts", "", "profile-specific known_hosts path")
	cmd.Flags().StringVar(&flags.RemoteRoot, "remote-root", "", "managed BOFBench directory on Windows")
	cmd.Flags().StringVar(&flags.BuildMode, "build-mode", "", "build mode: auto, local, or remote")
	cmd.Flags().StringVar(&flags.VagrantFile, "vagrantfile", "", "operator-supplied Vagrantfile")
	cmd.Flags().StringVar(&flags.VagrantMachine, "machine", "", "Vagrant machine name")
	cmd.Flags().StringVar(&flags.SliverSession, "sliver-session", "", "Sliver session selector; no C2 secrets are stored")
	cmd.Flags().BoolVar(&flags.WinRMHTTPS, "winrm-https", false, "use HTTPS WinRM on port 5986")
}

func applyProfileFlagChanges(cmd *cobra.Command, profile *lab.Profile, flags labProfileFlags) {
	if cmd.Flags().Changed("provider") {
		profile.Provider = flags.Provider
		if !cmd.Flags().Changed("transport") {
			profile.Transport = lab.DefaultProfile(flags.Provider).Transport
		}
	}
	if cmd.Flags().Changed("topology") {
		profile.Topology = flags.Topology
	}
	if cmd.Flags().Changed("transport") {
		profile.Transport = flags.Transport
		if !cmd.Flags().Changed("port") {
			profile.Port = 0
		}
	}
	if cmd.Flags().Changed("host") {
		profile.Host = flags.Host
	}
	if cmd.Flags().Changed("user") {
		profile.User = flags.User
	}
	if cmd.Flags().Changed("port") {
		profile.Port = flags.Port
	}
	if cmd.Flags().Changed("identity") {
		profile.IdentityFile = flags.Identity
	}
	if cmd.Flags().Changed("known-hosts") {
		profile.KnownHosts = flags.KnownHosts
	}
	if cmd.Flags().Changed("remote-root") {
		profile.RemoteRoot = flags.RemoteRoot
	}
	if cmd.Flags().Changed("build-mode") {
		profile.BuildMode = flags.BuildMode
	}
	if cmd.Flags().Changed("vagrantfile") {
		profile.VagrantFile = flags.VagrantFile
	}
	if cmd.Flags().Changed("machine") {
		profile.VagrantMachine = flags.VagrantMachine
	}
	if cmd.Flags().Changed("sliver-session") {
		profile.SliverSession = flags.SliverSession
	}
	if cmd.Flags().Changed("winrm-https") {
		profile.WinRMHTTPS = flags.WinRMHTTPS
		if !cmd.Flags().Changed("port") {
			profile.Port = 0
		}
	}
	*profile = lab.NormalizeProfile(*profile)
}

func profileTarget(profile lab.Profile) string {
	if profile.Provider == "vagrant" && profile.Host == "" {
		if profile.VagrantMachine != "" {
			return "vagrant:" + profile.VagrantMachine
		}
		return "vagrant"
	}
	host := profile.Host
	if profile.User != "" {
		host = profile.User + "@" + host
	}
	if profile.Port != 0 && !((profile.Transport == "ssh" && profile.Port == 22) || (profile.Transport == "winrm" && profile.Port == 5985) || (profile.Transport == "winrm" && profile.WinRMHTTPS && profile.Port == 5986)) {
		host += fmt.Sprintf(":%d", profile.Port)
	}
	return host
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < 2 {
		return value[:limit]
	}
	return value[:limit-1] + "…"
}

func absolutePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

func activeSuffix(active bool) string {
	if active {
		return " (active)"
	}
	return ""
}

func activeLabel(active bool) string {
	if active {
		return "active"
	}
	return "configured"
}

const sshSetupScript = `$ErrorActionPreference = 'Stop'
# Run once from an elevated PowerShell prompt.
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
}
New-Item -ItemType Directory -Force -Path %s | Out-Null
Write-Host 'OpenSSH is ready. Add your public key to the target account before using BOFBench.'
`

const winRMSetupScript = `$ErrorActionPreference = 'Stop'
# Run once from an elevated PowerShell prompt on a trusted, firewalled lab network.
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Service -Name WinRM -StartupType Automatic
Start-Service WinRM
New-Item -ItemType Directory -Force -Path %s | Out-Null
Write-Host 'WinRM is ready. BOFBench reads the password from the profile-specific environment variable and never stores it.'
`
