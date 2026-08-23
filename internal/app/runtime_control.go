package app

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/professor-moody/bofbench/internal/lab"
	"github.com/professor-moody/bofbench/internal/runtimecontrol"
)

func runtimeControlCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "control", Short: "Manage secret-free runtime control-plane profiles"}
	cmd.AddCommand(
		runtimeControlAddCommand(stdout),
		runtimeControlListCommand(stdout),
		runtimeControlShowCommand(stdout),
		runtimeControlLifecycleCommand(stdout, "status"),
		runtimeControlLifecycleCommand(stdout, "up"),
		runtimeControlLifecycleCommand(stdout, "down"),
		runtimeControlTrustClientCommand(stdout),
		runtimeControlRemoveCommand(stdout),
	)
	return cmd
}

func runtimeControlTrustClientCommand(stdout io.Writer) *cobra.Command {
	var controlsPath string
	cmd := &cobra.Command{Use: "trust-client <name>", Short: "Pin the running control guest SSH host key through the trusted Proxmox path", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		name, control, err := runtimecontrol.Resolve(config, args[0])
		if err != nil {
			return err
		}
		if control.Client == nil || control.Client.Transport != "ssh" {
			return fmt.Errorf("runtime control %s has no SSH client transport", name)
		}
		profile, err := runtimecontrol.LabProfile(control)
		if err != nil {
			return err
		}
		status, err := lab.RunProviderAction(cmd.Context(), "runtime-control-"+name, profile, "status", lab.ProviderActionOptions{})
		if err != nil {
			return err
		}
		host := strings.TrimSpace(status.Resource.GuestIPv4)
		if status.Resource.State != "running" || host == "" {
			return fmt.Errorf("runtime control %s is not running with a guest address", name)
		}
		if profile.Proxmox == nil || strings.TrimSpace(profile.Proxmox.SSHProxy) == "" {
			return fmt.Errorf("runtime control %s has no trusted Proxmox SSH path", name)
		}
		port := control.Client.Port
		scan := "ssh-keyscan -T 5 -p " + strconv.Itoa(port) + " -t ed25519 -- " + posixShellQuote(host)
		command := exec.CommandContext(cmd.Context(), "ssh", "-o", "BatchMode=yes", profile.Proxmox.SSHProxy, scan)
		data, err := command.Output()
		if err != nil {
			return fmt.Errorf("read runtime control %s host key through %s: %w", name, profile.Proxmox.SSHProxy, err)
		}
		line, fingerprint, err := parseSSHKeyscan(data, host, port)
		if err != nil {
			return err
		}
		if err := writeOwnerFile(control.Client.KnownHosts, []byte(line+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Runtime client host key pinned\ncontrol      %s\nhost         %s:%d\nfingerprint  %s\nknown hosts  %s\n", name, host, port, fingerprint, control.Client.KnownHosts)
		return nil
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	return cmd
}

func parseSSHKeyscan(data []byte, host string, port int) (string, string, error) {
	wantHost := host
	if port != 22 {
		wantHost = "[" + host + "]:" + strconv.Itoa(port)
	}
	for _, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) != 3 || fields[0] != wantHost || fields[1] != "ssh-ed25519" {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil || len(blob) == 0 {
			return "", "", fmt.Errorf("runtime client returned an invalid ed25519 host key")
		}
		digest := sha256.Sum256(blob)
		fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
		return strings.Join(fields, " "), fingerprint, nil
	}
	return "", "", fmt.Errorf("runtime client did not return one ed25519 host key for %s:%d", host, port)
}

func writeOwnerFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".bofbench-owner-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func runtimeControlAddCommand(stdout io.Writer) *cobra.Command {
	var controlsPath, runtimeName, provider, preparation, cloneMode, guestName string
	var clientTransport, clientUser, clientIdentity, clientKnownHosts, clientPath, clientHome, clientConfig string
	var vmid, templateVMID, clientPort int
	var replace bool
	cmd := &cobra.Command{
		Use: "add <name>", Short: "Register a Proxmox-backed Sliver or Cobalt Strike control plane", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := runtimecontrol.Load(controlsPath)
			if err != nil {
				return err
			}
			control := runtimecontrol.Control{Runtime: runtimeName, Provider: provider, ProxmoxPrep: preparation, VMID: vmid, TemplateVMID: templateVMID, CloneMode: cloneMode, Name: guestName}
			if strings.TrimSpace(clientTransport) != "" {
				control.Client = &runtimecontrol.Client{
					Transport: clientTransport, User: clientUser, Port: clientPort,
					IdentityFile: clientIdentity, KnownHosts: clientKnownHosts,
					Path: clientPath, Home: clientHome, ConfigPath: clientConfig,
				}
			}
			if err := runtimecontrol.Add(&config, args[0], control, replace); err != nil {
				return err
			}
			if err := runtimecontrol.Save(controlsPath, config); err != nil {
				return err
			}
			control = config.Controls[args[0]]
			fmt.Fprintf(stdout, "Runtime control %q saved\nruntime   %s\nprovider  %s\nresource  vmid=%d template=%d\nconfig    %s\n", args[0], control.Runtime, control.Provider, control.VMID, control.TemplateVMID, absolutePath(controlsPath))
			if control.Client != nil {
				fmt.Fprintf(stdout, "client    %s://%s %s\n", control.Client.Transport, control.Client.User, control.Client.Path)
			}
			fmt.Fprintf(stdout, "next      bofbench runtime control up %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	cmd.Flags().StringVar(&runtimeName, "runtime", "sliver", "runtime type: sliver or cobaltstrike")
	cmd.Flags().StringVar(&provider, "provider", "proxmox", "control-plane provider")
	cmd.Flags().StringVar(&preparation, "proxmox-prep", "", "secret-free Proxmox preparation file")
	cmd.Flags().IntVar(&vmid, "vmid", 0, "BOFBench-owned control-plane VMID")
	cmd.Flags().IntVar(&templateVMID, "template-vmid", 0, "source Linux template VMID")
	cmd.Flags().StringVar(&cloneMode, "clone-mode", "full", "Proxmox clone mode: full or linked")
	cmd.Flags().StringVar(&guestName, "guest-name", "", "Proxmox guest name; defaults to the control name")
	cmd.Flags().StringVar(&clientTransport, "client-transport", "", "run the runtime client remotely: ssh")
	cmd.Flags().StringVar(&clientUser, "client-user", "bofbench", "remote runtime-client SSH user")
	cmd.Flags().IntVar(&clientPort, "client-port", 22, "remote runtime-client SSH port")
	cmd.Flags().StringVar(&clientIdentity, "client-identity", "", "local SSH identity used only for the runtime-client guest")
	cmd.Flags().StringVar(&clientKnownHosts, "client-known-hosts", "", "dedicated known_hosts file for the runtime-client guest")
	cmd.Flags().StringVar(&clientPath, "client-path", "/usr/local/bin/sliver-client", "runtime-client executable path on the control guest")
	cmd.Flags().StringVar(&clientHome, "client-home", "/home/bofbench/.sliver-client", "dedicated runtime-client home on the control guest")
	cmd.Flags().StringVar(&clientConfig, "client-config", "/home/bofbench/.sliver-client/configs/bofbench.cfg", "runtime-client operator config on the control guest")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace an existing control profile")
	_ = cmd.MarkFlagRequired("proxmox-prep")
	_ = cmd.MarkFlagRequired("vmid")
	return cmd
}

func runtimeControlListCommand(stdout io.Writer) *cobra.Command {
	var controlsPath, format string
	cmd := &cobra.Command{Use: "list", Short: "List configured runtime control planes", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, config)
		}
		if format != "text" {
			return fmt.Errorf("runtime control list format must be text or json")
		}
		if len(config.Controls) == 0 {
			fmt.Fprintln(stdout, "No runtime control planes configured.")
			return nil
		}
		fmt.Fprintln(stdout, "ACTIVE  NAME                 RUNTIME       PROVIDER  VMID  TEMPLATE")
		for _, name := range runtimecontrol.Names(config) {
			control := config.Controls[name]
			active := ""
			if config.Active == name {
				active = "*"
			}
			fmt.Fprintf(stdout, "%-7s %-20s %-13s %-9s %-5d %d\n", active, name, control.Runtime, control.Provider, control.VMID, control.TemplateVMID)
		}
		return nil
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func runtimeControlShowCommand(stdout io.Writer) *cobra.Command {
	var controlsPath, format string
	cmd := &cobra.Command{Use: "show <name>", Short: "Show one runtime control profile without resolving secrets", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		name, control, err := runtimecontrol.Resolve(config, args[0])
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, map[string]any{"name": name, "control": control})
		}
		if format != "text" {
			return fmt.Errorf("runtime control show format must be text or json")
		}
		fmt.Fprintf(stdout, "Runtime control %s\nruntime      %s\nprovider     %s\nvmid         %d\ntemplate     %d\nclone mode   %s\npreparation  %s\n", name, control.Runtime, control.Provider, control.VMID, control.TemplateVMID, control.CloneMode, control.ProxmoxPrep)
		if control.Client != nil {
			fmt.Fprintf(stdout, "client        %s\nclient user   %s\nclient path   %s\nclient home   %s\nclient config %s\nknown hosts   %s\n", control.Client.Transport, control.Client.User, control.Client.Path, control.Client.Home, control.Client.ConfigPath, control.Client.KnownHosts)
		}
		return nil
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func runtimeControlLifecycleCommand(stdout io.Writer, action string) *cobra.Command {
	var controlsPath, format string
	var force bool
	cmd := &cobra.Command{Use: action + " <name>", Short: strings.Title(action) + " one runtime control plane", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		name, control, err := runtimecontrol.Resolve(config, args[0])
		if err != nil {
			return err
		}
		profile, err := runtimecontrol.LabProfile(control)
		if err != nil {
			return fmt.Errorf("runtime control %s: %w", name, err)
		}
		var receipts []lab.ProviderReceipt
		if action == "up" {
			status, statusErr := lab.RunProviderAction(cmd.Context(), "runtime-control-"+name, profile, "status", lab.ProviderActionOptions{})
			receipts = append(receipts, status)
			if statusErr != nil {
				return statusErr
			}
			if status.Resource.State == "absent" {
				if control.TemplateVMID == 0 {
					return fmt.Errorf("runtime control %s is absent and has no template VMID", name)
				}
				clone, cloneErr := lab.RunProviderAction(cmd.Context(), "runtime-control-"+name, profile, "clone", lab.ProviderActionOptions{Name: control.Name})
				receipts = append(receipts, clone)
				if cloneErr != nil {
					return cloneErr
				}
			}
		}
		receipt, err := lab.RunProviderAction(cmd.Context(), "runtime-control-"+name, profile, action, lab.ProviderActionOptions{Force: force})
		receipts = append(receipts, receipt)
		if err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, map[string]any{"name": name, "runtime": control.Runtime, "action": action, "receipts": receipts})
		}
		if format != "text" {
			return fmt.Errorf("runtime control %s format must be text or json", action)
		}
		fmt.Fprintf(stdout, "Runtime control %s %s complete\n", name, action)
		for _, item := range receipts {
			fmt.Fprintf(stdout, "%-10s vmid=%d state=%s task=%s receipt=%s\n", item.Action, item.Resource.VMID, item.Resource.State, emptyText(item.TaskStatus, "-"), item.EvidencePath)
		}
		return nil
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&force, "force", false, "allow force-capable provider behavior")
	return cmd
}

func runtimeControlRemoveCommand(stdout io.Writer) *cobra.Command {
	var controlsPath string
	cmd := &cobra.Command{Use: "remove <name>", Short: "Remove a control profile without changing its VM", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		if err := runtimecontrol.Remove(&config, args[0]); err != nil {
			return err
		}
		if err := runtimecontrol.Save(controlsPath, config); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Runtime control %q removed; no VM or runtime service was changed\n", args[0])
		return nil
	}
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	return cmd
}
