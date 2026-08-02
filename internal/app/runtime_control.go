package app

import (
	"fmt"
	"io"
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
		runtimeControlRemoveCommand(stdout),
	)
	return cmd
}

func runtimeControlAddCommand(stdout io.Writer) *cobra.Command {
	var controlsPath, runtimeName, provider, preparation, cloneMode, guestName string
	var vmid, templateVMID int
	var replace bool
	cmd := &cobra.Command{
		Use: "add <name>", Short: "Register a Proxmox-backed Sliver or Cobalt Strike control plane", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := runtimecontrol.Load(controlsPath)
			if err != nil {
				return err
			}
			control := runtimecontrol.Control{Runtime: runtimeName, Provider: provider, ProxmoxPrep: preparation, VMID: vmid, TemplateVMID: templateVMID, CloneMode: cloneMode, Name: guestName}
			if err := runtimecontrol.Add(&config, args[0], control, replace); err != nil {
				return err
			}
			if err := runtimecontrol.Save(controlsPath, config); err != nil {
				return err
			}
			control = config.Controls[args[0]]
			fmt.Fprintf(stdout, "Runtime control %q saved\nruntime   %s\nprovider  %s\nresource  vmid=%d template=%d\nconfig    %s\nnext      bofbench runtime control up %s\n", args[0], control.Runtime, control.Provider, control.VMID, control.TemplateVMID, absolutePath(controlsPath), args[0])
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
