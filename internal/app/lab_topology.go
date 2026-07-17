package app

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

func labTopologyCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "topology", Short: "Group portable lab profiles by execution, target, and domain roles"}
	cmd.AddCommand(
		labTopologyAddCommand(stdout),
		labTopologyListCommand(stdout),
		labTopologyShowCommand(stdout),
		labTopologyStatusCommand(stdout),
		labTopologyProvisionCommand(stdout),
		labTopologyVerifyCommand(stdout),
		labTopologyLifecycleCommand(stdout, "up"),
		labTopologyLifecycleCommand(stdout, "down"),
		labTopologyLifecycleCommand(stdout, "snapshot"),
		labTopologyLifecycleCommand(stdout, "restore"),
		labTopologyTargetCommand(stdout),
		labTopologyUseCommand(stdout),
		labTopologyRemoveCommand(stdout),
	)
	return cmd
}

func labTopologyTargetCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Manage ordered named target sets in a topology"}
	cmd.AddCommand(labTopologyTargetAddCommand(stdout), labTopologyTargetListCommand(stdout), labTopologyTargetRemoveCommand(stdout))
	return cmd
}

func labTopologyTargetAddCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, setName, profileName string
	cmd := &cobra.Command{Use: "add <topology>", Short: "Append one exact lab profile to a named target set", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := lab.LoadProfiles(profilesPath)
		if err != nil {
			return err
		}
		if err := lab.AddTopologyTarget(&config, args[0], setName, profileName); err != nil {
			return err
		}
		if err := lab.SaveProfiles(profilesPath, config); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Topology %q target set %q now includes %q\n", args[0], setName, profileName)
		return nil
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&setName, "set", "", "target set name")
	cmd.Flags().StringVar(&profileName, "lab", "", "exact lab profile to append")
	_ = cmd.MarkFlagRequired("set")
	_ = cmd.MarkFlagRequired("lab")
	return cmd
}

func labTopologyTargetListCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, format string
	cmd := &cobra.Command{Use: "list <topology>", Short: "List ordered target sets for one topology", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := lab.LoadProfiles(profilesPath)
		if err != nil {
			return err
		}
		topology, ok := config.Topologies[args[0]]
		if !ok {
			return fmt.Errorf("topology %q does not exist", args[0])
		}
		if format == "json" {
			return printJSON(stdout, map[string]any{"topology": args[0], "target_sets": topology.TargetSets})
		}
		if format != "text" {
			return fmt.Errorf("lab topology target list format must be text or json")
		}
		if len(topology.TargetSets) == 0 {
			fmt.Fprintf(stdout, "Topology %q has no named target sets.\n", args[0])
			return nil
		}
		names := make([]string, 0, len(topology.TargetSets))
		for name := range topology.TargetSets {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintln(stdout, "SET                  POSITION  PROFILE")
		for _, name := range names {
			for index, profile := range topology.TargetSets[name] {
				fmt.Fprintf(stdout, "%-20s %-9d %s\n", name, index+1, profile)
			}
		}
		return nil
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTopologyTargetRemoveCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, setName, profileName string
	cmd := &cobra.Command{Use: "remove <topology>", Short: "Remove one profile from a named target set", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		config, err := lab.LoadProfiles(profilesPath)
		if err != nil {
			return err
		}
		if err := lab.RemoveTopologyTarget(&config, args[0], setName, profileName); err != nil {
			return err
		}
		if err := lab.SaveProfiles(profilesPath, config); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Topology %q target set %q no longer includes %q\n", args[0], setName, profileName)
		return nil
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&setName, "set", "", "target set name")
	cmd.Flags().StringVar(&profileName, "lab", "", "exact lab profile to remove")
	_ = cmd.MarkFlagRequired("set")
	_ = cmd.MarkFlagRequired("lab")
	return cmd
}

type topologyProviderResult struct {
	Role     string                `json:"role"`
	Profile  string                `json:"profile"`
	Action   string                `json:"action"`
	Receipts []lab.ProviderReceipt `json:"receipts"`
}

func labTopologyLifecycleCommand(stdout io.Writer, action string) *cobra.Command {
	var profilesPath, snapshot, format string
	var force bool
	use := action + " <name>"
	short := map[string]string{
		"up":       "Provision missing provider guests and start every controllable topology role",
		"down":     "Gracefully stop every controllable topology role in reverse order",
		"snapshot": "Snapshot every provider-controlled topology role",
		"restore":  "Restore every provider-controlled topology role to one snapshot",
	}[action]
	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		resolved, err := lab.ResolveTopology(args[0], profilesPath)
		if err != nil {
			return err
		}
		roles := orderedTopologyProviderRoles(resolved, action == "down")
		results := make([]topologyProviderResult, 0, len(roles))
		for _, role := range roles {
			result, runErr := runTopologyProviderRole(cmd.Context(), role.role, role.profile, action, snapshot, force)
			results = append(results, result)
			if runErr != nil {
				if format == "json" {
					_ = printJSON(stdout, map[string]any{"topology": resolved.Name, "action": action, "roles": results, "status": "failed"})
				}
				return fmt.Errorf("topology %s role %s: %w", resolved.Name, role.role, runErr)
			}
		}
		if format == "json" {
			return printJSON(stdout, map[string]any{"topology": resolved.Name, "action": action, "roles": results, "status": "complete"})
		}
		if format != "text" {
			return fmt.Errorf("lab topology %s format must be text or json", action)
		}
		fmt.Fprintf(stdout, "Lab topology %s %s complete\n", resolved.Name, action)
		for _, result := range results {
			if len(result.Receipts) == 0 {
				fmt.Fprintf(stdout, "%-18s %-18s external (not lifecycle-managed)\n", strings.ReplaceAll(result.Role, "_", " "), result.Profile)
				continue
			}
			last := result.Receipts[len(result.Receipts)-1]
			fmt.Fprintf(stdout, "%-18s %-18s %-10s vmid=%d receipt=%s\n", strings.ReplaceAll(result.Role, "_", " "), result.Profile, last.Resource.State, last.Resource.VMID, last.EvidencePath)
		}
		return nil
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&snapshot, "snapshot", "", "snapshot name for snapshot or restore")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&force, "force", false, "permit force-capable provider behavior")
	if action == "snapshot" || action == "restore" {
		_ = cmd.MarkFlagRequired("snapshot")
	}
	return cmd
}

type topologyProviderRole struct {
	role    string
	profile lab.ResolvedProfile
}

func orderedTopologyProviderRoles(resolved lab.ResolvedTopology, reverse bool) []topologyProviderRole {
	var roles []topologyProviderRole
	if resolved.DomainController != nil {
		roles = append(roles, topologyProviderRole{"domain_controller", *resolved.DomainController})
	}
	if resolved.Target != nil {
		roles = append(roles, topologyProviderRole{"target", *resolved.Target})
	}
	roles = append(roles, topologyProviderRole{"execution", resolved.Execution})
	if reverse {
		for left, right := 0, len(roles)-1; left < right; left, right = left+1, right-1 {
			roles[left], roles[right] = roles[right], roles[left]
		}
	}
	return roles
}

func runTopologyProviderRole(ctx context.Context, role string, resolved lab.ResolvedProfile, action, snapshot string, force bool) (topologyProviderResult, error) {
	result := topologyProviderResult{Role: role, Profile: resolved.Name, Action: action}
	providerName := strings.ToLower(strings.TrimSpace(resolved.Profile.Provider))
	if providerName == "existing" {
		// Existing systems are intentionally never started, stopped, snapshotted,
		// or restored by BOFBench. Their status remains part of topology status.
		return result, nil
	}
	if action == "up" && providerName == "proxmox" {
		status, err := lab.RunProviderAction(ctx, resolved.Name, resolved.Profile, "status", lab.ProviderActionOptions{})
		result.Receipts = append(result.Receipts, status)
		if err != nil {
			return result, err
		}
		if status.Resource.State == "absent" {
			clone, cloneErr := lab.RunProviderAction(ctx, resolved.Name, resolved.Profile, "clone", lab.ProviderActionOptions{Name: resolved.Name})
			result.Receipts = append(result.Receipts, clone)
			if cloneErr != nil {
				return result, cloneErr
			}
		}
	}
	receipt, err := lab.RunProviderAction(ctx, resolved.Name, resolved.Profile, action, lab.ProviderActionOptions{Snapshot: snapshot, Force: force})
	result.Receipts = append(result.Receipts, receipt)
	return result, err
}

func labTopologyAddCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, execution, target, domainController string
	var replace bool
	cmd := &cobra.Command{
		Use: "add <name>", Short: "Save a reusable multi-host lab role mapping", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			topology := lab.ProfileTopology{Execution: execution, Target: target, DomainController: domainController}
			if err := lab.AddTopology(&config, args[0], topology, replace); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Lab topology %q saved\nExecution          %s\nTarget             %s\nDomain controller  %s\n", args[0], execution, emptyText(target, "not configured"), emptyText(domainController, "not configured"))
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&execution, "execution", "", "profile where BOFBench executes the BOF")
	cmd.Flags().StringVar(&target, "target", "", "profile for exact cross-host effects and verification")
	cmd.Flags().StringVar(&domainController, "domain-controller", "", "profile for domain discovery and directory proofs")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace an existing topology")
	_ = cmd.MarkFlagRequired("execution")
	return cmd
}

func labTopologyListCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, format string
	cmd := &cobra.Command{
		Use: "list", Short: "List configured lab topologies", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, map[string]any{"active": config.ActiveTopology, "topologies": config.Topologies})
			}
			if format != "text" {
				return fmt.Errorf("lab topology list format must be text or json")
			}
			if len(config.Topologies) == 0 {
				fmt.Fprintln(stdout, "No lab topologies configured.")
				return nil
			}
			fmt.Fprintln(stdout, "ACTIVE  NAME                 EXECUTION            TARGET               DOMAIN CONTROLLER")
			for _, name := range lab.TopologyNames(config) {
				topology := config.Topologies[name]
				active := ""
				if config.ActiveTopology == name {
					active = "*"
				}
				fmt.Fprintf(stdout, "%-7s %-20s %-20s %-20s %s\n", active, name, topology.Execution, emptyText(topology.Target, "-"), emptyText(topology.DomainController, "-"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTopologyShowCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, format string
	cmd := &cobra.Command{
		Use: "show <name>", Short: "Show the profile roles in one topology", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := lab.ResolveTopology(args[0], profilesPath)
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, resolved)
			}
			if format != "text" {
				return fmt.Errorf("lab topology show format must be text or json")
			}
			fmt.Fprintf(stdout, "Lab topology %s\nExecution          %s (%s)\n", resolved.Name, resolved.Execution.Name, profileTarget(resolved.Execution.Profile))
			if resolved.Target != nil {
				fmt.Fprintf(stdout, "Target             %s (%s)\n", resolved.Target.Name, profileTarget(resolved.Target.Profile))
			}
			if resolved.DomainController != nil {
				fmt.Fprintf(stdout, "Domain controller  %s (%s)\n", resolved.DomainController.Name, profileTarget(resolved.DomainController.Profile))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

type topologyRoleStatus struct {
	Role         string `json:"role"`
	Profile      string `json:"profile"`
	Target       string `json:"target"`
	Status       string `json:"status"`
	ComputerName string `json:"computer_name,omitempty"`
	Error        string `json:"error,omitempty"`
}

func labTopologyStatusCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, format string
	cmd := &cobra.Command{
		Use: "status <name>", Short: "Check every configured role in a lab topology", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := lab.ResolveTopology(args[0], profilesPath)
			if err != nil {
				return err
			}
			roles := []struct {
				name string
				item *lab.ResolvedProfile
			}{{"execution", &resolved.Execution}, {"target", resolved.Target}, {"domain_controller", resolved.DomainController}}
			var statuses []topologyRoleStatus
			for _, role := range roles {
				if role.item == nil {
					continue
				}
				remote, resolveErr := lab.ResolveRemoteOptions(cmd.Context(), role.item.Name, role.item.Profile)
				status := topologyRoleStatus{Role: role.name, Profile: role.item.Name, Target: profileTarget(role.item.Profile), Status: "unavailable"}
				if resolveErr == nil {
					report, statusErr := lab.RemoteStatus(cmd.Context(), remote)
					status.ComputerName = report.ComputerName
					if statusErr == nil {
						status.Status = "ready"
					} else {
						status.Error = statusErr.Error()
					}
				} else {
					status.Error = resolveErr.Error()
				}
				statuses = append(statuses, status)
			}
			if format == "json" {
				return printJSON(stdout, map[string]any{"topology": resolved.Name, "roles": statuses})
			}
			if format != "text" {
				return fmt.Errorf("lab topology status format must be text or json")
			}
			fmt.Fprintf(stdout, "Lab topology %s\n", resolved.Name)
			for _, status := range statuses {
				fmt.Fprintf(stdout, "%-18s %-18s %-12s %s\n", strings.ReplaceAll(status.Role, "_", " "), status.Profile, status.Status, emptyText(status.ComputerName, status.Target))
				if status.Error != "" {
					fmt.Fprintf(stdout, "  %s\n", status.Error)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTopologyUseCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	cmd := &cobra.Command{
		Use: "use <name>", Short: "Select the active lab topology", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if err := lab.UseTopology(&config, args[0]); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Active lab topology is now %q\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	return cmd
}

func labTopologyRemoveCommand(stdout io.Writer) *cobra.Command {
	var profilesPath string
	cmd := &cobra.Command{
		Use: "remove <name>", Short: "Remove a topology without changing its profiles or hosts", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := lab.LoadProfiles(profilesPath)
			if err != nil {
				return err
			}
			if err := lab.RemoveTopology(&config, args[0]); err != nil {
				return err
			}
			if err := lab.SaveProfiles(profilesPath, config); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Lab topology %q removed; no profile or host was changed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	return cmd
}
