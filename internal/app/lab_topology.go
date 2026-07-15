package app

import (
	"fmt"
	"io"
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
		labTopologyUseCommand(stdout),
		labTopologyRemoveCommand(stdout),
	)
	return cmd
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
