package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

func labInitCommand(stdout io.Writer) *cobra.Command {
	cmd := labAddCommand(stdout)
	run := cmd.RunE
	cmd.Use = "init"
	cmd.Short = "Compatibility alias for 'lab add default'"
	cmd.Args = cobra.NoArgs
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return run(cmd, []string{"default"})
	}
	return cmd
}

func labBootstrapCommand(stdout io.Writer) *cobra.Command {
	var labName string
	var profilesPath string
	var repository string
	var executable string
	var loader string
	var loaderX86 string
	var format string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "bootstrap", Short: "Deploy BOFBench and native loaders and report usable lab capabilities", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("lab bootstrap format must be text or json")
			}
			resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			report, bootstrapErr := lab.Bootstrap(ctx, lab.BootstrapOptions{ProfileName: resolved.Name, Profile: resolved.Profile, Repository: repository, Executable: executable, LoaderX64: loader, LoaderX86: loaderX86})
			if format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.BootstrapText(report))
			}
			if bootstrapErr != nil {
				return codedError{code: 1, err: bootstrapErr}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile; follows standard profile precedence when omitted")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&repository, "repo", "", "BOFBench repository root; default current directory")
	cmd.Flags().StringVar(&executable, "bofbench-exe", "", "prebuilt Windows bofbench.exe; otherwise cross-build it")
	cmd.Flags().StringVar(&loader, "loader-x64", "", "prebuilt x64 loader; default native/loader/bofbench-loader.exe")
	cmd.Flags().StringVar(&loaderX86, "loader-x86", "", "prebuilt x86 loader; default native/loader/bofbench-loader-x86.exe")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "complete bootstrap timeout")
	return cmd
}

func labProviderCommand(stdout io.Writer, operation string) *cobra.Command {
	var labName string
	var profilesPath string
	var resourceName string
	var format string
	var force bool
	use := operation
	if operation == "snapshot" || operation == "restore" {
		use += " <name>"
	}
	cmd := &cobra.Command{
		Use: use, Short: providerCommandSummary(operation),
		Args: func(cmd *cobra.Command, args []string) error {
			if operation == "snapshot" || operation == "restore" {
				return cobra.ExactArgs(1)(cmd, args)
			}
			return cobra.NoArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
			if err != nil {
				return err
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("lab %s format must be text or json", operation)
			}
			snapshot := ""
			if len(args) > 0 {
				snapshot = args[0]
			}
			if operation == "up" && strings.EqualFold(resolved.Profile.Provider, "proxmox") {
				status, statusErr := lab.RunProviderAction(cmd.Context(), resolved.Name, resolved.Profile, "status", lab.ProviderActionOptions{})
				if statusErr != nil {
					return codedError{code: 1, err: statusErr}
				}
				if status.Resource.State == "absent" {
					_, cloneErr := lab.RunProviderAction(cmd.Context(), resolved.Name, resolved.Profile, "clone", lab.ProviderActionOptions{Name: resolved.Name})
					if cloneErr != nil {
						return codedError{code: 1, err: cloneErr}
					}
				}
			}
			receipt, actionErr := lab.RunProviderAction(cmd.Context(), resolved.Name, resolved.Profile, operation, lab.ProviderActionOptions{Snapshot: snapshot, Name: resourceName, Force: force})
			if format == "json" {
				if err := printJSON(stdout, receipt); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.ProviderReceiptText(receipt))
			}
			if actionErr != nil {
				return codedError{code: 1, err: actionErr}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	if operation == "clone" {
		cmd.Flags().StringVar(&resourceName, "name", "", "name for the cloned VM")
	}
	if operation == "destroy" || operation == "stop" {
		cmd.Flags().BoolVar(&force, "force", false, "request forceful provider action")
	}
	return cmd
}

func labProviderRootCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "provider", Short: "Inspect the infrastructure provider behind a lab profile"}
	cmd.AddCommand(labProviderCommand(stdout, "status"))
	return cmd
}

func providerCommandSummary(operation string) string {
	switch operation {
	case "up":
		return "Start the configured lab machine"
	case "down":
		return "Gracefully stop the configured lab machine"
	case "stop":
		return "Immediately stop the configured lab machine"
	case "snapshot":
		return "Save a named lab snapshot"
	case "restore":
		return "Restore a named lab snapshot"
	case "clone":
		return "Clone the configured Proxmox template into this profile VMID"
	case "template":
		return "Convert the configured Proxmox VM into a template"
	case "destroy":
		return "Destroy the configured provider-managed lab machine"
	default:
		return "Show provider state and discovered guest identity"
	}
}
