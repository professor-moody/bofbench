package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	var machine string
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
			profile := resolved.Profile
			if profile.Provider != "vagrant" {
				return fmt.Errorf("lab %s requires the vagrant provider; existing VMs are controlled by their operator snapshot system", operation)
			}
			selectedMachine := machine
			if selectedMachine == "" {
				selectedMachine = profile.VagrantMachine
			}
			vagrantArgs := []string{}
			switch operation {
			case "up":
				vagrantArgs = append(vagrantArgs, "up")
				if selectedMachine != "" {
					vagrantArgs = append(vagrantArgs, selectedMachine)
				}
			case "snapshot":
				vagrantArgs = append(vagrantArgs, "snapshot", "save")
				if selectedMachine != "" {
					vagrantArgs = append(vagrantArgs, selectedMachine)
				}
				vagrantArgs = append(vagrantArgs, args[0])
			case "restore":
				vagrantArgs = append(vagrantArgs, "snapshot", "restore")
				if selectedMachine != "" {
					vagrantArgs = append(vagrantArgs, selectedMachine)
				}
				vagrantArgs = append(vagrantArgs, args[0])
			}
			command := exec.CommandContext(cmd.Context(), "vagrant", vagrantArgs...)
			if profile.VagrantFile != "" {
				absolute, err := filepath.Abs(profile.VagrantFile)
				if err != nil {
					return err
				}
				command.Dir = filepath.Dir(absolute)
				command.Env = append(os.Environ(), "VAGRANT_VAGRANTFILE="+filepath.Base(absolute))
			}
			output, err := command.CombinedOutput()
			if len(output) > 0 {
				fmt.Fprint(stdout, string(output))
			}
			if err != nil {
				return codedError{code: 1, err: fmt.Errorf("vagrant %s failed: %w", operation, err)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&labName, "lab", "", "named Vagrant lab profile")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	if operation == "snapshot" || operation == "restore" {
		cmd.Flags().StringVar(&machine, "machine", "", "Vagrant machine name; omit for single-machine labs")
	}
	return cmd
}

func providerCommandSummary(operation string) string {
	switch operation {
	case "up":
		return "Start the configured Vagrant Windows topology"
	case "snapshot":
		return "Save a named Vagrant lab snapshot"
	default:
		return "Restore a named Vagrant lab snapshot"
	}
}
