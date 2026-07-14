package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

func labInitCommand(stdout io.Writer) *cobra.Command {
	var configPath string
	var provider string
	var topology string
	var transport string
	var host string
	var remoteRoot string
	var executable string
	var vagrantFile string
	cmd := &cobra.Command{
		Use: "init", Short: "Configure an existing Windows VM or a Vagrant-backed lab", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			config := lab.DefaultConfig(provider)
			config.Topology = strings.ToLower(topology)
			config.Transport = strings.ToLower(transport)
			config.Host = host
			config.RemoteRoot = remoteRoot
			config.Executable = executable
			config.VagrantFile = vagrantFile
			if err := lab.SaveConfig(configPath, config); err != nil {
				return err
			}
			absolute, _ := filepath.Abs(configPath)
			fmt.Fprintf(stdout, "Windows lab configured\nprovider    %s\ntopology    %s\ntransport   %s\nconfig      %s\nnext        bofbench lab bootstrap\n", config.Provider, config.Topology, config.Transport, absolute)
			return nil
		},
	}
	defaults := lab.DefaultConfig("existing")
	cmd.Flags().StringVar(&configPath, "config", lab.DefaultConfigPath(), "lab configuration path")
	cmd.Flags().StringVar(&provider, "provider", "existing", "provider: existing or vagrant")
	cmd.Flags().StringVar(&topology, "topology", defaults.Topology, "topology: standalone or domain")
	cmd.Flags().StringVar(&transport, "transport", defaults.Transport, "existing-VM transport: ssh or winrm")
	cmd.Flags().StringVar(&host, "host", defaults.Host, "existing Windows VM SSH host or alias")
	cmd.Flags().StringVar(&remoteRoot, "remote-root", defaults.RemoteRoot, "managed BOFBench directory on Windows")
	cmd.Flags().StringVar(&executable, "remote-exe", defaults.Executable, "BOFBench executable path on Windows")
	cmd.Flags().StringVar(&vagrantFile, "vagrantfile", defaults.VagrantFile, "operator-supplied Vagrantfile")
	return cmd
}

func labBootstrapCommand(stdout io.Writer) *cobra.Command {
	var configPath string
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
			config, err := lab.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("load lab config; run 'bofbench lab init' first: %w", err)
			}
			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			report, bootstrapErr := lab.Bootstrap(ctx, lab.BootstrapOptions{Config: config, ConfigPath: configPath, Repository: repository, Executable: executable, LoaderX64: loader, LoaderX86: loaderX86})
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
	cmd.Flags().StringVar(&configPath, "config", lab.DefaultConfigPath(), "lab configuration path")
	cmd.Flags().StringVar(&repository, "repo", "", "BOFBench repository root; default current directory")
	cmd.Flags().StringVar(&executable, "bofbench-exe", "", "prebuilt Windows bofbench.exe; otherwise cross-build it")
	cmd.Flags().StringVar(&loader, "loader-x64", "", "prebuilt x64 loader; default native/loader/bofbench-loader.exe")
	cmd.Flags().StringVar(&loaderX86, "loader-x86", "", "prebuilt x86 loader; default native/loader/bofbench-loader-x86.exe")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "complete bootstrap timeout")
	return cmd
}

func labProviderCommand(stdout io.Writer, operation string) *cobra.Command {
	var configPath string
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
			config, err := lab.LoadConfig(configPath)
			if err != nil {
				return err
			}
			if config.Provider != "vagrant" {
				return fmt.Errorf("lab %s requires the vagrant provider; existing VMs are controlled by their operator snapshot system", operation)
			}
			vagrantArgs := []string{}
			switch operation {
			case "up":
				vagrantArgs = append(vagrantArgs, "up")
			case "snapshot":
				vagrantArgs = append(vagrantArgs, "snapshot", "save")
				if machine != "" {
					vagrantArgs = append(vagrantArgs, machine)
				}
				vagrantArgs = append(vagrantArgs, args[0])
			case "restore":
				vagrantArgs = append(vagrantArgs, "snapshot", "restore")
				if machine != "" {
					vagrantArgs = append(vagrantArgs, machine)
				}
				vagrantArgs = append(vagrantArgs, args[0])
			}
			command := exec.CommandContext(cmd.Context(), "vagrant", vagrantArgs...)
			if config.VagrantFile != "" {
				absolute, err := filepath.Abs(config.VagrantFile)
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
	cmd.Flags().StringVar(&configPath, "config", lab.DefaultConfigPath(), "lab configuration path")
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
