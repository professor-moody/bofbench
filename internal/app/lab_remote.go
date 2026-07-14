package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

type remoteLabFlags struct {
	Host       string
	RemoteRoot string
	Executable string
	SSH        string
	SCP        string
	Timeout    time.Duration
	Format     string
}

func labRemoteStatusCommand(stdout io.Writer) *cobra.Command {
	flags := defaultRemoteLabFlags()
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check a remote Windows lab over SSH",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			report, statusErr := lab.RemoteStatus(ctx, flags.options())
			if flags.Format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.RemoteStatusText(report))
			}
			if statusErr != nil {
				return codedError{code: 1, err: statusErr}
			}
			return nil
		},
	}
	bindRemoteLabFlags(cmd, &flags, false)
	return cmd
}

func labRemoteSyncCommand(stdout io.Writer) *cobra.Command {
	flags := defaultRemoteLabFlags()
	cmd := &cobra.Command{
		Use:   "sync <project>",
		Short: "Atomically sync a BOF project into the managed Windows lab workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			report, syncErr := lab.RemoteSync(ctx, args[0], flags.options())
			if flags.Format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.RemoteSyncText(report))
			}
			if syncErr != nil {
				return codedError{code: 1, err: syncErr}
			}
			return nil
		},
	}
	bindRemoteLabFlags(cmd, &flags, true)
	return cmd
}

func labRemoteRunCommand(stdout io.Writer) *cobra.Command {
	flags := defaultRemoteLabFlags()
	var compiler string
	var runtimeName string
	var profile string
	var noSync bool
	cmd := &cobra.Command{
		Use:   "run <project>",
		Short: "Sync, natively execute, and collect a BOF developer run from Windows",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			report, runErr := lab.RemoteRun(ctx, args[0], lab.RemoteRunOptions{
				RemoteOptions: flags.options(), Compiler: compiler, Runtime: runtimeName, Profile: profile, NoSync: noSync,
			})
			if flags.Format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.RemoteRunText(report))
			}
			if runErr != nil {
				return codedError{code: 1, err: runErr}
			}
			return nil
		},
	}
	bindRemoteLabFlags(cmd, &flags, true)
	cmd.Flags().StringVar(&compiler, "compiler", "msvc", "remote compiler profile: msvc, mingw, or auto")
	cmd.Flags().StringVar(&runtimeName, "runtime", "windows-coff", "remote runtime")
	cmd.Flags().StringVar(&profile, "profile", "", "bofbench.toml test profile")
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "run the already-synced managed project")
	return cmd
}

func labRemoteCollectCommand(stdout io.Writer) *cobra.Command {
	flags := defaultRemoteLabFlags()
	cmd := &cobra.Command{
		Use:   "collect <remote-run-id>",
		Short: "Collect and fingerprint a complete Windows run directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			report, collectErr := lab.RemoteCollect(ctx, args[0], flags.options())
			if flags.Format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.RemoteCollectText(report))
			}
			if collectErr != nil {
				return codedError{code: 1, err: collectErr}
			}
			return nil
		},
	}
	bindRemoteLabFlags(cmd, &flags, true)
	return cmd
}

func labRemoteResetCommand(stdout io.Writer) *cobra.Command {
	flags := defaultRemoteLabFlags()
	var scope string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset BOFBench-managed Windows lab work",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			report, resetErr := lab.RemoteReset(ctx, scope, flags.options())
			if flags.Format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, lab.RemoteResetText(report))
			}
			if resetErr != nil {
				return codedError{code: 1, err: resetErr}
			}
			return nil
		},
	}
	bindRemoteLabFlags(cmd, &flags, false)
	cmd.Flags().StringVar(&scope, "scope", "managed", "reset scope: managed, artifacts, or runs")
	return cmd
}

func defaultRemoteLabFlags() remoteLabFlags {
	opts := lab.DefaultRemoteOptions()
	if config, err := lab.LoadConfig(lab.DefaultConfigPath()); err == nil && config.Provider == "existing" {
		opts = config.RemoteOptions()
	}
	return remoteLabFlags{
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, Executable: os.Getenv("BOFBENCH_LAB_EXE"), SSH: opts.SSH, SCP: opts.SCP,
		Timeout: 3 * time.Minute, Format: "text",
	}
}

func (flags remoteLabFlags) options() lab.RemoteOptions {
	return lab.RemoteOptions{Host: flags.Host, RemoteRoot: flags.RemoteRoot, Executable: flags.Executable, SSH: flags.SSH, SCP: flags.SCP}
}

func bindRemoteLabFlags(cmd *cobra.Command, flags *remoteLabFlags, needsSCP bool) {
	cmd.Flags().StringVar(&flags.Host, "host", flags.Host, "SSH host or configured alias")
	cmd.Flags().StringVar(&flags.RemoteRoot, "remote-root", flags.RemoteRoot, "BOFBench root on Windows")
	cmd.Flags().StringVar(&flags.Executable, "remote-exe", flags.Executable, "BOFBench executable on Windows")
	cmd.Flags().StringVar(&flags.SSH, "ssh", flags.SSH, "SSH client executable")
	if needsSCP {
		cmd.Flags().StringVar(&flags.SCP, "scp", flags.SCP, "SCP client executable")
	}
	cmd.Flags().DurationVar(&flags.Timeout, "transport-timeout", flags.Timeout, "complete remote operation timeout")
	cmd.Flags().StringVar(&flags.Format, "format", flags.Format, "output format: text or json")
}

func validateRemoteFormat(format string) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("remote lab format must be text or json")
	}
	return nil
}
