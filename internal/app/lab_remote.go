package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
)

type remoteLabFlags struct {
	Lab        string
	Profiles   string
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
		Short: "Check a remote Windows lab over its configured transport",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRemoteFormat(flags.Format); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.Timeout)
			defer cancel()
			opts, _, err := flags.options(cmd.Context(), ".")
			if err != nil {
				return err
			}
			report, statusErr := lab.RemoteStatus(ctx, opts)
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
			opts, _, err := flags.options(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			report, syncErr := lab.RemoteSync(ctx, args[0], opts)
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
	var arch string
	var runtimeName string
	var profile string
	var noSync bool
	var bootstrapMode string
	var runTimeout int
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
			opts, resolvedLab, err := flags.options(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			ensured, err := lab.EnsureRuntime(ctx, bootstrapMode, lab.BootstrapOptions{ProfileName: resolvedLab.Name, Profile: resolvedLab.Profile})
			if err != nil {
				return codedError{code: 1, err: err}
			}
			if ensured.Bootstrap != nil {
				fmt.Fprint(stdout, lab.BootstrapText(*ensured.Bootstrap))
			}
			report, runErr := lab.RemoteRun(ctx, args[0], lab.RemoteRunOptions{
				RemoteOptions: opts, Compiler: compiler, Arch: arch, Runtime: runtimeName, Profile: profile, NoSync: noSync, TimeoutMS: runTimeout,
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
	cmd.Flags().StringVar(&arch, "arch", "x64", "BOF architecture: x64 or x86")
	cmd.Flags().StringVar(&runtimeName, "runtime", "windows-coff", "remote runtime")
	cmd.Flags().StringVar(&profile, "profile", "", "bofbench.toml test profile")
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "run the already-synced managed project")
	cmd.Flags().StringVar(&bootstrapMode, "bootstrap", "auto", "remote runtime bootstrap: auto, always, or never")
	cmd.Flags().IntVar(&runTimeout, "timeout", 5000, "BOF execution timeout in milliseconds")
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
			opts, _, err := flags.options(cmd.Context(), ".")
			if err != nil {
				return err
			}
			report, collectErr := lab.RemoteCollect(ctx, args[0], opts)
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
			opts, _, err := flags.options(cmd.Context(), ".")
			if err != nil {
				return err
			}
			report, resetErr := lab.RemoteReset(ctx, scope, opts)
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
	return remoteLabFlags{
		Profiles: lab.ProfilesPath(), SSH: "ssh", SCP: "scp",
		Timeout: 3 * time.Minute, Format: "text",
	}
}

func (flags remoteLabFlags) options(ctx context.Context, project string) (lab.RemoteOptions, lab.ResolvedProfile, error) {
	resolved, err := lab.ResolveProfile(flags.Lab, project, flags.Profiles)
	if err != nil {
		if flags.Host == "" {
			return lab.RemoteOptions{}, lab.ResolvedProfile{}, err
		}
		profile := lab.DefaultProfile("existing")
		profile.Host = flags.Host
		resolved = lab.ResolvedProfile{Name: "command-line", Source: "legacy-host-flags", Profile: profile}
	}
	opts, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return lab.RemoteOptions{}, lab.ResolvedProfile{}, err
	}
	if flags.Host != "" {
		opts.Host = flags.Host
	}
	if flags.RemoteRoot != "" {
		opts.RemoteRoot = flags.RemoteRoot
		opts.Executable = ""
	}
	if flags.Executable != "" {
		opts.Executable = flags.Executable
	}
	if flags.SSH != "" {
		opts.SSH = flags.SSH
	}
	if flags.SCP != "" {
		opts.SCP = flags.SCP
	}
	return opts, resolved, nil
}

func bindRemoteLabFlags(cmd *cobra.Command, flags *remoteLabFlags, needsSCP bool) {
	cmd.Flags().StringVar(&flags.Lab, "lab", "", "named lab profile; follows standard profile precedence when omitted")
	cmd.Flags().StringVar(&flags.Profiles, "profiles", flags.Profiles, "global lab profiles file")
	cmd.Flags().StringVar(&flags.Host, "host", "", "compatibility host override; prefer --lab")
	cmd.Flags().StringVar(&flags.RemoteRoot, "remote-root", "", "compatibility remote-root override; prefer the lab profile")
	cmd.Flags().StringVar(&flags.Executable, "remote-exe", "", "compatibility executable override; normally derived from remote_root")
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
