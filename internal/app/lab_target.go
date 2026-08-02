package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/bofbench/internal/lab"
)

func labTargetCommand(stdout io.Writer) *cobra.Command {
	var labName string
	var profilesPath string
	var repository string
	var format string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "target", Short: "Manage the disposable LocalSystem capability-proof target"}
	cmd.PersistentFlags().StringVar(&labName, "lab", "", "named lab profile")
	cmd.PersistentFlags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.PersistentFlags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.PersistentFlags().DurationVar(&timeout, "transport-timeout", 3*time.Minute, "complete operation timeout")
	for _, operation := range []string{"deploy", "status", "remove"} {
		op := operation
		sub := &cobra.Command{
			Use: op, Short: op + " the disposable BOFBenchTarget service", Args: cobra.NoArgs,
			RunE: func(command *cobra.Command, args []string) error {
				if format != "text" && format != "json" {
					return fmt.Errorf("target format must be text or json")
				}
				resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(command.Context(), timeout)
				defer cancel()
				var report lab.TargetReport
				switch op {
				case "deploy":
					report, err = lab.DeployTarget(ctx, resolved.Name, resolved.Profile, repository)
				case "status":
					report, err = lab.TargetStatus(ctx, resolved.Name, resolved.Profile)
				case "remove":
					report, err = lab.RemoveTarget(ctx, resolved.Name, resolved.Profile)
				}
				if format == "json" {
					if printErr := printJSON(stdout, report); printErr != nil {
						return printErr
					}
				} else {
					fmt.Fprint(stdout, lab.TargetReportText(report))
				}
				if err != nil {
					return codedError{code: 1, err: err}
				}
				return nil
			},
		}
		if operation == "deploy" {
			sub.Flags().StringVar(&repository, "repo", "", "BOFBench repository root")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}
