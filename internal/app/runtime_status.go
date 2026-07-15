package app

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
	"bofbench/internal/runtimeadapter"
)

type runtimeStatusItem struct {
	Runtime      string                      `json:"runtime"`
	Availability runtimeadapter.Availability `json:"availability"`
	Sessions     []runtimeadapter.Session    `json:"sessions,omitempty"`
	SessionError string                      `json:"session_error,omitempty"`
}

func runtimeCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "runtime", Short: "Inspect native, lab, Sliver, and Cobalt Strike runtime readiness"}
	cmd.AddCommand(runtimeStatusCommand(stdout), runtimeSessionsCommand(stdout))
	return cmd
}

func runtimeStatusCommand(stdout io.Writer) *cobra.Command {
	var labName, profilesPath, format string
	cmd := &cobra.Command{
		Use: "status", Short: "Show concise runtime and session readiness", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			context := &runtimeRunContext{stdout: io.Discard, input: ".", labName: labName, labProfiles: profilesPath}
			registry, err := runtimeAdapterRegistry(context)
			if err != nil {
				return err
			}
			var report []runtimeStatusItem
			for _, name := range registry.Names() {
				adapter, _ := registry.Resolve(name)
				availability, detectErr := adapter.Detect(cmd.Context())
				if detectErr != nil {
					availability.Detail = detectErr.Error()
				}
				item := runtimeStatusItem{Runtime: name, Availability: availability}
				if availability.Available {
					sessions, sessionErr := adapter.Sessions(cmd.Context())
					item.Sessions = sessions
					if sessionErr != nil {
						item.SessionError = sessionErr.Error()
					}
				}
				report = append(report, item)
			}
			if format == "json" {
				return printJSON(stdout, report)
			}
			if format != "text" {
				return fmt.Errorf("runtime status format must be text or json")
			}
			fmt.Fprintln(stdout, "RUNTIME       STATUS       SESSION / DETAIL")
			for _, item := range report {
				status := "unavailable"
				if item.Availability.Available {
					status = "ready"
				}
				detail := item.Availability.Detail
				if len(item.Sessions) > 0 {
					detail = item.Sessions[0].Name
					if detail == "" {
						detail = item.Sessions[0].ID
					}
				}
				if item.SessionError != "" {
					detail = item.SessionError
					status = "configured"
				}
				fmt.Fprintf(stdout, "%-13s %-12s %s\n", item.Runtime, status, emptyText(detail, "no session selected"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile used for lab and Sliver readiness")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func runtimeSessionsCommand(stdout io.Writer) *cobra.Command {
	var via, labName, profilesPath, format string
	cmd := &cobra.Command{
		Use: "sessions", Short: "Show sessions visible to one runtime adapter", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			context := &runtimeRunContext{stdout: io.Discard, input: ".", labName: labName, labProfiles: profilesPath}
			registry, err := runtimeAdapterRegistry(context)
			if err != nil {
				return err
			}
			adapter, err := registry.Resolve(via)
			if err != nil {
				return err
			}
			availability, err := adapter.Detect(cmd.Context())
			if err != nil {
				return err
			}
			if !availability.Available {
				return fmt.Errorf("%s runtime is unavailable: %s", adapter.Name(), emptyText(availability.Detail, "not configured"))
			}
			sessions, err := adapter.Sessions(cmd.Context())
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, sessions)
			}
			if format != "text" {
				return fmt.Errorf("runtime sessions format must be text or json")
			}
			if len(sessions) == 0 {
				fmt.Fprintf(stdout, "No %s sessions are selected or available.\n", adapter.Name())
				return nil
			}
			fmt.Fprintln(stdout, "RUNTIME       SESSION                  HOST                 STATUS")
			for _, session := range sessions {
				fmt.Fprintf(stdout, "%-13s %-24s %-20s %s\n", adapter.Name(), emptyText(session.Name, session.ID), emptyText(session.Host, "-"), emptyText(session.Status, "ready"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&via, "via", "sliver", "runtime adapter: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile used for lab and Sliver session selection")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}
