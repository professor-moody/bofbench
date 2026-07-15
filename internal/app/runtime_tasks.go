package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
	"bofbench/internal/runtimeadapter"
)

type runtimeTaskView struct {
	Receipt runtimeadapter.Receipt `json:"receipt"`
	Path    string                 `json:"path"`
	Updated string                 `json:"updated"`
}

func runtimeTasksCommand(stdout io.Writer) *cobra.Command {
	var via, labName, format string
	cmd := &cobra.Command{
		Use: "tasks", Short: "List persisted C2 task receipts", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tasks, err := loadRuntimeTaskReceipts("runs", via, labName)
			if err != nil {
				return err
			}
			return printRuntimeTasks(stdout, tasks, format)
		},
	}
	cmd.Flags().StringVar(&via, "via", "sliver", "runtime task source: sliver or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "optional receipt profile filter")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func runtimeTaskCommand(stdout io.Writer) *cobra.Command {
	var via, labName, format string
	var wait bool
	var timeout, interval time.Duration
	cmd := &cobra.Command{
		Use: "task <task-id|receipt-path>", Short: "Inspect or wait for one persisted C2 task", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if wait {
				var cancel context.CancelFunc
				ctx, cancel = contextWithTimeout(ctx, timeout)
				defer cancel()
			}
			for {
				task, err := findRuntimeTaskReceipt("runs", args[0], via, labName)
				if err == nil && (!wait || runtimeTaskTerminal(task.Receipt.ExecutionState)) {
					return printRuntimeTasks(stdout, []runtimeTaskView{task}, format)
				}
				if err != nil && !wait {
					return err
				}
				select {
				case <-ctx.Done():
					if err != nil {
						return fmt.Errorf("waiting for runtime task: %w", err)
					}
					return fmt.Errorf("runtime task did not reach a terminal state: %w", ctx.Err())
				case <-time.After(interval):
				}
			}
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "optional runtime filter: sliver or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "optional receipt profile filter")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait until the persisted task reaches a terminal state")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "maximum wait time")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "receipt polling interval")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func runtimeWatchCommand(stdout io.Writer) *cobra.Command {
	var via, labName, profilesPath, format string
	var timeout, interval time.Duration
	cmd := &cobra.Command{
		Use: "watch", Short: "Watch runtime session readiness and persisted task transitions", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("runtime watch format must be text or json")
			}
			runContext := &runtimeRunContext{stdout: io.Discard, input: ".", labName: labName, labProfiles: profilesPath}
			registry, err := runtimeAdapterRegistry(runContext)
			if err != nil {
				return err
			}
			adapter, err := registry.Resolve(via)
			if err != nil {
				return err
			}
			ctx, cancel := contextWithTimeout(cmd.Context(), timeout)
			defer cancel()
			seen := map[string]string{}
			for {
				sessions, sessionErr := adapter.Sessions(ctx)
				tasks, taskErr := loadRuntimeTaskReceipts("runs", via, labName)
				if taskErr != nil {
					return taskErr
				}
				if format == "json" {
					if err := printJSON(stdout, struct {
						Sessions []runtimeadapter.Session `json:"sessions,omitempty"`
						Tasks    []runtimeTaskView        `json:"tasks,omitempty"`
						Error    string                   `json:"session_error,omitempty"`
					}{Sessions: sessions, Tasks: tasks, Error: errorText(sessionErr)}); err != nil {
						return err
					}
				} else {
					if sessionErr != nil {
						fmt.Fprintf(stdout, "%s session unavailable: %s\n", adapter.Name(), sessionErr)
					} else {
						for _, session := range sessions {
							key := "session:" + session.ID
							if seen[key] != session.Status {
								fmt.Fprintf(stdout, "%s session %s host=%s state=%s\n", adapter.Name(), emptyText(session.Name, session.ID), emptyText(session.Host, "-"), emptyText(session.Status, "ready"))
								seen[key] = session.Status
							}
						}
					}
					for _, task := range tasks {
						key := "task:" + emptyText(task.Receipt.TaskID, task.Path)
						if seen[key] != task.Receipt.ExecutionState {
							printRuntimeTaskLine(stdout, task)
							seen[key] = task.Receipt.ExecutionState
						}
					}
				}
				select {
				case <-ctx.Done():
					if ctx.Err() == context.DeadlineExceeded {
						return nil
					}
					return ctx.Err()
				case <-time.After(interval):
				}
			}
		},
	}
	cmd.Flags().StringVar(&via, "via", "sliver", "runtime adapter: sliver or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile used for session and receipt filtering")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "maximum watch duration")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "polling interval")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func loadRuntimeTaskReceipts(root, via, profile string) ([]runtimeTaskView, error) {
	if via != "" && via != "sliver" && via != "cobaltstrike" {
		return nil, fmt.Errorf("runtime tasks supports sliver or cobaltstrike, got %q", via)
	}
	paths, err := filepath.Glob(filepath.Join(root, "*", "result.json"))
	if err != nil {
		return nil, err
	}
	var tasks []runtimeTaskView
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var receipt runtimeadapter.Receipt
		if json.Unmarshal(data, &receipt) != nil || receipt.Schema != runtimeadapter.ReceiptSchema {
			continue
		}
		if receipt.Runtime != "sliver" && receipt.Runtime != "cobaltstrike" {
			continue
		}
		if via != "" && receipt.Runtime != via || profile != "" && receipt.Profile != profile {
			continue
		}
		info, _ := os.Stat(path)
		updated := receipt.CompletedAt
		if updated == "" && info != nil {
			updated = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		tasks = append(tasks, runtimeTaskView{Receipt: receipt, Path: path, Updated: updated})
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].Updated > tasks[j].Updated })
	return tasks, nil
}

func findRuntimeTaskReceipt(root, id, via, profile string) (runtimeTaskView, error) {
	if strings.ContainsAny(id, `/\\`) || strings.HasSuffix(strings.ToLower(id), ".json") {
		data, err := os.ReadFile(id)
		if err != nil {
			return runtimeTaskView{}, err
		}
		var receipt runtimeadapter.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return runtimeTaskView{}, err
		}
		return runtimeTaskView{Receipt: receipt, Path: id, Updated: receipt.CompletedAt}, nil
	}
	tasks, err := loadRuntimeTaskReceipts(root, via, profile)
	if err != nil {
		return runtimeTaskView{}, err
	}
	for _, task := range tasks {
		if task.Receipt.TaskID == id || filepath.Base(filepath.Dir(task.Path)) == id {
			return task, nil
		}
	}
	return runtimeTaskView{}, fmt.Errorf("runtime task %q was not found", id)
}

func runtimeTaskTerminal(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "completed", "failed", "cancelled", "timeout":
		return true
	default:
		return false
	}
}

func printRuntimeTasks(stdout io.Writer, tasks []runtimeTaskView, format string) error {
	if format == "json" {
		return printJSON(stdout, tasks)
	}
	if format != "text" {
		return fmt.Errorf("runtime tasks format must be text or json")
	}
	if len(tasks) == 0 {
		fmt.Fprintln(stdout, "No persisted C2 task receipts.")
		return nil
	}
	fmt.Fprintln(stdout, "RUNTIME       TASK                     SESSION          STATE       COMPLETE  RECEIPT")
	for _, task := range tasks {
		printRuntimeTaskLine(stdout, task)
	}
	return nil
}

func printRuntimeTaskLine(stdout io.Writer, task runtimeTaskView) {
	fmt.Fprintf(stdout, "%-13s %-24s %-16s %-11s %-9t %s\n", task.Receipt.Runtime, emptyText(task.Receipt.TaskID, "-"), emptyText(task.Receipt.Session, "-"), emptyText(task.Receipt.ExecutionState, task.Receipt.Status), task.Receipt.OutputComplete, task.Path)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
