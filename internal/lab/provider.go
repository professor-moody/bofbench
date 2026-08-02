package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/runlog"
)

const proxmoxGuestReadyTimeout = 5 * time.Minute

func waitForProviderGuestIPv4(ctx context.Context, provider Provider, initial ProviderResource, timeout time.Duration) (ProviderResource, error) {
	if initial.GuestIPv4 != "" || initial.State != "running" || !initial.GuestAgent {
		return initial, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resource := initial
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return resource, fmt.Errorf("guest agent did not report an IPv4 address within %s", timeout)
		case <-ticker.C:
			updated, err := provider.DiscoverGuest(waitCtx)
			if err != nil {
				continue
			}
			resource = updated
			if resource.GuestIPv4 != "" {
				return resource, nil
			}
		}
	}
}

const (
	ProviderReceiptSchema  = "bofbench.provider-receipt"
	ProviderReceiptVersion = 1
)

type ProviderResource struct {
	Node       string `json:"node,omitempty"`
	VMID       int    `json:"vmid,omitempty"`
	Name       string `json:"name,omitempty"`
	State      string `json:"state,omitempty"`
	Template   bool   `json:"template,omitempty"`
	GuestIPv4  string `json:"guest_ipv4,omitempty"`
	GuestAgent bool   `json:"guest_agent,omitempty"`
}

// ProviderReceipt is the durable, secret-free record for provider actions.
// TaskID may contain a Proxmox UPID or an equivalent provider task identity.
type ProviderReceipt struct {
	Schema        string           `json:"schema"`
	SchemaVersion int              `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Provider      string           `json:"provider"`
	Profile       string           `json:"profile"`
	Action        string           `json:"action"`
	Status        string           `json:"status"`
	TaskID        string           `json:"task_id,omitempty"`
	TaskStatus    string           `json:"task_status,omitempty"`
	Snapshot      string           `json:"snapshot,omitempty"`
	Resource      ProviderResource `json:"resource"`
	StartedAt     string           `json:"started_at"`
	CompletedAt   string           `json:"completed_at,omitempty"`
	Error         string           `json:"error,omitempty"`
	EvidencePath  string           `json:"evidence_path"`
}

type ProviderActionOptions struct {
	Snapshot string
	Name     string
	Force    bool
}

type Provider interface {
	Name() string
	Perform(context.Context, string, ProviderActionOptions) (ProviderReceipt, error)
	DiscoverGuest(context.Context) (ProviderResource, error)
	Close()
}

func ResolveProvider(profileName string, profile Profile) (Provider, error) {
	profile = NormalizeProfile(profile)
	switch profile.Provider {
	case "existing":
		return &existingProvider{profileName: profileName, profile: profile}, nil
	case "vagrant":
		return &vagrantProvider{profileName: profileName, profile: profile}, nil
	case "proxmox":
		return NewProxmoxProvider(profileName, profile)
	default:
		return nil, fmt.Errorf("unsupported lab provider %q", profile.Provider)
	}
}

func RunProviderAction(ctx context.Context, profileName string, profile Profile, action string, opts ProviderActionOptions) (ProviderReceipt, error) {
	provider, err := ResolveProvider(profileName, profile)
	if err != nil {
		return ProviderReceipt{}, err
	}
	defer provider.Close()
	receipt, actionErr := provider.Perform(ctx, strings.ToLower(strings.TrimSpace(action)), opts)
	if receipt.Schema == "" {
		receipt = newProviderReceipt(provider.Name(), profileName, action)
	}
	if actionErr != nil {
		receipt.Status = "failed"
		receipt.Error = actionErr.Error()
	}
	if receipt.CompletedAt == "" {
		receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if writeErr := persistProviderReceipt(&receipt); writeErr != nil && actionErr == nil {
		return receipt, writeErr
	}
	return receipt, actionErr
}

func newProviderReceipt(provider, profile, action string) ProviderReceipt {
	runDir, err := runlog.NewDir("provider-" + safeProviderName(action))
	if err != nil {
		// Preserve the action result even if its evidence directory cannot be
		// allocated. persistProviderReceipt will return the concrete error.
		runDir = filepath.Join("runs", time.Now().UTC().Format("20060102-150405")+"-provider-"+safeProviderName(action))
	}
	return ProviderReceipt{
		Schema: ProviderReceiptSchema, SchemaVersion: ProviderReceiptVersion,
		RunID: runlog.ID(runDir), Provider: provider, Profile: profile,
		Action: action, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "provider.json"),
	}
}

func persistProviderReceipt(receipt *ProviderReceipt) error {
	if receipt == nil {
		return fmt.Errorf("provider receipt is nil")
	}
	if strings.TrimSpace(receipt.EvidencePath) == "" {
		return fmt.Errorf("provider receipt evidence path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(receipt.EvidencePath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(receipt.EvidencePath, append(data, '\n'), 0o600)
}

func safeProviderName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "action"
	}
	return b.String()
}

func ProviderReceiptText(receipt ProviderReceipt) string {
	return fmt.Sprintf("Lab provider %s\nprofile   %s\nprovider  %s\naction    %s\nresource  %s/%d %s\ntask      %s %s\nreports   %s\n", strings.ToUpper(receipt.Status), receipt.Profile, receipt.Provider, receipt.Action, receipt.Resource.Node, receipt.Resource.VMID, receipt.Resource.State, receipt.TaskID, receipt.TaskStatus, receipt.EvidencePath)
}

type existingProvider struct {
	profileName string
	profile     Profile
}

func (p *existingProvider) Name() string { return "existing" }
func (p *existingProvider) Close()       {}
func (p *existingProvider) DiscoverGuest(context.Context) (ProviderResource, error) {
	return ProviderResource{Name: p.profileName, State: "external", GuestIPv4: p.profile.Host}, nil
}
func (p *existingProvider) Perform(ctx context.Context, action string, _ ProviderActionOptions) (ProviderReceipt, error) {
	receipt := newProviderReceipt(p.Name(), p.profileName, action)
	resource, _ := p.DiscoverGuest(ctx)
	receipt.Resource = resource
	if action != "status" {
		return receipt, fmt.Errorf("existing provider does not control %s; use the host's lifecycle system", action)
	}
	receipt.Status, receipt.TaskStatus = "complete", "external"
	return receipt, nil
}

type vagrantProvider struct {
	profileName string
	profile     Profile
}

func (p *vagrantProvider) Name() string { return "vagrant" }
func (p *vagrantProvider) Close()       {}
func (p *vagrantProvider) DiscoverGuest(ctx context.Context) (ProviderResource, error) {
	output, err := executeVagrantCommand(ctx, p.profile, "status", "--machine-readable")
	if err != nil {
		return ProviderResource{}, err
	}
	state := "unknown"
	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) >= 4 && parts[2] == "state" {
			state = parts[3]
		}
	}
	return ProviderResource{Name: p.profile.VagrantMachine, State: state, GuestAgent: false}, nil
}
func (p *vagrantProvider) Perform(ctx context.Context, action string, opts ProviderActionOptions) (ProviderReceipt, error) {
	receipt := newProviderReceipt(p.Name(), p.profileName, action)
	var args []string
	switch action {
	case "status":
		resource, err := p.DiscoverGuest(ctx)
		receipt.Resource = resource
		if err != nil {
			return receipt, err
		}
		receipt.Status, receipt.TaskStatus = "complete", resource.State
		return receipt, nil
	case "up":
		args = []string{"up"}
	case "down":
		args = []string{"halt"}
	case "snapshot":
		if strings.TrimSpace(opts.Snapshot) == "" {
			return receipt, fmt.Errorf("snapshot name is required")
		}
		receipt.Snapshot = opts.Snapshot
		args = []string{"snapshot", "save", opts.Snapshot}
	case "restore":
		if strings.TrimSpace(opts.Snapshot) == "" {
			return receipt, fmt.Errorf("snapshot name is required")
		}
		receipt.Snapshot = opts.Snapshot
		args = []string{"snapshot", "restore", opts.Snapshot}
	case "destroy":
		args = []string{"destroy", "-f"}
	default:
		return receipt, fmt.Errorf("vagrant provider does not support action %q", action)
	}
	if _, err := executeVagrantCommand(ctx, p.profile, args...); err != nil {
		return receipt, err
	}
	resource, _ := p.DiscoverGuest(ctx)
	receipt.Resource = resource
	receipt.Status, receipt.TaskStatus = "complete", "completed"
	return receipt, nil
}
