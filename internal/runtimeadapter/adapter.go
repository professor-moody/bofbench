package runtimeadapter

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ReceiptSchema         = "bofbench.runtime-receipt"
	ReceiptSchemaVersion  = 6
	MinimumReceiptVersion = 4
)

type Availability struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type Session struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Host     string `json:"host,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Status   string `json:"status,omitempty"`
	Selected bool   `json:"selected,omitempty"`
}

type Argument struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value,omitempty"`
	Required  bool   `json:"required,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

type Request struct {
	Input      string            `json:"input"`
	Object     string            `json:"object,omitempty"`
	Entrypoint string            `json:"entrypoint"`
	Arguments  []Argument        `json:"arguments,omitempty"`
	Session    string            `json:"session,omitempty"`
	Cleanup    bool              `json:"cleanup,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

type Prepared struct {
	Runtime    string   `json:"runtime"`
	Request    Request  `json:"request"`
	Package    string   `json:"package,omitempty"`
	Command    []string `json:"command,omitempty"`
	PreparedAt string   `json:"prepared_at"`
}

type StateTransition struct {
	State  string `json:"state"`
	At     string `json:"at"`
	Detail string `json:"detail,omitempty"`
}

type OutputChunk struct {
	Number     int    `json:"number"`
	LineCount  int    `json:"line_count,omitempty"`
	Final      bool   `json:"final,omitempty"`
	ReceivedAt string `json:"received_at,omitempty"`
}

type Receipt struct {
	Schema               string            `json:"schema"`
	SchemaVersion        int               `json:"schema_version"`
	Runtime              string            `json:"runtime"`
	RuntimeVersion       string            `json:"runtime_version,omitempty"`
	Status               string            `json:"status"`
	ExecutionState       string            `json:"execution_state,omitempty"`
	OutputComplete       bool              `json:"output_complete"`
	Profile              string            `json:"profile,omitempty"`
	Transport            string            `json:"transport,omitempty"`
	RemoteHost           string            `json:"remote_host,omitempty"`
	RemoteComputer       string            `json:"remote_computer,omitempty"`
	Session              string            `json:"session,omitempty"`
	TaskID               string            `json:"task_id,omitempty"`
	StateTransitions     []StateTransition `json:"state_transitions,omitempty"`
	Object               string            `json:"object,omitempty"`
	ObjectSHA256         string            `json:"object_sha256,omitempty"`
	Entrypoint           string            `json:"entrypoint,omitempty"`
	Arguments            []string          `json:"argument_types,omitempty"`
	SensitiveArguments   []string          `json:"sensitive_arguments,omitempty"`
	Output               []string          `json:"output,omitempty"`
	RedactedOutputFields []string          `json:"redacted_output_fields,omitempty"`
	TimeoutMS            int               `json:"timeout_ms,omitempty"`
	TimedOut             bool              `json:"timed_out,omitempty"`
	ExitState            string            `json:"exit_state,omitempty"`
	ExitCode             *int              `json:"exit_code,omitempty"`
	StartedAt            string            `json:"started_at"`
	CompletedAt          string            `json:"completed_at"`
	DurationMS           int64             `json:"duration_ms"`
	Error                string            `json:"error,omitempty"`
	ReceiptPath          string            `json:"receipt_path,omitempty"`
	LastRefreshAt        string            `json:"last_refresh_at,omitempty"`
	CompletionSource     string            `json:"completion_source,omitempty"`
	OutputChunks         []OutputChunk     `json:"output_chunks,omitempty"`
	FinalChunk           bool              `json:"final_chunk,omitempty"`
	RemoteTaskError      string            `json:"remote_task_error,omitempty"`
	TerminalReason       string            `json:"terminal_reason,omitempty"`
	OutputClassification string            `json:"output_classification,omitempty"`
	WorkerPID            int               `json:"worker_pid,omitempty"`
	RemoteWorkerPID      int               `json:"remote_worker_pid,omitempty"`
	RemoteTaskName       string            `json:"remote_task_name,omitempty"`
	RemoteReceiptPath    string            `json:"remote_receipt_path,omitempty"`
	CancelSupported      bool              `json:"cancel_supported,omitempty"`
	CancelRequestedAt    string            `json:"cancel_requested_at,omitempty"`
	CanceledAt           string            `json:"canceled_at,omitempty"`
	CancelSource         string            `json:"cancel_source,omitempty"`
	LastOutputAt         string            `json:"last_output_at,omitempty"`
	// TransientOutput carries unredacted runtime output only inside the current
	// process so result contracts can verify sensitive payload hashes before
	// persistence. It is deliberately excluded from every serialized receipt.
	TransientOutput []string `json:"-"`
}

func AddTransition(receipt *Receipt, state, detail string, at time.Time) {
	if receipt == nil || strings.TrimSpace(state) == "" {
		return
	}
	receipt.StateTransitions = append(receipt.StateTransitions, StateTransition{State: strings.ToLower(strings.TrimSpace(state)), At: at.UTC().Format(time.RFC3339Nano), Detail: strings.TrimSpace(detail)})
}

// Adapter is the runtime boundary shared by native, lab, Sliver, and Cobalt
// Strike implementations. Metadata/report generation belongs behind this
// boundary; callers only select a runtime and provide a typed request.
type Adapter interface {
	Name() string
	Detect(context.Context) (Availability, error)
	Sessions(context.Context) ([]Session, error)
	ConvertArguments([]Argument) ([]string, error)
	Prepare(context.Context, Request) (Prepared, error)
	Start(context.Context, Prepared) (Receipt, error)
	Execute(context.Context, Prepared) (Receipt, error)
	Refresh(context.Context, Receipt) (Receipt, error)
	Cancel(context.Context, Receipt) (Receipt, error)
	Cleanup(context.Context, Prepared) (Receipt, error)
}

type Hooks struct {
	Detect           func(context.Context) (Availability, error)
	Sessions         func(context.Context) ([]Session, error)
	ConvertArguments func([]Argument) ([]string, error)
	Prepare          func(context.Context, Request) (Prepared, error)
	Start            func(context.Context, Prepared) (Receipt, error)
	Execute          func(context.Context, Prepared) (Receipt, error)
	Refresh          func(context.Context, Receipt) (Receipt, error)
	Cancel           func(context.Context, Receipt) (Receipt, error)
	Cleanup          func(context.Context, Prepared) (Receipt, error)
}

type Functional struct {
	name  string
	hooks Hooks
}

func New(name string, hooks Hooks) (*Functional, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil, fmt.Errorf("runtime adapter name is required")
	}
	return &Functional{name: name, hooks: hooks}, nil
}

func (adapter *Functional) Name() string { return adapter.name }

func (adapter *Functional) Detect(ctx context.Context) (Availability, error) {
	if adapter.hooks.Detect == nil {
		return Availability{Detail: "availability detection is not implemented"}, nil
	}
	return adapter.hooks.Detect(ctx)
}

func (adapter *Functional) Sessions(ctx context.Context) ([]Session, error) {
	if adapter.hooks.Sessions == nil {
		return nil, nil
	}
	return adapter.hooks.Sessions(ctx)
}

func (adapter *Functional) ConvertArguments(arguments []Argument) ([]string, error) {
	if adapter.hooks.ConvertArguments == nil {
		values := make([]string, 0, len(arguments))
		for _, argument := range arguments {
			if argument.Required && argument.Value == "" {
				return nil, fmt.Errorf("missing required runtime argument %q", argument.Name)
			}
			if argument.Value != "" {
				values = append(values, argument.Value)
			}
		}
		return values, nil
	}
	return adapter.hooks.ConvertArguments(arguments)
}

func (adapter *Functional) Prepare(ctx context.Context, request Request) (Prepared, error) {
	if adapter.hooks.Prepare != nil {
		return adapter.hooks.Prepare(ctx, request)
	}
	return Prepared{Runtime: adapter.name, Request: request, PreparedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func (adapter *Functional) Execute(ctx context.Context, prepared Prepared) (Receipt, error) {
	if adapter.hooks.Execute == nil {
		return Receipt{}, fmt.Errorf("runtime adapter %s does not implement execution", adapter.name)
	}
	return adapter.hooks.Execute(ctx, prepared)
}

func (adapter *Functional) Start(ctx context.Context, prepared Prepared) (Receipt, error) {
	if adapter.hooks.Start != nil {
		return adapter.hooks.Start(ctx, prepared)
	}
	return adapter.Execute(ctx, prepared)
}

func (adapter *Functional) Refresh(ctx context.Context, receipt Receipt) (Receipt, error) {
	if adapter.hooks.Refresh == nil {
		return receipt, nil
	}
	return adapter.hooks.Refresh(ctx, receipt)
}

func (adapter *Functional) Cancel(ctx context.Context, receipt Receipt) (Receipt, error) {
	if adapter.hooks.Cancel == nil {
		receipt.CancelSupported = false
		return receipt, fmt.Errorf("runtime adapter %s does not support task cancellation", adapter.name)
	}
	return adapter.hooks.Cancel(ctx, receipt)
}

func (adapter *Functional) Cleanup(ctx context.Context, prepared Prepared) (Receipt, error) {
	if adapter.hooks.Cleanup == nil {
		return Receipt{}, fmt.Errorf("runtime adapter %s does not implement cleanup", adapter.name)
	}
	return adapter.hooks.Cleanup(ctx, prepared)
}

type Registry struct {
	items map[string]Adapter
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{items: map[string]Adapter{}}
	for _, adapter := range adapters {
		if adapter == nil || strings.TrimSpace(adapter.Name()) == "" {
			return nil, fmt.Errorf("runtime adapter and name are required")
		}
		name := strings.ToLower(adapter.Name())
		if _, exists := registry.items[name]; exists {
			return nil, fmt.Errorf("duplicate runtime adapter %q", name)
		}
		registry.items[name] = adapter
	}
	return registry, nil
}

func (registry *Registry) Resolve(name string) (Adapter, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = "native"
	}
	if adapter, ok := registry.items[name]; ok {
		return adapter, nil
	}
	return nil, fmt.Errorf("unknown runtime adapter %q; choose %s", name, strings.Join(registry.Names(), ", "))
}

func (registry *Registry) Names() []string {
	names := make([]string, 0, len(registry.items))
	for name := range registry.items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func NormalizeReceipt(receipt Receipt) (Receipt, error) {
	if receipt.Schema != ReceiptSchema || receipt.SchemaVersion < MinimumReceiptVersion || receipt.SchemaVersion > ReceiptSchemaVersion {
		return receipt, fmt.Errorf("unsupported runtime receipt schema %q version %d", receipt.Schema, receipt.SchemaVersion)
	}
	if receipt.SchemaVersion < ReceiptSchemaVersion {
		receipt.SchemaVersion = ReceiptSchemaVersion
	}
	if receipt.OutputClassification == "" {
		if receipt.OutputComplete {
			receipt.OutputClassification = "complete"
		} else {
			receipt.OutputClassification = "partial"
		}
	}
	if receipt.FinalChunk && len(receipt.OutputChunks) > 0 {
		receipt.OutputChunks[len(receipt.OutputChunks)-1].Final = true
	}
	return receipt, nil
}
