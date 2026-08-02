package operation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	packsvc "github.com/professor-moody/bofbench/internal/pack"
	"github.com/professor-moody/bofbench/internal/runtimeadapter"
)

const (
	Schema                = "bofbench.operation"
	SchemaVersion         = 11
	MinimumSchemaVersion  = 1
	ReceiptSchema         = "bofbench.operation-receipt"
	ReceiptSchemaVersion  = 11
	MinimumReceiptVersion = 1
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type Input struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	Required      bool   `json:"required,omitempty"`
	Default       string `json:"default,omitempty"`
	Sensitive     bool   `json:"sensitive,omitempty"`
	TopologyValue string `json:"topology_value,omitempty"`
}

type Capture struct {
	Tag     string `json:"tag,omitempty"`
	Field   string `json:"field,omitempty"`
	Capture string `json:"capture,omitempty"`
}

type Cleanup struct {
	Pack      string            `json:"pack"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// Outcome is an ordered result route. The first expectation that matches a
// completed runtime result selects the next step. Runtime failures and
// incomplete output never reach outcome evaluation.
type Outcome struct {
	ID     string                   `json:"id"`
	Expect packsvc.ProofExpectation `json:"expect"`
	Next   string                   `json:"next"`
}

// RetryContract names one complete terminal result that the operator has
// explicitly declared transient. Runtime failures, partial output, and
// incomplete tasks never reach retry-contract evaluation.
type RetryContract struct {
	ID     string                   `json:"id"`
	Expect packsvc.ProofExpectation `json:"expect"`
}

// RetryPolicy is intentionally bounded and deterministic. MaxAttempts counts
// the first invocation, so a value of three permits at most two retries.
type RetryPolicy struct {
	MaxAttempts int             `json:"max_attempts"`
	DelayMS     int             `json:"delay_ms"`
	Backoff     string          `json:"backoff"`
	MaxDelayMS  int             `json:"max_delay_ms,omitempty"`
	When        []RetryContract `json:"when"`
}

type ParallelBranch struct {
	ID        string                    `json:"id"`
	Pack      string                    `json:"pack,omitempty"`
	Operation string                    `json:"operation,omitempty"`
	Arguments map[string]string         `json:"arguments,omitempty"`
	Captures  map[string]Capture        `json:"captures,omitempty"`
	Cleanup   *Cleanup                  `json:"cleanup,omitempty"`
	Expect    *packsvc.ProofExpectation `json:"expect,omitempty"`
}

type Parallel struct {
	Join     string            `json:"join"`
	Branches []ParallelBranch  `json:"branches"`
	Exports  map[string]string `json:"exports,omitempty"`
}

// FanOut expands one pack or child-operation invocation over an explicit,
// bounded operator-supplied list. Expansion happens before any branch starts,
// producing the same atomic preparation and reverse cleanup semantics as an
// explicit parallel group.
type FanOut struct {
	Source        string   `json:"source"`
	Separator     string   `json:"separator,omitempty"`
	MaxItems      int      `json:"max_items"`
	ResolvedItems []string `json:"-"`
}

type Step struct {
	ID             string                    `json:"id"`
	Pack           string                    `json:"pack,omitempty"`
	Operation      string                    `json:"operation,omitempty"`
	Mode           string                    `json:"mode,omitempty"`
	DependsOn      []string                  `json:"depends_on,omitempty"`
	DependsOnReady []string                  `json:"depends_on_ready,omitempty"`
	Arguments      map[string]string         `json:"arguments,omitempty"`
	Captures       map[string]Capture        `json:"captures,omitempty"`
	ReadyCaptures  map[string]Capture        `json:"ready_captures,omitempty"`
	Cleanup        *Cleanup                  `json:"cleanup,omitempty"`
	Expect         *packsvc.ProofExpectation `json:"expect,omitempty"`
	Ready          *packsvc.ProofExpectation `json:"ready,omitempty"`
	TimeoutMS      int                       `json:"timeout_ms,omitempty"`
	Retry          *RetryPolicy              `json:"retry,omitempty"`
	Outcomes       []Outcome                 `json:"outcomes,omitempty"`
	Parallel       *Parallel                 `json:"parallel,omitempty"`
	FanOut         *FanOut                   `json:"fan_out,omitempty"`
}

type ProofCase struct {
	ID                 string                       `json:"id"`
	Via                []string                     `json:"via"`
	Architectures      []string                     `json:"architectures,omitempty"`
	Roles              []string                     `json:"roles,omitempty"`
	Inputs             map[string]string            `json:"inputs,omitempty"`
	ExpectCaptures     map[string]string            `json:"expect_captures,omitempty"`
	Cleanup            bool                         `json:"cleanup,omitempty"`
	StateChecks        []packsvc.ProofStateCheck    `json:"state_checks,omitempty"`
	ExpectPath         []string                     `json:"expect_path,omitempty"`
	ExpectExpandedPath []string                     `json:"expect_expanded_path,omitempty"`
	ExpectParallel     map[string]map[string]string `json:"expect_parallel,omitempty"`
	ExpectWaves        [][]string                   `json:"expect_waves,omitempty"`
	ExpectSteps        map[string]string            `json:"expect_steps,omitempty"`
	ExpectReadySteps   []string                     `json:"expect_ready_steps,omitempty"`
	ExpectTransitions  map[string][]string          `json:"expect_transitions,omitempty"`
	ExpectAttempts     map[string]int               `json:"expect_attempts,omitempty"`
	ExpectRetryReasons map[string][]string          `json:"expect_retry_reasons,omitempty"`
	ExpectFanOut       map[string]int               `json:"expect_fan_out,omitempty"`
}

type Document struct {
	Schema        string      `json:"schema"`
	SchemaVersion int         `json:"schema_version"`
	ID            string      `json:"id"`
	Version       string      `json:"version"`
	Title         string      `json:"title"`
	Summary       string      `json:"summary"`
	Tier          string      `json:"tier"`
	Execution     string      `json:"execution,omitempty"`
	Inputs        []Input     `json:"inputs,omitempty"`
	Roles         []string    `json:"roles,omitempty"`
	Steps         []Step      `json:"steps"`
	ProofCases    []ProofCase `json:"proof_cases,omitempty"`
}

type Resolved struct {
	Document    Document `json:"operation"`
	Catalog     string   `json:"catalog"`
	CatalogRoot string   `json:"catalog_root,omitempty"`
	Manifest    string   `json:"manifest,omitempty"`
	Qualified   string   `json:"qualified"`
	SHA256      string   `json:"sha256"`
}

type LoadOptions struct {
	Project       string
	ExtraCatalogs []string
	PackRegistry  *packsvc.Registry
}

type Registry struct {
	items        map[string]Resolved
	unqualified  map[string][]string
	packRegistry *packsvc.Registry
}

type StepReceipt struct {
	ID                 string                  `json:"id"`
	Pack               string                  `json:"pack"`
	PackSHA256         string                  `json:"pack_sha256"`
	CleanupPack        string                  `json:"cleanup_pack,omitempty"`
	CleanupSHA256      string                  `json:"cleanup_pack_sha256,omitempty"`
	State              string                  `json:"state"`
	ObjectSHA256       string                  `json:"object_sha256,omitempty"`
	OutputComplete     bool                    `json:"output_complete"`
	Runtime            runtimeadapter.Receipt  `json:"runtime_receipt,omitempty"`
	Captures           map[string]string       `json:"captures,omitempty"`
	Error              string                  `json:"error,omitempty"`
	CleanupState       string                  `json:"cleanup_state,omitempty"`
	CleanupRuntime     *runtimeadapter.Receipt `json:"cleanup_runtime_receipt,omitempty"`
	ContractState      string                  `json:"contract_state,omitempty"`
	MatchedTag         string                  `json:"matched_tag,omitempty"`
	MatchedFields      []string                `json:"matched_fields,omitempty"`
	PayloadVerified    bool                    `json:"payload_verified,omitempty"`
	MatchedOutcome     string                  `json:"matched_outcome,omitempty"`
	NextStep           string                  `json:"next_step,omitempty"`
	Operation          string                  `json:"operation,omitempty"`
	OperationSHA256    string                  `json:"operation_sha256,omitempty"`
	ChildReceipt       string                  `json:"child_receipt,omitempty"`
	ChildCleanupState  string                  `json:"child_cleanup_state,omitempty"`
	StartedAt          string                  `json:"started_at,omitempty"`
	CompletedAt        string                  `json:"completed_at,omitempty"`
	ReadyAt            string                  `json:"ready_at,omitempty"`
	DependsOn          []string                `json:"depends_on,omitempty"`
	DependsOnReady     []string                `json:"depends_on_ready,omitempty"`
	BlockedBy          []string                `json:"blocked_by,omitempty"`
	Mode               string                  `json:"mode,omitempty"`
	ReadyState         string                  `json:"ready_state,omitempty"`
	ReadyContractState string                  `json:"ready_contract_state,omitempty"`
	ReadyMatchedTag    string                  `json:"ready_matched_tag,omitempty"`
	ReadyMatchedFields []string                `json:"ready_matched_fields,omitempty"`
	ReadyCaptures      map[string]string       `json:"ready_captures,omitempty"`
	LastProgressAt     string                  `json:"last_progress_at,omitempty"`
	CancellationState  string                  `json:"cancellation_state,omitempty"`
	Attempt            int                     `json:"attempt,omitempty"`
	MaxAttempts        int                     `json:"max_attempts,omitempty"`
	RetryState         string                  `json:"retry_state,omitempty"`
	RetryReason        string                  `json:"retry_reason,omitempty"`
	NextAttemptAt      string                  `json:"next_attempt_at,omitempty"`
	Attempts           []AttemptReceipt        `json:"attempts,omitempty"`
	Parallel           *ParallelReceipt        `json:"parallel,omitempty"`
	FanOut             *FanOutReceipt          `json:"fan_out,omitempty"`
}

type FanOutBranchReceipt struct {
	ID           string `json:"id"`
	Item         string `json:"item"`
	State        string `json:"state"`
	CleanupState string `json:"cleanup_state,omitempty"`
	Error        string `json:"error,omitempty"`
}

type FanOutReceipt struct {
	Source              string                `json:"source"`
	Items               []string              `json:"items"`
	MaxItems            int                   `json:"max_items"`
	State               string                `json:"state"`
	ObservedConcurrency int                   `json:"observed_concurrency,omitempty"`
	Branches            []FanOutBranchReceipt `json:"branches"`
}

// AttemptReceipt preserves the exact runtime result that caused success,
// failure, or a declared retry. The parent StepReceipt continues to mirror the
// latest attempt for compatibility with operation-receipt versions 1-7.
type AttemptReceipt struct {
	Number         int                     `json:"number"`
	State          string                  `json:"state"`
	ObjectSHA256   string                  `json:"object_sha256,omitempty"`
	OutputComplete bool                    `json:"output_complete"`
	Runtime        runtimeadapter.Receipt  `json:"runtime_receipt,omitempty"`
	ContractState  string                  `json:"contract_state,omitempty"`
	MatchedTag     string                  `json:"matched_tag,omitempty"`
	MatchedFields  []string                `json:"matched_fields,omitempty"`
	Captures       map[string]string       `json:"captures,omitempty"`
	RetryReason    string                  `json:"retry_reason,omitempty"`
	DelayMS        int                     `json:"delay_ms,omitempty"`
	NextEligibleAt string                  `json:"next_eligible_at,omitempty"`
	StartedAt      string                  `json:"started_at,omitempty"`
	CompletedAt    string                  `json:"completed_at,omitempty"`
	CleanupState   string                  `json:"cleanup_state,omitempty"`
	CleanupRuntime *runtimeadapter.Receipt `json:"cleanup_runtime_receipt,omitempty"`
}

type ExecutionWave struct {
	Index       int      `json:"index"`
	Steps       []string `json:"steps"`
	State       string   `json:"state"`
	ReadyAt     string   `json:"ready_at,omitempty"`
	StartedAt   string   `json:"started_at,omitempty"`
	CompletedAt string   `json:"completed_at,omitempty"`
}

type ParallelReceipt struct {
	Join                string            `json:"join"`
	State               string            `json:"state"`
	Branches            []StepReceipt     `json:"branches"`
	Exports             map[string]string `json:"exports,omitempty"`
	ObservedConcurrency int               `json:"observed_concurrency,omitempty"`
	StartedAt           string            `json:"started_at,omitempty"`
	CompletedAt         string            `json:"completed_at,omitempty"`
}

type Receipt struct {
	Schema            string            `json:"schema"`
	SchemaVersion     int               `json:"schema_version"`
	Operation         string            `json:"operation"`
	OperationSHA256   string            `json:"operation_sha256"`
	Status            string            `json:"status"`
	Runtime           string            `json:"runtime"`
	Lab               string            `json:"lab,omitempty"`
	Topology          string            `json:"topology,omitempty"`
	Architecture      string            `json:"architecture"`
	Compiler          string            `json:"compiler"`
	Inputs            map[string]string `json:"inputs,omitempty"`
	RedactedInputs    []string          `json:"redacted_inputs,omitempty"`
	Captures          map[string]string `json:"captures,omitempty"`
	ActualPath        []string          `json:"actual_path,omitempty"`
	ExpandedPath      []string          `json:"expanded_path,omitempty"`
	SkippedSteps      []string          `json:"skipped_steps,omitempty"`
	DependencySHA256  map[string]string `json:"dependency_sha256,omitempty"`
	Steps             []StepReceipt     `json:"steps"`
	CleanupState      string            `json:"cleanup_state,omitempty"`
	StartedAt         string            `json:"started_at"`
	UpdatedAt         string            `json:"updated_at"`
	CompletedAt       string            `json:"completed_at,omitempty"`
	Path              string            `json:"path"`
	Error             string            `json:"error,omitempty"`
	Parallelism       int               `json:"parallelism,omitempty"`
	MaxConcurrency    int               `json:"max_observed_concurrency,omitempty"`
	Execution         string            `json:"execution,omitempty"`
	TopologicalOrder  []string          `json:"topological_order,omitempty"`
	BlockedSteps      []string          `json:"blocked_steps,omitempty"`
	ExecutionWaves    []ExecutionWave   `json:"execution_waves,omitempty"`
	ControllerPID     int               `json:"controller_pid,omitempty"`
	ControlPath       string            `json:"control_path,omitempty"`
	CancelRequestedAt string            `json:"cancel_requested_at,omitempty"`
	CanceledAt        string            `json:"canceled_at,omitempty"`
	CancellationState string            `json:"cancellation_state,omitempty"`
	ActiveSteps       []string          `json:"active_steps,omitempty"`
}

func Load(opts LoadOptions) (*Registry, error) {
	registry := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}, packRegistry: opts.PackRegistry}
	if registry.packRegistry == nil {
		packs, err := packsvc.Load(packsvc.LoadOptions{Project: opts.Project, ExtraCatalogs: opts.ExtraCatalogs})
		if err != nil {
			return nil, err
		}
		registry.packRegistry = packs
	}
	for _, item := range builtins() {
		if err := registry.add(item); err != nil {
			return nil, err
		}
	}
	loaded := map[string]bool{}
	loadRoot := func(root, catalog string) error {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		absolute = filepath.Clean(absolute)
		if loaded[absolute] {
			return nil
		}
		loaded[absolute] = true
		return registry.loadCatalog(absolute, catalog)
	}
	if opts.Project != "" {
		root := filepath.Join(projectDir(opts.Project), ".bofbench", "operations")
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			if err := loadRoot(root, "project"); err != nil {
				return nil, err
			}
		}
	}
	config, err := packsvc.LoadCatalogConfig()
	if err != nil {
		return nil, err
	}
	for _, catalog := range config.Catalogs {
		if err := loadRoot(catalog.Path, catalog.Name); err != nil {
			return nil, fmt.Errorf("catalog %s operations: %w", catalog.Name, err)
		}
	}
	for _, selector := range opts.ExtraCatalogs {
		if selector == "builtin" {
			continue
		}
		root, name := selector, strings.ToLower(filepath.Base(filepath.Clean(selector)))
		for _, catalog := range config.Catalogs {
			if catalog.Name == selector {
				root, name = catalog.Path, catalog.Name
				break
			}
		}
		if err := loadRoot(root, name); err != nil {
			return nil, err
		}
	}
	if err := registry.validatePackReferences(); err != nil {
		return nil, err
	}
	if err := registry.validateOperationReferences(); err != nil {
		return nil, err
	}
	return registry, nil
}

func (r *Registry) List() []Resolved {
	out := make([]Resolved, 0, len(r.items))
	for _, item := range r.items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Qualified < out[j].Qualified })
	return out
}

func (r *Registry) Search(query string) []Resolved {
	terms := strings.Fields(strings.ToLower(query))
	if len(terms) == 0 {
		return r.List()
	}
	var out []Resolved
	for _, item := range r.List() {
		haystack := strings.ToLower(item.Qualified + " " + item.Document.Title + " " + item.Document.Summary)
		matched := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, item)
		}
	}
	return out
}

func (r *Registry) Resolve(name string) (Resolved, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if item, ok := r.items[name]; ok {
		return item, nil
	}
	// "internal/<id>" is a stable operator alias for a uniquely resolved
	// private operation even when the configured catalog has a local name such
	// as "bofbench-packs-internal". Real catalog qualification still resolves
	// collisions explicitly.
	if id, ok := strings.CutPrefix(name, "internal/"); ok {
		var matches []Resolved
		for _, qualified := range r.unqualified[id] {
			if item := r.items[qualified]; item.Document.Tier == "internal" {
				matches = append(matches, item)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
	}
	qualified := r.unqualified[name]
	if len(qualified) == 1 {
		return r.items[qualified[0]], nil
	}
	if len(qualified) > 1 {
		return Resolved{}, fmt.Errorf("operation %q exists in multiple catalogs; choose %s", name, strings.Join(qualified, ", "))
	}
	return Resolved{}, fmt.Errorf("unknown operation %q; use 'bofbench operation search %s'", name, name)
}

func (r *Registry) PackRegistry() *packsvc.Registry { return r.packRegistry }

func ValidateFile(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	var document Document
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validate(document); err != nil {
		return Document{}, err
	}
	if document.Execution == "" {
		document.Execution = "linear"
	}
	return document, nil
}

func (r *Registry) loadCatalog(root, catalog string) error {
	var manifests []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".") && path != root {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == "operation.json" && strings.Contains(filepath.ToSlash(path), "/operations/") {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Catalogs are allowed to contain packs without operations.
	sort.Strings(manifests)
	for _, manifest := range manifests {
		document, err := ValidateFile(manifest)
		if err != nil {
			return err
		}
		data, _ := os.ReadFile(manifest)
		sum := sha256.Sum256(data)
		item := Resolved{Document: document, Catalog: catalog, CatalogRoot: root, Manifest: manifest, Qualified: catalog + "/" + document.ID, SHA256: hex.EncodeToString(sum[:])}
		if err := r.add(item); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) add(item Resolved) error {
	if _, exists := r.items[item.Qualified]; exists {
		return fmt.Errorf("duplicate operation %s", item.Qualified)
	}
	r.items[item.Qualified] = item
	r.unqualified[item.Document.ID] = append(r.unqualified[item.Document.ID], item.Qualified)
	sort.Strings(r.unqualified[item.Document.ID])
	return nil
}

func (r *Registry) validatePackReferences() error {
	for _, item := range r.List() {
		if err := ValidatePackReferences(item.Document, r.packRegistry); err != nil {
			return fmt.Errorf("operation %s: %w", item.Qualified, err)
		}
	}
	return nil
}

// ValidateDocumentReferences checks both pack and child-operation references
// for a document that is not yet installed in the registry.
func (r *Registry) ValidateDocumentReferences(document Document) error {
	if err := ValidatePackReferences(document, r.packRegistry); err != nil {
		return err
	}
	for _, step := range document.Steps {
		if step.Parallel != nil {
			for _, branch := range step.Parallel.Branches {
				if branch.Operation == "" {
					continue
				}
				if err := r.validateChildInvocation(step.ID+" branch "+branch.ID, branch.Operation, branch.Arguments, branch.Captures); err != nil {
					return err
				}
			}
			continue
		}
		if step.Operation == "" {
			continue
		}
		if err := r.validateChildInvocation("step "+step.ID, step.Operation, step.Arguments, step.Captures); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) validateChildInvocation(label, operationName string, arguments map[string]string, captures map[string]Capture) error {
	child, err := r.Resolve(operationName)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err := validateStepArguments(arguments, operationArguments(child.Document.Inputs)); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	available := operationCaptureNames(child.Document)
	for name, capture := range captures {
		if capture.Capture == "" || !available[capture.Capture] {
			return fmt.Errorf("%s export %s selects unknown child capture %q", label, name, capture.Capture)
		}
	}
	return nil
}

func (r *Registry) validateOperationReferences() error {
	for _, item := range r.List() {
		if err := r.ValidateDocumentReferences(item.Document); err != nil {
			return fmt.Errorf("operation %s: %w", item.Qualified, err)
		}
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var walk func(Resolved, []string) error
	walk = func(item Resolved, path []string) error {
		if visiting[item.Qualified] {
			return fmt.Errorf("operation call cycle: %s", strings.Join(append(path, item.Qualified), " -> "))
		}
		if visited[item.Qualified] {
			return nil
		}
		visiting[item.Qualified] = true
		for _, step := range item.Document.Steps {
			if step.Parallel != nil {
				for _, branch := range step.Parallel.Branches {
					if branch.Operation == "" {
						continue
					}
					child, err := r.Resolve(branch.Operation)
					if err != nil {
						return err
					}
					if err := walk(child, append(path, item.Qualified)); err != nil {
						return err
					}
				}
				continue
			}
			if step.Operation == "" {
				continue
			}
			child, err := r.Resolve(step.Operation)
			if err != nil {
				return err
			}
			if err := walk(child, append(path, item.Qualified)); err != nil {
				return err
			}
		}
		visiting[item.Qualified] = false
		visited[item.Qualified] = true
		return nil
	}
	for _, item := range r.List() {
		if err := walk(item, nil); err != nil {
			return err
		}
	}
	return nil
}

func operationArguments(inputs []Input) []packsvc.Argument {
	result := make([]packsvc.Argument, 0, len(inputs))
	for _, input := range inputs {
		result = append(result, packsvc.Argument{Name: input.Name, Type: input.Type, Required: input.Required, Default: input.Default, Sensitive: input.Sensitive})
	}
	return result
}

func operationCaptureNames(document Document) map[string]bool {
	result := map[string]bool{}
	for _, step := range document.Steps {
		if step.Parallel != nil {
			for name := range step.Parallel.Exports {
				result[name] = true
			}
			continue
		}
		for name := range step.Captures {
			result[name] = true
		}
	}
	return result
}

// ValidatePackReferences checks a parsed operation against a resolved pack
// registry. It is used both during catalog loading and when validating an
// operation file before it is installed.
func ValidatePackReferences(document Document, packs *packsvc.Registry) error {
	for _, step := range document.Steps {
		if step.Parallel != nil {
			for _, branch := range step.Parallel.Branches {
				if branch.Operation != "" {
					continue
				}
				if err := validatePackInvocation(step.ID+" branch "+branch.ID, branch.Pack, branch.Arguments, branch.Captures, branch.Cleanup, packs); err != nil {
					return err
				}
			}
			continue
		}
		if step.Operation != "" {
			continue
		}
		if err := validatePackInvocation("step "+step.ID, step.Pack, step.Arguments, step.Captures, step.Cleanup, packs); err != nil {
			return err
		}
	}
	return nil
}

func validatePackInvocation(label, packName string, arguments map[string]string, captures map[string]Capture, cleanupSpec *Cleanup, packs *packsvc.Registry) error {
	resolved, err := packs.Resolve(packName)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err := validateStepArguments(arguments, resolved.Document.Arguments); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	for name, capture := range captures {
		if contains(resolved.Document.SensitiveOutputFields, capture.Field) {
			return fmt.Errorf("%s capture %s selects sensitive output field %s; sensitive captures cannot be persisted", label, name, capture.Field)
		}
	}
	if cleanupSpec != nil {
		cleanup, err := packs.Resolve(cleanupSpec.Pack)
		if err != nil {
			return fmt.Errorf("%s cleanup: %w", label, err)
		}
		if err := validateStepArguments(cleanupSpec.Arguments, cleanup.Document.Arguments); err != nil {
			return fmt.Errorf("%s cleanup: %w", label, err)
		}
	}
	return nil
}

func validateStepArguments(values map[string]string, definitions []packsvc.Argument) error {
	known := map[string]packsvc.Argument{}
	for _, definition := range definitions {
		known[definition.Name] = definition
	}
	for name := range values {
		if known[name].Name == "" {
			return fmt.Errorf("unknown pack argument %q", name)
		}
	}
	for _, definition := range definitions {
		if definition.Required && definition.Default == "" {
			if _, ok := values[definition.Name]; !ok {
				return fmt.Errorf("missing required pack argument %q", definition.Name)
			}
		}
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validate(document Document) error {
	if document.Schema != Schema || document.SchemaVersion < MinimumSchemaVersion || document.SchemaVersion > SchemaVersion {
		return fmt.Errorf("unsupported operation schema %q version %d", document.Schema, document.SchemaVersion)
	}
	if !idPattern.MatchString(document.ID) {
		return fmt.Errorf("invalid operation id %q", document.ID)
	}
	if document.Version == "" || document.Title == "" || document.Summary == "" {
		return fmt.Errorf("operation version, title, and summary are required")
	}
	if document.Tier != "public" && document.Tier != "internal" {
		return fmt.Errorf("operation tier must be public or internal")
	}
	if document.SchemaVersion < 6 && document.Execution != "" {
		return fmt.Errorf("operation execution mode requires schema version 6")
	}
	if document.SchemaVersion < 9 && documentUsesTemplates(document) {
		return fmt.Errorf("operation string templates require schema version 9")
	}
	if document.Execution == "" {
		document.Execution = "linear"
	}
	if document.Execution != "linear" && document.Execution != "dag" {
		return fmt.Errorf("operation execution must be linear or dag")
	}
	seenRoles := map[string]bool{}
	for _, role := range document.Roles {
		if role != "execution" && role != "target" && role != "domain_controller" {
			return fmt.Errorf("unsupported topology role %q", role)
		}
		if seenRoles[role] {
			return fmt.Errorf("duplicate topology role %q", role)
		}
		seenRoles[role] = true
	}
	if len(document.Steps) == 0 {
		return fmt.Errorf("operation must declare at least one step")
	}
	inputs, steps, captures := map[string]Input{}, map[string]bool{}, map[string]string{}
	stepIndexes := map[string]int{}
	for index, step := range document.Steps {
		if !idPattern.MatchString(step.ID) {
			return fmt.Errorf("each step needs a valid id")
		}
		if document.SchemaVersion < 4 && step.Pack == "" {
			return fmt.Errorf("each step needs a valid id and pack")
		}
		if document.SchemaVersion < 4 && step.Operation != "" {
			return fmt.Errorf("step %s operation references require schema version 4", step.ID)
		}
		if document.SchemaVersion == 4 && (step.Pack == "") == (step.Operation == "") {
			return fmt.Errorf("step %s must declare exactly one of pack or operation", step.ID)
		}
		if document.SchemaVersion < 5 && step.Parallel != nil {
			return fmt.Errorf("step %s parallel execution requires schema version 5", step.ID)
		}
		if document.SchemaVersion < 6 && len(step.DependsOn) > 0 {
			return fmt.Errorf("step %s dependencies require schema version 6", step.ID)
		}
		if document.SchemaVersion < 7 && (step.Mode != "" || step.Ready != nil || len(step.ReadyCaptures) > 0 || len(step.DependsOnReady) > 0 || step.TimeoutMS != 0) {
			return fmt.Errorf("step %s background readiness requires schema version 7", step.ID)
		}
		if document.SchemaVersion < 8 && step.Retry != nil {
			return fmt.Errorf("step %s retry requires schema version 8", step.ID)
		}
		if document.SchemaVersion < 10 && step.FanOut != nil {
			return fmt.Errorf("step %s fan_out requires schema version 10", step.ID)
		}
		if step.FanOut != nil {
			if document.Execution != "linear" {
				return fmt.Errorf("step %s fan_out must be invoked by a linear operation; DAGs may compose that child operation", step.ID)
			}
			if step.Parallel != nil || (step.Pack == "") == (step.Operation == "") {
				return fmt.Errorf("step %s fan_out requires exactly one pack or child operation target", step.ID)
			}
			if step.FanOut.MaxItems < 1 || step.FanOut.MaxItems > 64 {
				return fmt.Errorf("step %s fan_out max_items must be between 1 and 64", step.ID)
			}
			separator := step.FanOut.Separator
			if separator == "" {
				separator = ","
			}
			if separator != "," && separator != ";" && separator != "\\n" {
				return fmt.Errorf("step %s fan_out separator must be comma, semicolon, or \\n", step.ID)
			}
			inputSource := strings.HasPrefix(step.FanOut.Source, "$input.")
			topologySource := document.SchemaVersion >= 11 && strings.HasPrefix(step.FanOut.Source, "$topology.target_sets.")
			if (!inputSource && !topologySource) || strings.Contains(step.FanOut.Source, "${") {
				return fmt.Errorf("step %s fan_out source must be an exact $input reference or schema-v11 topology target-set reference", step.ID)
			}
			if index != len(document.Steps)-1 || len(step.Outcomes) > 0 {
				return fmt.Errorf("step %s fan_out must be the terminal linear step and cannot declare outcomes", step.ID)
			}
		}
		if document.Execution != "dag" && step.Retry != nil {
			return fmt.Errorf("step %s retry is available only in dag execution", step.ID)
		}
		if document.Execution != "dag" && len(step.DependsOn) > 0 {
			return fmt.Errorf("step %s depends_on is available only in dag execution", step.ID)
		}
		if document.Execution != "dag" && len(step.DependsOnReady) > 0 {
			return fmt.Errorf("step %s depends_on_ready is available only in dag execution", step.ID)
		}
		if document.SchemaVersion >= 5 && stepTargetCount(step) != 1 {
			return fmt.Errorf("step %s must declare exactly one of pack, operation, or parallel", step.ID)
		}
		if step.Operation != "" && step.Cleanup != nil {
			return fmt.Errorf("step %s child operation owns its cleanup; cleanup cannot be declared on the parent step", step.ID)
		}
		if step.Parallel != nil && (step.Cleanup != nil || len(step.Arguments) > 0 || len(step.Captures) > 0 || step.Expect != nil || len(step.Outcomes) > 0) {
			return fmt.Errorf("step %s parallel groups own branch arguments, contracts, captures, and cleanup", step.ID)
		}
		if _, exists := stepIndexes[step.ID]; exists {
			return fmt.Errorf("duplicate step %q", step.ID)
		}
		stepIndexes[step.ID] = index
	}
	for _, input := range document.Inputs {
		if !idPattern.MatchString(input.Name) {
			return fmt.Errorf("invalid input name %q", input.Name)
		}
		if _, exists := inputs[input.Name]; exists {
			return fmt.Errorf("duplicate input %q", input.Name)
		}
		if !validType(input.Type) {
			return fmt.Errorf("input %s has unsupported type %q", input.Name, input.Type)
		}
		if input.TopologyValue != "" {
			parts := strings.Split(input.TopologyValue, ".")
			if len(parts) < 2 || (parts[0] != "execution" && parts[0] != "target" && parts[0] != "domain_controller" && parts[0] != "domain" && parts[0] != "target_sets") {
				return fmt.Errorf("input %s has invalid topology value %q", input.Name, input.TopologyValue)
			}
		}
		inputs[input.Name] = input
	}
	if document.Execution == "dag" {
		var err error
		captures, err = validateDAG(document, inputs, stepIndexes)
		if err != nil {
			return err
		}
	} else {
		for stepIndex, step := range document.Steps {
			steps[step.ID] = true
			if step.FanOut != nil {
				if strings.HasPrefix(step.FanOut.Source, "$input.") {
					if err := validateReference(step.FanOut.Source, inputs, captures, steps); err != nil {
						return fmt.Errorf("step %s fan_out: %w", step.ID, err)
					}
					inputName := strings.TrimPrefix(step.FanOut.Source, "$input.")
					if inputs[inputName].Sensitive {
						return fmt.Errorf("step %s fan_out source input cannot be sensitive because target items are recorded in the receipt", step.ID)
					}
				} else if !regexp.MustCompile(`^\$topology\.target_sets\.[A-Za-z0-9._-]+\.computer_names$`).MatchString(step.FanOut.Source) {
					return fmt.Errorf("step %s fan_out has invalid topology target-set source %q", step.ID, step.FanOut.Source)
				}
			}
			if step.Parallel != nil {
				if err := validateParallel(step.ID, *step.Parallel, inputs, captures, steps); err != nil {
					return err
				}
				for name := range step.Parallel.Exports {
					if captures[name] != "" {
						return fmt.Errorf("capture %q is declared more than once", name)
					}
					captures[name] = step.ID
				}
				continue
			}
			if document.SchemaVersion == 2 && step.Expect == nil {
				return fmt.Errorf("step %s requires expect in operation schema version 2", step.ID)
			}
			if document.SchemaVersion < 3 && len(step.Outcomes) > 0 {
				return fmt.Errorf("step %s outcomes require operation schema version 3", step.ID)
			}
			if document.SchemaVersion >= 3 && (step.Expect == nil) == (len(step.Outcomes) == 0) {
				return fmt.Errorf("step %s must declare exactly one of expect or outcomes", step.ID)
			}
			if step.Expect != nil {
				expectation := expandFanOutExpectation(*step.Expect, "fanout-item")
				if err := validateExpectation(step.ID, expectation, inputs, captures, steps); err != nil {
					return err
				}
			}
			seenOutcomes := map[string]bool{}
			for _, outcome := range step.Outcomes {
				if !idPattern.MatchString(outcome.ID) || seenOutcomes[outcome.ID] {
					return fmt.Errorf("step %s has invalid or duplicate outcome %q", step.ID, outcome.ID)
				}
				seenOutcomes[outcome.ID] = true
				if err := validateExpectation(step.ID+" outcome "+outcome.ID, outcome.Expect, inputs, captures, steps); err != nil {
					return err
				}
				if outcome.Next != "$complete" && outcome.Next != "$fail" {
					target, ok := stepIndexes[outcome.Next]
					if !ok {
						return fmt.Errorf("step %s outcome %s selects unknown step %q", step.ID, outcome.ID, outcome.Next)
					}
					if target <= stepIndex {
						return fmt.Errorf("step %s outcome %s must select a later step", step.ID, outcome.ID)
					}
				}
			}
			for _, value := range step.Arguments {
				value = expandFanOutString(value, "fanout-item")
				if err := validateReference(value, inputs, captures, steps); err != nil {
					return fmt.Errorf("step %s: %w", step.ID, err)
				}
			}
			for name, capture := range step.Captures {
				if !idPattern.MatchString(name) {
					return fmt.Errorf("step %s has invalid capture %q", step.ID, name)
				}
				if step.Operation == "" && (capture.Tag == "" || capture.Field == "" || capture.Capture != "") {
					return fmt.Errorf("step %s pack capture %q requires tag and field", step.ID, name)
				}
				if step.Operation != "" && (capture.Capture == "" || capture.Tag != "" || capture.Field != "") {
					return fmt.Errorf("step %s operation capture %q requires child capture", step.ID, name)
				}
				if captures[name] != "" {
					return fmt.Errorf("capture %q is declared more than once", name)
				}
				captures[name] = step.ID
			}
			if step.Cleanup != nil {
				for _, value := range step.Cleanup.Arguments {
					value = expandFanOutString(value, "fanout-item")
					if err := validateReference(value, inputs, captures, steps); err != nil {
						return fmt.Errorf("step %s cleanup: %w", step.ID, err)
					}
				}
			}
		}
	}
	seenProofs := map[string]bool{}
	for _, proof := range document.ProofCases {
		if !idPattern.MatchString(proof.ID) || seenProofs[proof.ID] {
			return fmt.Errorf("invalid or duplicate proof case %q", proof.ID)
		}
		seenProofs[proof.ID] = true
		if len(proof.Via) == 0 {
			return fmt.Errorf("proof case %s requires at least one runtime", proof.ID)
		}
		for _, via := range proof.Via {
			if via != "native" && via != "lab" && via != "sliver" && via != "cobaltstrike" {
				return fmt.Errorf("proof case %s has unsupported runtime %q", proof.ID, via)
			}
		}
		for _, arch := range proof.Architectures {
			if arch != "x64" && arch != "x86" {
				return fmt.Errorf("proof case %s has unsupported architecture %q", proof.ID, arch)
			}
		}
		for name := range proof.Inputs {
			if inputs[name].Name == "" {
				return fmt.Errorf("proof case %s uses unknown input %q", proof.ID, name)
			}
		}
		for name := range proof.ExpectCaptures {
			if captures[name] == "" {
				return fmt.Errorf("proof case %s expects unknown capture %q", proof.ID, name)
			}
		}
		previous := -1
		for _, stepID := range proof.ExpectPath {
			index, ok := stepIndexes[stepID]
			if !ok {
				return fmt.Errorf("proof case %s expects unknown path step %q", proof.ID, stepID)
			}
			if index <= previous {
				return fmt.Errorf("proof case %s expect_path must follow definition order", proof.ID)
			}
			previous = index
		}
		for _, stepID := range proof.ExpectExpandedPath {
			parts := strings.Split(stepID, "/")
			_, known := stepIndexes[parts[0]]
			if len(parts) == 0 || !known {
				return fmt.Errorf("proof case %s expects unknown expanded path step %q", proof.ID, stepID)
			}
		}
		for groupID, branches := range proof.ExpectParallel {
			index, ok := stepIndexes[groupID]
			if !ok || document.Steps[index].Parallel == nil {
				return fmt.Errorf("proof case %s expects unknown parallel group %q", proof.ID, groupID)
			}
			known := map[string]bool{}
			for _, branch := range document.Steps[index].Parallel.Branches {
				known[branch.ID] = true
			}
			for branchID, state := range branches {
				if !known[branchID] {
					return fmt.Errorf("proof case %s expects unknown branch %s/%s", proof.ID, groupID, branchID)
				}
				if state != "completed" && state != "failed" && state != "incomplete" {
					return fmt.Errorf("proof case %s branch %s/%s has unsupported state %q", proof.ID, groupID, branchID, state)
				}
			}
		}
		for waveIndex, wave := range proof.ExpectWaves {
			if len(wave) == 0 {
				return fmt.Errorf("proof case %s expect_waves[%d] cannot be empty", proof.ID, waveIndex)
			}
			for _, stepID := range wave {
				if _, ok := stepIndexes[stepID]; !ok {
					return fmt.Errorf("proof case %s expects unknown wave step %q", proof.ID, stepID)
				}
			}
		}
		for stepID, state := range proof.ExpectSteps {
			if _, ok := stepIndexes[stepID]; !ok {
				return fmt.Errorf("proof case %s expects unknown step %q", proof.ID, stepID)
			}
			switch state {
			case "completed", "failed", "incomplete", "blocked", "skipped":
			default:
				return fmt.Errorf("proof case %s step %s has unsupported state %q", proof.ID, stepID, state)
			}
		}
		for _, stepID := range proof.ExpectReadySteps {
			index, ok := stepIndexes[stepID]
			if !ok || document.Steps[index].Mode != "background" {
				return fmt.Errorf("proof case %s expects unknown or non-background ready step %q", proof.ID, stepID)
			}
		}
		for stepID, transitions := range proof.ExpectTransitions {
			if _, ok := stepIndexes[stepID]; !ok {
				return fmt.Errorf("proof case %s expects transitions for unknown step %q", proof.ID, stepID)
			}
			for _, state := range transitions {
				switch state {
				case "pending", "preparing", "running", "ready", "retry_wait", "completed", "failed", "incomplete", "canceling", "canceled", "blocked", "skipped":
				default:
					return fmt.Errorf("proof case %s step %s has unsupported transition %q", proof.ID, stepID, state)
				}
			}
		}
		for stepID, attempts := range proof.ExpectAttempts {
			if _, ok := stepIndexes[stepID]; !ok {
				return fmt.Errorf("proof case %s expects attempts for unknown step %q", proof.ID, stepID)
			}
			if attempts < 1 || attempts > 16 {
				return fmt.Errorf("proof case %s step %s has invalid expected attempt count %d", proof.ID, stepID, attempts)
			}
		}
		for stepID, reasons := range proof.ExpectRetryReasons {
			index, ok := stepIndexes[stepID]
			if !ok || document.Steps[index].Retry == nil {
				return fmt.Errorf("proof case %s expects retry reasons for unknown or non-retry step %q", proof.ID, stepID)
			}
			known := map[string]bool{}
			for _, contract := range document.Steps[index].Retry.When {
				known[contract.ID] = true
			}
			for _, reason := range reasons {
				if !known[reason] {
					return fmt.Errorf("proof case %s step %s expects unknown retry reason %q", proof.ID, stepID, reason)
				}
			}
		}
		for stepID, count := range proof.ExpectFanOut {
			index, ok := stepIndexes[stepID]
			if !ok || document.Steps[index].FanOut == nil {
				return fmt.Errorf("proof case %s expects fan-out for unknown or non-fan-out step %q", proof.ID, stepID)
			}
			if count < 1 || count > document.Steps[index].FanOut.MaxItems {
				return fmt.Errorf("proof case %s step %s has invalid expected fan-out count %d", proof.ID, stepID, count)
			}
		}
	}
	return nil
}

func validateDAG(document Document, inputs map[string]Input, stepIndexes map[string]int) (map[string]string, error) {
	if document.SchemaVersion < 6 || document.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("dag execution requires operation schema version 6 through %d", SchemaVersion)
	}
	captureOwners := map[string]string{}
	for _, step := range document.Steps {
		if step.Parallel != nil || len(step.Outcomes) > 0 {
			return nil, fmt.Errorf("dag step %s cannot declare parallel groups or ordered outcomes", step.ID)
		}
		if step.Expect == nil {
			return nil, fmt.Errorf("dag step %s requires expect", step.ID)
		}
		mode := step.Mode
		if mode == "" {
			mode = "foreground"
		}
		if mode != "foreground" && mode != "background" {
			return nil, fmt.Errorf("dag step %s mode must be foreground or background", step.ID)
		}
		if mode == "foreground" && (step.Ready != nil || len(step.ReadyCaptures) > 0 || step.TimeoutMS != 0) {
			return nil, fmt.Errorf("dag step %s foreground mode cannot declare readiness fields", step.ID)
		}
		if mode == "background" {
			if document.SchemaVersion < 7 || step.Ready == nil || step.TimeoutMS <= 0 {
				return nil, fmt.Errorf("dag step %s background mode requires schema v7, ready, and timeout_ms", step.ID)
			}
			if step.Operation != "" || step.Parallel != nil {
				return nil, fmt.Errorf("dag step %s background mode currently requires a direct pack", step.ID)
			}
		}
		if step.Retry != nil {
			if document.SchemaVersion < 8 {
				return nil, fmt.Errorf("dag step %s retry requires schema v8", step.ID)
			}
			if step.Operation != "" || step.Parallel != nil {
				return nil, fmt.Errorf("dag step %s retry currently requires a direct pack", step.ID)
			}
			if step.Retry.MaxAttempts < 2 || step.Retry.MaxAttempts > 16 {
				return nil, fmt.Errorf("dag step %s retry max_attempts must be between 2 and 16", step.ID)
			}
			if step.Retry.DelayMS < 0 || step.Retry.MaxDelayMS < 0 {
				return nil, fmt.Errorf("dag step %s retry delays cannot be negative", step.ID)
			}
			if step.Retry.Backoff != "fixed" && step.Retry.Backoff != "exponential" {
				return nil, fmt.Errorf("dag step %s retry backoff must be fixed or exponential", step.ID)
			}
			if step.Retry.Backoff == "exponential" && step.Retry.MaxDelayMS > 0 && step.Retry.MaxDelayMS < step.Retry.DelayMS {
				return nil, fmt.Errorf("dag step %s retry max_delay_ms cannot be less than delay_ms", step.ID)
			}
			if len(step.Retry.When) == 0 {
				return nil, fmt.Errorf("dag step %s retry requires at least one when contract", step.ID)
			}
			seenRetry := map[string]bool{}
			for _, contract := range step.Retry.When {
				if !idPattern.MatchString(contract.ID) || seenRetry[contract.ID] {
					return nil, fmt.Errorf("dag step %s has invalid or duplicate retry contract %q", step.ID, contract.ID)
				}
				seenRetry[contract.ID] = true
				if err := validateExpectation(step.ID+" retry "+contract.ID, contract.Expect, inputs, captureOwners, map[string]bool{}); err != nil {
					return nil, err
				}
			}
		}
		allDependencies := append(append([]string(nil), step.DependsOn...), step.DependsOnReady...)
		seenDependencies := map[string]bool{}
		for _, dependency := range allDependencies {
			if dependency == step.ID {
				return nil, fmt.Errorf("dag step %s cannot depend on itself", step.ID)
			}
			if _, ok := stepIndexes[dependency]; !ok {
				return nil, fmt.Errorf("dag step %s depends on unknown step %q", step.ID, dependency)
			}
			if seenDependencies[dependency] {
				return nil, fmt.Errorf("dag step %s repeats dependency %q", step.ID, dependency)
			}
			seenDependencies[dependency] = true
		}
		for _, dependency := range step.DependsOnReady {
			target := document.Steps[stepIndexes[dependency]]
			if target.Mode != "background" {
				return nil, fmt.Errorf("dag step %s depends_on_ready requires background step %q", step.ID, dependency)
			}
		}
		allCaptures := map[string]Capture{}
		for name, capture := range step.Captures {
			allCaptures[name] = capture
		}
		for name, capture := range step.ReadyCaptures {
			if _, exists := allCaptures[name]; exists {
				return nil, fmt.Errorf("step %s declares capture %q more than once", step.ID, name)
			}
			allCaptures[name] = capture
		}
		for name, capture := range allCaptures {
			if !idPattern.MatchString(name) {
				return nil, fmt.Errorf("step %s has invalid capture %q", step.ID, name)
			}
			if step.Operation == "" && (capture.Tag == "" || capture.Field == "" || capture.Capture != "") {
				return nil, fmt.Errorf("step %s pack capture %q requires tag and field", step.ID, name)
			}
			if step.Operation != "" && (capture.Capture == "" || capture.Tag != "" || capture.Field != "") {
				return nil, fmt.Errorf("step %s operation capture %q requires child capture", step.ID, name)
			}
			if captureOwners[name] != "" {
				return nil, fmt.Errorf("capture %q is declared more than once", name)
			}
			captureOwners[name] = step.ID
		}
	}
	order, ancestors, err := dagTopology(document)
	if err != nil {
		return nil, err
	}
	_ = order
	allSteps := map[string]bool{}
	for id := range stepIndexes {
		allSteps[id] = true
	}
	for _, step := range document.Steps {
		available := map[string]string{}
		for name, owner := range captureOwners {
			if ancestors[step.ID][owner] {
				available[name] = owner
			}
		}
		validateValue := func(label, value string) error {
			if err := validateReference(value, inputs, available, allSteps); err != nil {
				return fmt.Errorf("dag step %s %s: %w", step.ID, label, err)
			}
			references, err := operationReferences(value)
			if err != nil {
				return fmt.Errorf("dag step %s %s: %w", step.ID, label, err)
			}
			for _, reference := range references {
				if !strings.HasPrefix(reference, "$step.") {
					continue
				}
				parts := strings.Split(strings.TrimPrefix(reference, "$step."), ".")
				if len(parts) == 2 && !ancestors[step.ID][parts[0]] {
					return fmt.Errorf("dag step %s may consume captures only from transitive dependencies", step.ID)
				}
			}
			return nil
		}
		for _, value := range step.Arguments {
			if err := validateValue("argument", value); err != nil {
				return nil, err
			}
		}
		if err := validateDAGExpectation(step.ID, *step.Expect, inputs, available, allSteps, ancestors[step.ID]); err != nil {
			return nil, err
		}
		if step.Ready != nil {
			if err := validateDAGExpectation(step.ID+" ready", *step.Ready, inputs, available, allSteps, ancestors[step.ID]); err != nil {
				return nil, err
			}
		}
		if step.Cleanup != nil {
			cleanupAvailable := map[string]string{}
			for name, owner := range available {
				cleanupAvailable[name] = owner
			}
			for name, owner := range captureOwners {
				if owner == step.ID {
					cleanupAvailable[name] = owner
				}
			}
			for _, value := range step.Cleanup.Arguments {
				if err := validateReference(value, inputs, cleanupAvailable, allSteps); err != nil {
					return nil, fmt.Errorf("dag step %s cleanup: %w", step.ID, err)
				}
			}
		}
	}
	return captureOwners, nil
}

func validateDAGExpectation(label string, expectation packsvc.ProofExpectation, inputs map[string]Input, captures map[string]string, steps map[string]bool, ancestors map[string]bool) error {
	if err := validateExpectation(label, expectation, inputs, captures, steps); err != nil {
		return err
	}
	values := make([]string, 0, len(expectation.Fields)+1)
	for _, value := range expectation.Fields {
		values = append(values, value)
	}
	if expectation.Payload != nil {
		values = append(values, expectation.Payload.SHA256)
	}
	for _, value := range values {
		references, err := operationReferences(value)
		if err != nil {
			return err
		}
		for _, reference := range references {
			if !strings.HasPrefix(reference, "$step.") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(reference, "$step."), ".")
			if len(parts) == 2 && !ancestors[parts[0]] {
				return fmt.Errorf("dag step %s expectation may consume captures only from transitive dependencies", label)
			}
		}
	}
	return nil
}

func stepTargetCount(step Step) int {
	count := 0
	if step.Pack != "" {
		count++
	}
	if step.Operation != "" {
		count++
	}
	if step.Parallel != nil {
		count++
	}
	return count
}

func expandFanOutString(value, item string) string {
	value = strings.ReplaceAll(value, "${item}", item)
	return strings.ReplaceAll(value, "$item", item)
}

func expandFanOutExpectation(expectation packsvc.ProofExpectation, item string) packsvc.ProofExpectation {
	result := expectation
	result.Tag = expandFanOutString(result.Tag, item)
	result.Fields = map[string]string{}
	for name, value := range expectation.Fields {
		result.Fields[name] = expandFanOutString(value, item)
	}
	if expectation.Payload != nil {
		payload := *expectation.Payload
		payload.Tag = expandFanOutString(payload.Tag, item)
		payload.Field = expandFanOutString(payload.Field, item)
		payload.SHA256 = expandFanOutString(payload.SHA256, item)
		result.Payload = &payload
	}
	return result
}

func expandFanOutMap(values map[string]string, item string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = expandFanOutString(value, item)
	}
	return result
}

// ExpandFanOutDocument converts bounded fan-out declarations into
// explicit parallel branches. The original definition hash remains pinned;
// the concrete items and branch states are pinned in the receipt.
func ExpandFanOutDocument(document Document, inputs map[string]string) (Document, error) {
	return ExpandFanOutDocumentWithTopology(document, inputs, nil)
}

// ExpandFanOutDocumentWithTopology resolves schema-v11 target-set sources from
// the caller's already inspected topology values. It never discovers targets.
func ExpandFanOutDocumentWithTopology(document Document, inputs, topologyValues map[string]string) (Document, error) {
	result := document
	result.Steps = append([]Step(nil), document.Steps...)
	for index := range result.Steps {
		step := result.Steps[index]
		if step.FanOut == nil {
			continue
		}
		var source string
		var err error
		if strings.HasPrefix(step.FanOut.Source, "$topology.") {
			key := strings.TrimPrefix(step.FanOut.Source, "$topology.")
			source = topologyValues[key]
			if source == "" {
				err = fmt.Errorf("topology value %s is unavailable", key)
			}
		} else {
			source, err = ResolveValue(step.FanOut.Source, inputs, nil, nil)
		}
		if err != nil {
			return Document{}, fmt.Errorf("expand fan-out step %s: %w", step.ID, err)
		}
		separator := step.FanOut.Separator
		if separator == "" {
			separator = ","
		}
		if separator == "\\n" {
			separator = "\n"
		}
		seen := map[string]bool{}
		items := []string{}
		for _, raw := range strings.Split(source, separator) {
			item := strings.TrimSpace(raw)
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			items = append(items, item)
		}
		if len(items) == 0 {
			return Document{}, fmt.Errorf("fan-out step %s resolved no targets", step.ID)
		}
		if len(items) > step.FanOut.MaxItems {
			return Document{}, fmt.Errorf("fan-out step %s resolved %d targets; maximum is %d", step.ID, len(items), step.FanOut.MaxItems)
		}
		parallel := &Parallel{Join: "all"}
		for itemIndex, item := range items {
			branch := ParallelBranch{ID: fmt.Sprintf("target-%02d", itemIndex+1), Pack: step.Pack, Operation: step.Operation, Arguments: expandFanOutMap(step.Arguments, item), Captures: step.Captures}
			if step.Expect != nil {
				expectation := expandFanOutExpectation(*step.Expect, item)
				branch.Expect = &expectation
			}
			if step.Cleanup != nil {
				cleanup := *step.Cleanup
				cleanup.Arguments = expandFanOutMap(step.Cleanup.Arguments, item)
				branch.Cleanup = &cleanup
			}
			parallel.Branches = append(parallel.Branches, branch)
		}
		fanOut := *step.FanOut
		fanOut.ResolvedItems = append([]string(nil), items...)
		step.FanOut, step.Parallel = &fanOut, parallel
		step.Pack, step.Operation, step.Arguments, step.Captures, step.Cleanup, step.Expect = "", "", nil, nil, nil, nil
		result.Steps[index] = step
	}
	return result, nil
}

func SyncFanOutReceipt(step Step, receipt *StepReceipt) {
	if receipt == nil || step.FanOut == nil || receipt.Parallel == nil {
		return
	}
	if receipt.FanOut == nil {
		receipt.FanOut = &FanOutReceipt{Source: step.FanOut.Source, Items: append([]string(nil), step.FanOut.ResolvedItems...), MaxItems: step.FanOut.MaxItems}
	}
	receipt.FanOut.State = receipt.Parallel.State
	receipt.FanOut.ObservedConcurrency = receipt.Parallel.ObservedConcurrency
	receipt.FanOut.Branches = receipt.FanOut.Branches[:0]
	for index, branch := range receipt.Parallel.Branches {
		item := ""
		if index < len(receipt.FanOut.Items) {
			item = receipt.FanOut.Items[index]
		}
		receipt.FanOut.Branches = append(receipt.FanOut.Branches, FanOutBranchReceipt{ID: branch.ID, Item: item, State: branch.State, CleanupState: branch.CleanupState, Error: branch.Error})
	}
}

func branchTargetCount(branch ParallelBranch) int {
	count := 0
	if branch.Pack != "" {
		count++
	}
	if branch.Operation != "" {
		count++
	}
	return count
}

func dagTopology(document Document) ([]string, map[string]map[string]bool, error) {
	index := map[string]int{}
	dependencies := map[string][]string{}
	dependents := map[string][]string{}
	indegree := map[string]int{}
	for position, step := range document.Steps {
		index[step.ID] = position
		seen := map[string]bool{}
		for _, dependency := range append(append([]string(nil), step.DependsOn...), step.DependsOnReady...) {
			if seen[dependency] {
				return nil, nil, fmt.Errorf("dag step %s repeats dependency %q", step.ID, dependency)
			}
			seen[dependency] = true
			dependencies[step.ID] = append(dependencies[step.ID], dependency)
			dependents[dependency] = append(dependents[dependency], step.ID)
			indegree[step.ID]++
		}
	}
	var ready []string
	for _, step := range document.Steps {
		if indegree[step.ID] == 0 {
			ready = append(ready, step.ID)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool { return index[ready[i]] < index[ready[j]] })
	var order []string
	for len(ready) > 0 {
		current := ready[0]
		ready = ready[1:]
		order = append(order, current)
		for _, dependent := range dependents[current] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				ready = append(ready, dependent)
				sort.SliceStable(ready, func(i, j int) bool { return index[ready[i]] < index[ready[j]] })
			}
		}
	}
	if len(order) != len(document.Steps) {
		return nil, nil, fmt.Errorf("dag operation contains a dependency cycle")
	}
	ancestors := map[string]map[string]bool{}
	for _, id := range order {
		ancestors[id] = map[string]bool{}
		for _, dependency := range dependencies[id] {
			ancestors[id][dependency] = true
			for ancestor := range ancestors[dependency] {
				ancestors[id][ancestor] = true
			}
		}
	}
	return order, ancestors, nil
}

func TopologicalOrder(document Document) ([]string, error) {
	if document.Execution != "dag" {
		order := make([]string, 0, len(document.Steps))
		for _, step := range document.Steps {
			order = append(order, step.ID)
		}
		return order, nil
	}
	order, _, err := dagTopology(document)
	return order, err
}

func validateParallel(stepID string, parallel Parallel, inputs map[string]Input, captures map[string]string, steps map[string]bool) error {
	if parallel.Join != "all" {
		return fmt.Errorf("step %s parallel join must be all", stepID)
	}
	if len(parallel.Branches) < 2 {
		return fmt.Errorf("step %s parallel group requires at least two branches", stepID)
	}
	branchCaptures := map[string]map[string]bool{}
	seen := map[string]bool{}
	for _, branch := range parallel.Branches {
		if !idPattern.MatchString(branch.ID) || seen[branch.ID] {
			return fmt.Errorf("step %s has invalid or duplicate parallel branch %q", stepID, branch.ID)
		}
		seen[branch.ID] = true
		if branchTargetCount(branch) != 1 {
			return fmt.Errorf("step %s branch %s must declare exactly one of pack or operation", stepID, branch.ID)
		}
		if branch.Operation != "" && branch.Cleanup != nil {
			return fmt.Errorf("step %s branch %s child operation owns its cleanup", stepID, branch.ID)
		}
		if branch.Expect == nil {
			return fmt.Errorf("step %s branch %s requires expect", stepID, branch.ID)
		}
		if err := validateExpectation(stepID+" branch "+branch.ID, *branch.Expect, inputs, captures, steps); err != nil {
			return err
		}
		for _, value := range branch.Arguments {
			if err := validateReference(value, inputs, captures, steps); err != nil {
				return fmt.Errorf("step %s branch %s: %w", stepID, branch.ID, err)
			}
		}
		branchCaptures[branch.ID] = map[string]bool{}
		for name, capture := range branch.Captures {
			if !idPattern.MatchString(name) {
				return fmt.Errorf("step %s branch %s has invalid capture %q", stepID, branch.ID, name)
			}
			if branch.Pack != "" && (capture.Tag == "" || capture.Field == "" || capture.Capture != "") {
				return fmt.Errorf("step %s branch %s pack capture %q requires tag and field", stepID, branch.ID, name)
			}
			if branch.Operation != "" && (capture.Capture == "" || capture.Tag != "" || capture.Field != "") {
				return fmt.Errorf("step %s branch %s operation capture %q requires child capture", stepID, branch.ID, name)
			}
			branchCaptures[branch.ID][name] = true
		}
		if branch.Cleanup != nil {
			cleanupCaptures := map[string]string{}
			for name, owner := range captures {
				cleanupCaptures[name] = owner
			}
			for name := range branchCaptures[branch.ID] {
				cleanupCaptures[name] = stepID + "/" + branch.ID
			}
			for _, value := range branch.Cleanup.Arguments {
				if err := validateReference(value, inputs, cleanupCaptures, steps); err != nil {
					return fmt.Errorf("step %s branch %s cleanup: %w", stepID, branch.ID, err)
				}
			}
		}
	}
	for name, reference := range parallel.Exports {
		if !idPattern.MatchString(name) {
			return fmt.Errorf("step %s has invalid parallel export %q", stepID, name)
		}
		parts := strings.Split(strings.TrimPrefix(reference, "$"), ".")
		if len(parts) != 3 || parts[0] != "branch" || !branchCaptures[parts[1]][parts[2]] {
			return fmt.Errorf("step %s export %s selects unknown branch capture %q", stepID, name, reference)
		}
	}
	return nil
}

func validateExpectation(label string, expectation packsvc.ProofExpectation, inputs map[string]Input, captures map[string]string, steps map[string]bool) error {
	if !idPattern.MatchString(expectation.Tag) {
		return fmt.Errorf("step %s has invalid expected tag %q", label, expectation.Tag)
	}
	for _, value := range expectation.Fields {
		if value != "*" {
			if err := validateReference(value, inputs, captures, steps); err != nil {
				return fmt.Errorf("step %s expectation: %w", label, err)
			}
		}
	}
	if payload := expectation.Payload; payload != nil {
		if !idPattern.MatchString(payload.Tag) || !idPattern.MatchString(payload.Field) || (payload.Encoding != "hex" && payload.Encoding != "base64") || payload.SHA256 == "" {
			return fmt.Errorf("step %s has invalid payload expectation", label)
		}
		if strings.HasPrefix(payload.SHA256, "$") {
			if err := validateReference(payload.SHA256, inputs, captures, steps); err != nil {
				return fmt.Errorf("step %s payload expectation: %w", label, err)
			}
		}
	}
	return nil
}

func validateReference(value string, inputs map[string]Input, captures map[string]string, steps map[string]bool) error {
	references, err := operationReferences(value)
	if err != nil {
		return err
	}
	for _, reference := range references {
		if err := validateExactReference(reference, inputs, captures, steps); err != nil {
			return err
		}
	}
	return nil
}

func validateExactReference(value string, inputs map[string]Input, captures map[string]string, steps map[string]bool) error {
	if !strings.HasPrefix(value, "$") {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(value, "$"), ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid reference %q", value)
	}
	switch parts[0] {
	case "input":
		if len(parts) != 2 || inputs[parts[1]].Name == "" {
			return fmt.Errorf("unknown or forward input reference %q", value)
		}
	case "capture":
		if len(parts) != 2 || captures[parts[1]] == "" {
			return fmt.Errorf("unknown or forward capture reference %q", value)
		}
	case "step":
		if len(parts) != 3 || !steps[parts[1]] || captures[parts[2]] != parts[1] {
			return fmt.Errorf("unknown or forward step capture reference %q", value)
		}
	case "topology":
		if len(parts) < 3 || (parts[1] != "execution" && parts[1] != "target" && parts[1] != "domain_controller" && parts[1] != "domain") {
			return fmt.Errorf("topology reference %q must select a role and field", value)
		}
	default:
		return fmt.Errorf("unsupported reference %q", value)
	}
	return nil
}

func operationReferences(value string) ([]string, error) {
	if !strings.Contains(value, "${") {
		if strings.HasPrefix(value, "$") {
			return []string{value}, nil
		}
		return nil, nil
	}
	var references []string
	remaining := value
	for {
		start := strings.Index(remaining, "${")
		if start < 0 {
			break
		}
		tail := remaining[start+2:]
		end := strings.IndexByte(tail, '}')
		if end < 0 {
			return nil, fmt.Errorf("unterminated operation template in %q", value)
		}
		name := tail[:end]
		if name == "" || strings.ContainsAny(name, "${}") {
			return nil, fmt.Errorf("invalid operation template reference in %q", value)
		}
		references = append(references, "$"+name)
		remaining = tail[end+1:]
	}
	return references, nil
}

func documentUsesTemplates(document Document) bool {
	uses := func(value string) bool { return strings.Contains(value, "${") }
	expectationUses := func(expectation *packsvc.ProofExpectation) bool {
		if expectation == nil {
			return false
		}
		for _, value := range expectation.Fields {
			if uses(value) {
				return true
			}
		}
		return expectation.Payload != nil && uses(expectation.Payload.SHA256)
	}
	mapUses := func(values map[string]string) bool {
		for _, value := range values {
			if uses(value) {
				return true
			}
		}
		return false
	}
	for _, step := range document.Steps {
		if mapUses(step.Arguments) || expectationUses(step.Expect) || expectationUses(step.Ready) || (step.Cleanup != nil && mapUses(step.Cleanup.Arguments)) {
			return true
		}
		for _, outcome := range step.Outcomes {
			if expectationUses(&outcome.Expect) {
				return true
			}
		}
		if step.Retry != nil {
			for _, condition := range step.Retry.When {
				if expectationUses(&condition.Expect) {
					return true
				}
			}
		}
		if step.Parallel != nil {
			for _, branch := range step.Parallel.Branches {
				if mapUses(branch.Arguments) || expectationUses(branch.Expect) || (branch.Cleanup != nil && mapUses(branch.Cleanup.Arguments)) {
					return true
				}
			}
		}
	}
	return false
}

func validType(value string) bool {
	switch strings.ToLower(value) {
	case "string", "wstring", "int", "short", "bytes", "file":
		return true
	}
	return false
}

func ExecutionMode(document Document) string {
	if document.Execution == "" {
		return "linear"
	}
	return document.Execution
}

func emptyDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func IsDAG(document Document) bool { return ExecutionMode(document) == "dag" }

func ResolveValue(value string, inputs, captures, topology map[string]string) (string, error) {
	if strings.Contains(value, "${") {
		var rendered strings.Builder
		remaining := value
		for {
			start := strings.Index(remaining, "${")
			if start < 0 {
				rendered.WriteString(remaining)
				return rendered.String(), nil
			}
			rendered.WriteString(remaining[:start])
			tail := remaining[start+2:]
			end := strings.IndexByte(tail, '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated operation template in %q", value)
			}
			reference := "$" + tail[:end]
			resolved, err := resolveExactValue(reference, inputs, captures, topology)
			if err != nil {
				return "", err
			}
			rendered.WriteString(resolved)
			remaining = tail[end+1:]
		}
	}
	return resolveExactValue(value, inputs, captures, topology)
}

func resolveExactValue(value string, inputs, captures, topology map[string]string) (string, error) {
	if !strings.HasPrefix(value, "$") {
		return value, nil
	}
	if strings.HasPrefix(value, "$input.") {
		name := strings.TrimPrefix(value, "$input.")
		v, ok := inputs[name]
		if !ok {
			return "", fmt.Errorf("missing operation input %s", name)
		}
		return v, nil
	}
	if strings.HasPrefix(value, "$capture.") {
		name := strings.TrimPrefix(value, "$capture.")
		v, ok := captures[name]
		if !ok {
			return "", fmt.Errorf("missing operation capture %s", name)
		}
		return v, nil
	}
	if strings.HasPrefix(value, "$step.") {
		parts := strings.Split(strings.TrimPrefix(value, "$step."), ".")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid step capture reference %q", value)
		}
		v, ok := captures[parts[1]]
		if !ok {
			return "", fmt.Errorf("missing operation capture %s", parts[1])
		}
		return v, nil
	}
	if strings.HasPrefix(value, "$topology.") {
		name := strings.TrimPrefix(value, "$topology.")
		v, ok := topology[name]
		if !ok {
			return "", fmt.Errorf("missing topology value %s", name)
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported operation reference %q", value)
}

// ValidateTopologyRoles ensures an operation receives every host role it
// declares. Values are populated only after the corresponding profile has
// been resolved and its Windows identity inspected.
func ValidateTopologyRoles(roles []string, values map[string]string) error {
	for _, role := range roles {
		if strings.TrimSpace(values[role+".computer_name"]) == "" {
			return fmt.Errorf("operation requires topology role %s; select a topology that provides it", role)
		}
	}
	return nil
}

// ReadyDAGSteps returns a deterministic ready wave. Incomplete or running
// external-runtime work is returned alone so it is refreshed before any new
// dependent or independent work is scheduled.
func ReadyDAGSteps(document Document, receipt Receipt) ([]int, error) {
	if !IsDAG(document) {
		return nil, fmt.Errorf("ready waves require dag execution")
	}
	if len(document.Steps) != len(receipt.Steps) {
		return nil, fmt.Errorf("operation receipt step count does not match definition")
	}
	var foregroundActive, backgroundActive []int
	for index, step := range receipt.Steps {
		if step.State == "failed" {
			return nil, fmt.Errorf("dag step %q failed and cannot be resumed without an explicit retry", step.ID)
		}
		if step.State == "incomplete" || step.State == "running" {
			if document.Steps[index].Mode == "background" {
				backgroundActive = append(backgroundActive, index)
			} else {
				foregroundActive = append(foregroundActive, index)
			}
		}
		if step.State == "ready" {
			backgroundActive = append(backgroundActive, index)
		}
		if step.State == "retry_wait" && RetryDue(step, time.Now()) {
			foregroundActive = append(foregroundActive, index)
		}
	}
	if len(foregroundActive) > 0 {
		return foregroundActive, nil
	}
	state := map[string]string{}
	for _, step := range receipt.Steps {
		state[step.ID] = step.State
	}
	var ready []int
	for index, step := range document.Steps {
		if receipt.Steps[index].State != "pending" {
			continue
		}
		dependenciesComplete := true
		for _, dependency := range step.DependsOn {
			if state[dependency] != "completed" {
				dependenciesComplete = false
				break
			}
		}
		if dependenciesComplete {
			for _, dependency := range step.DependsOnReady {
				if state[dependency] != "ready" && state[dependency] != "completed" {
					dependenciesComplete = false
					break
				}
			}
		}
		if dependenciesComplete {
			ready = append(ready, index)
		}
	}
	return append(backgroundActive, ready...), nil
}

// RetryDue reports whether a persisted retry backoff has elapsed. A missing
// timestamp is treated as immediately eligible so older or hand-carried
// receipts cannot become permanently stuck.
func RetryDue(step StepReceipt, now time.Time) bool {
	if step.State != "retry_wait" {
		return false
	}
	if strings.TrimSpace(step.NextAttemptAt) == "" {
		return true
	}
	eligible, err := time.Parse(time.RFC3339Nano, step.NextAttemptAt)
	return err != nil || !now.Before(eligible)
}

// NextRetryDelay returns the shortest pending deterministic backoff.
func NextRetryDelay(receipt Receipt, now time.Time) (time.Duration, bool) {
	var shortest time.Duration
	found := false
	for _, step := range receipt.Steps {
		if step.State != "retry_wait" {
			continue
		}
		eligible, err := time.Parse(time.RFC3339Nano, step.NextAttemptAt)
		if err != nil || !now.Before(eligible) {
			return 0, true
		}
		delay := eligible.Sub(now)
		if !found || delay < shortest {
			shortest, found = delay, true
		}
	}
	return shortest, found
}

// MatchRetry returns the first explicitly declared transient result contract.
func MatchRetry(lines []string, policy *RetryPolicy, inputs, captures, topology map[string]string) (string, bool) {
	if policy == nil {
		return "", false
	}
	for _, contract := range policy.When {
		if _, _, err := EvaluateExpectation(lines, &contract.Expect, inputs, captures, topology); err == nil {
			return contract.ID, true
		}
	}
	return "", false
}

// RetryDelay returns the deterministic delay before the next attempt. The
// completedAttempts value includes the initial attempt.
func RetryDelay(policy *RetryPolicy, completedAttempts int) time.Duration {
	if policy == nil || policy.DelayMS <= 0 {
		return 0
	}
	delay := int64(policy.DelayMS)
	if policy.Backoff == "exponential" && completedAttempts > 1 {
		for i := 1; i < completedAttempts; i++ {
			if delay > int64(^uint(0)>>1)/2 {
				break
			}
			delay *= 2
		}
	}
	if policy.MaxDelayMS > 0 && delay > int64(policy.MaxDelayMS) {
		delay = int64(policy.MaxDelayMS)
	}
	return time.Duration(delay) * time.Millisecond
}

func UnblockDAGSteps(document Document, receipt *Receipt) {
	state := map[string]string{}
	for _, step := range receipt.Steps {
		state[step.ID] = step.State
	}
	for index, step := range document.Steps {
		if receipt.Steps[index].State != "blocked" {
			continue
		}
		ready := true
		for _, dependency := range step.DependsOn {
			if state[dependency] != "completed" {
				ready = false
				break
			}
		}
		if ready {
			for _, dependency := range step.DependsOnReady {
				if state[dependency] != "ready" && state[dependency] != "completed" {
					ready = false
					break
				}
			}
		}
		if ready {
			receipt.Steps[index].State = "pending"
			receipt.Steps[index].ContractState = "pending"
			receipt.Steps[index].BlockedBy = nil
		}
	}
}

func DAGComplete(receipt Receipt) bool {
	for _, step := range receipt.Steps {
		if step.State != "completed" && step.State != "skipped" && step.State != "canceled" {
			return false
		}
	}
	return true
}

func BlockDAGDescendants(document Document, receipt *Receipt, causes []string) {
	if len(causes) == 0 {
		return
	}
	blocked := map[string]bool{}
	for _, cause := range causes {
		blocked[cause] = true
	}
	changed := true
	for changed {
		changed = false
		for index, step := range document.Steps {
			if receipt.Steps[index].State != "pending" {
				continue
			}
			var blockers []string
			for _, dependency := range append(append([]string(nil), step.DependsOn...), step.DependsOnReady...) {
				if blocked[dependency] {
					blockers = append(blockers, dependency)
				}
			}
			if len(blockers) == 0 {
				continue
			}
			sort.Strings(blockers)
			receipt.Steps[index].State = "blocked"
			receipt.Steps[index].ContractState = "blocked"
			receipt.Steps[index].BlockedBy = blockers
			receipt.BlockedSteps = appendUnique(receipt.BlockedSteps, step.ID)
			blocked[step.ID] = true
			changed = true
		}
	}
}

// NextRunnableStep returns the single step selected by the persisted route.
// The selected next step is written when a completed result contract matches,
// so resume never reevaluates a prior branch against different output.
func NextRunnableStep(document Document, receipt Receipt) (int, bool, error) {
	if len(document.Steps) != len(receipt.Steps) {
		return 0, false, fmt.Errorf("operation receipt step count does not match definition")
	}
	for index, step := range receipt.Steps {
		if step.State == "incomplete" || step.State == "running" {
			return index, true, nil
		}
	}
	if len(receipt.ActualPath) == 0 {
		for index, step := range receipt.Steps {
			if step.State == "pending" {
				return index, true, nil
			}
		}
		return 0, false, nil
	}
	lastID := receipt.ActualPath[len(receipt.ActualPath)-1]
	last := -1
	for index := range document.Steps {
		if document.Steps[index].ID == lastID {
			last = index
			break
		}
	}
	if last < 0 {
		return 0, false, fmt.Errorf("receipt path references unknown step %q", lastID)
	}
	next := receipt.Steps[last].NextStep
	if next == "$complete" || next == "$fail" {
		return 0, false, nil
	}
	if next != "" {
		for index := range document.Steps {
			if document.Steps[index].ID == next {
				if receipt.Steps[index].State == "completed" {
					return 0, false, fmt.Errorf("route selected already completed step %q", next)
				}
				if receipt.Steps[index].State == "failed" {
					return 0, false, fmt.Errorf("route-selected step %q failed and cannot be resumed without an explicit retry", next)
				}
				return index, true, nil
			}
		}
		return 0, false, fmt.Errorf("route selected unknown step %q", next)
	}
	// Version 1/2 receipts and linear version 3 steps advance in definition
	// order when no explicit route was necessary.
	for index := last + 1; index < len(receipt.Steps); index++ {
		if receipt.Steps[index].State == "pending" {
			return index, true, nil
		}
		if receipt.Steps[index].State == "failed" {
			return 0, false, fmt.Errorf("step %q failed and cannot be resumed without an explicit retry", document.Steps[index].ID)
		}
	}
	return 0, false, nil
}

// RunnableStepIndexes remains as a compatibility helper for version 1/2
// callers and tests. New execution uses NextRunnableStep.
func RunnableStepIndexes(receipt Receipt) []int {
	indexes := make([]int, 0, len(receipt.Steps))
	for index, step := range receipt.Steps {
		if step.State != "completed" && step.State != "skipped" {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

// ApplyRoute records a completed step in the actual path and marks definition
// steps bypassed by its selected forward route as skipped.
func ApplyRoute(document Document, receipt *Receipt, index int) error {
	if index < 0 || index >= len(document.Steps) || index >= len(receipt.Steps) {
		return fmt.Errorf("invalid route step index %d", index)
	}
	id := document.Steps[index].ID
	if len(receipt.ActualPath) == 0 || receipt.ActualPath[len(receipt.ActualPath)-1] != id {
		receipt.ActualPath = append(receipt.ActualPath, id)
	}
	receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, id)
	next := receipt.Steps[index].NextStep
	target := index + 1
	if next == "$complete" || next == "$fail" {
		target = len(document.Steps)
	} else if next != "" {
		target = -1
		for candidate := index + 1; candidate < len(document.Steps); candidate++ {
			if document.Steps[candidate].ID == next {
				target = candidate
				break
			}
		}
		if target < 0 {
			return fmt.Errorf("step %s selected invalid next step %q", id, next)
		}
	}
	for skipped := index + 1; skipped < target; skipped++ {
		if receipt.Steps[skipped].State == "pending" {
			receipt.Steps[skipped].State = "skipped"
			receipt.Steps[skipped].ContractState = "skipped"
			receipt.SkippedSteps = appendUnique(receipt.SkippedSteps, document.Steps[skipped].ID)
		}
	}
	return nil
}

// RecordChildPath expands a completed child receipt beneath its parent step.
func RecordChildPath(receipt *Receipt, stepID string, child Receipt) {
	receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, stepID)
	path := child.ExpandedPath
	if len(path) == 0 {
		path = child.ActualPath
	}
	for _, childStep := range path {
		receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, stepID+"/"+childStep)
	}
}

func RecordParallelPath(receipt *Receipt, stepID string, parallel ParallelReceipt) {
	receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, stepID)
	for _, branch := range parallel.Branches {
		branchID := stepID + "/" + branch.ID
		receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, branchID)
		if branch.ChildReceipt == "" {
			continue
		}
		child, err := LoadReceipt(branch.ChildReceipt)
		if err != nil {
			continue
		}
		path := child.ExpandedPath
		if len(path) == 0 {
			path = child.ActualPath
		}
		for _, childStep := range path {
			receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, branchID+"/"+childStep)
		}
	}
	receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, stepID+"/$join")
}

func appendUnique(values []string, value string) []string {
	for _, candidate := range values {
		if candidate == value {
			return values
		}
	}
	return append(values, value)
}

// CleanupStepIndexes returns completed stateful steps in reverse order.
func CleanupStepIndexes(document Document, receipt Receipt) []int {
	var indexes []int
	ordered := make([]int, 0, len(document.Steps))
	if IsDAG(document) {
		order, err := TopologicalOrder(document)
		if err == nil {
			for _, id := range order {
				for index := range document.Steps {
					if document.Steps[index].ID == id {
						ordered = append(ordered, index)
						break
					}
				}
			}
		}
	} else if len(receipt.ActualPath) > 0 {
		for _, id := range receipt.ActualPath {
			for index := range document.Steps {
				if document.Steps[index].ID == id {
					ordered = append(ordered, index)
					break
				}
			}
		}
	} else {
		for index := range document.Steps {
			ordered = append(ordered, index)
		}
	}
	for position := len(ordered) - 1; position >= 0; position-- {
		index := ordered[position]
		if index >= len(receipt.Steps) {
			continue
		}
		step, state := document.Steps[index], receipt.Steps[index]
		parallelCleanup := false
		if step.Parallel != nil && state.Parallel != nil {
			for branchIndex, branch := range step.Parallel.Branches {
				if branchIndex >= len(state.Parallel.Branches) {
					continue
				}
				branchState := state.Parallel.Branches[branchIndex]
				childCleanup := branch.Operation != "" && branchState.ChildReceipt != "" && branchState.ChildCleanupState != "completed"
				packCleanup := branch.Cleanup != nil && branchState.CleanupState != "completed" && cleanupReferencesAvailable(branch.Cleanup, mergeCaptures(receipt.Captures, branchState.Captures))
				if branchState.State == "completed" && (childCleanup || packCleanup) {
					parallelCleanup = true
					break
				}
			}
		}
		childCleanup := step.Operation != "" && state.ChildReceipt != "" && state.ChildCleanupState != "completed"
		packCleanup := step.Cleanup != nil && state.CleanupState != "completed" && cleanupReferencesAvailable(step.Cleanup, receipt.Captures)
		if (state.State == "completed" || state.State == "failed" || state.State == "incomplete") && (parallelCleanup || childCleanup || packCleanup) {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func mergeCaptures(parent, local map[string]string) map[string]string {
	result := map[string]string{}
	for name, value := range parent {
		result[name] = value
	}
	for name, value := range local {
		result[name] = value
	}
	return result
}

func cleanupReferencesAvailable(cleanup *Cleanup, captures map[string]string) bool {
	for _, value := range cleanup.Arguments {
		if strings.HasPrefix(value, "$capture.") && captures[strings.TrimPrefix(value, "$capture.")] == "" {
			return false
		}
		if strings.HasPrefix(value, "$step.") {
			parts := strings.Split(strings.TrimPrefix(value, "$step."), ".")
			if len(parts) == 2 && captures[parts[1]] == "" {
				return false
			}
		}
	}
	return true
}

// EvaluateOutcomes returns the first ordered result route whose expectation
// matches. A mismatch is not a runtime failure; it is simply considered for
// the next declared outcome.
func EvaluateOutcomes(lines []string, outcomes []Outcome, inputs, captures, topology map[string]string) (Outcome, []string, bool, error) {
	var failures []string
	for _, outcome := range outcomes {
		fields, payload, err := EvaluateExpectation(lines, &outcome.Expect, inputs, captures, topology)
		if err == nil {
			return outcome, fields, payload, nil
		}
		failures = append(failures, outcome.ID)
	}
	return Outcome{}, nil, false, fmt.Errorf("structured output matched no outcome (%s)", strings.Join(failures, ", "))
}

// ClassifyExecution converts a runtime result into operation step and receipt
// states without treating submission as completion.
func ClassifyExecution(executionState string, outputComplete, failed bool) (string, string) {
	if executionState == "canceled" || executionState == "cancelled" {
		return "canceled", "canceled"
	}
	if failed || executionState == "failed" || executionState == "timeout" {
		return "failed", "failed"
	}
	if !outputComplete || executionState == "submitted" || executionState == "running" {
		return "incomplete", "incomplete"
	}
	return "completed", "running"
}

func CaptureOutput(lines []string, captures map[string]Capture) (map[string]string, error) {
	result := map[string]string{}
	for name, capture := range captures {
		found := false
		for _, line := range lines {
			tag, fields := parseStructuredLine(line)
			if tag != capture.Tag {
				continue
			}
			if value, ok := fields[capture.Field]; ok {
				result[name] = value
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("capture %s did not find [%s] field %s", name, capture.Tag, capture.Field)
		}
	}
	return result, nil
}

// CaptureAvailableOutput records captures present on a selected result route.
// A fallback result may intentionally omit fields produced only by a primary
// path; later steps still fail normally if they reference a missing capture.
func CaptureAvailableOutput(lines []string, captures map[string]Capture) map[string]string {
	result := map[string]string{}
	for name, capture := range captures {
		for _, line := range lines {
			tag, fields := parseStructuredLine(line)
			if tag == capture.Tag && fields[capture.Field] != "" {
				result[name] = fields[capture.Field]
				break
			}
		}
	}
	return result
}

// CaptureChildOutput exports selected non-sensitive captures from a completed
// child operation into the parent receipt.
func CaptureChildOutput(child Receipt, captures map[string]Capture) (map[string]string, error) {
	result := map[string]string{}
	for name, capture := range captures {
		value, ok := child.Captures[capture.Capture]
		if !ok || value == "" {
			return nil, fmt.Errorf("capture %s did not find child capture %s", name, capture.Capture)
		}
		result[name] = value
	}
	return result, nil
}

// EvaluateExpectation verifies a completed step's structured output. Payload
// bytes are checked in memory and are never added to operation receipts.
func EvaluateExpectation(lines []string, expectation *packsvc.ProofExpectation, inputs, captures, topology map[string]string) ([]string, bool, error) {
	if expectation == nil {
		return nil, false, nil
	}
	matchedFields := []string{}
	matched := false
	for _, line := range lines {
		tag, fields := parseStructuredLine(line)
		if tag != expectation.Tag {
			continue
		}
		ok := true
		matchedFields = matchedFields[:0]
		for name, raw := range expectation.Fields {
			expected := raw
			if raw != "*" {
				var err error
				expected, err = ResolveValue(raw, inputs, captures, topology)
				if err != nil {
					return nil, false, err
				}
			}
			actual, exists := fields[name]
			if !exists || (expected != "*" && actual != expected) {
				ok = false
				break
			}
			matchedFields = append(matchedFields, name)
		}
		if ok {
			matched = true
			break
		}
	}
	if !matched {
		return nil, false, fmt.Errorf("structured output did not match [%s] contract", expectation.Tag)
	}
	sort.Strings(matchedFields)
	payloadVerified := false
	if payload := expectation.Payload; payload != nil {
		var encoded strings.Builder
		for _, line := range lines {
			tag, fields := parseStructuredLine(line)
			if tag == payload.Tag {
				if value := fields[payload.Field]; value != "" && value != "<redacted>" {
					encoded.WriteString(value)
				}
			}
		}
		if encoded.Len() == 0 {
			return nil, false, fmt.Errorf("payload contract found no [%s] field %s", payload.Tag, payload.Field)
		}
		var data []byte
		var err error
		switch payload.Encoding {
		case "hex":
			data, err = hex.DecodeString(encoded.String())
		case "base64":
			data, err = base64.StdEncoding.DecodeString(encoded.String())
		}
		if err != nil {
			return nil, false, fmt.Errorf("decode %s payload: %w", payload.Encoding, err)
		}
		expected, err := ResolveValue(payload.SHA256, inputs, captures, topology)
		if err != nil {
			return nil, false, err
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), expected) {
			return nil, false, fmt.Errorf("payload SHA-256 did not match contract")
		}
		payloadVerified = true
	}
	return matchedFields, payloadVerified, nil
}

func parseStructuredLine(line string) (string, map[string]string) {
	line = strings.TrimSpace(line)
	start, end := strings.Index(line, "["), strings.Index(line, "]")
	if start < 0 || end <= start {
		return "", nil
	}
	fields := map[string]string{}
	for _, token := range strings.Fields(line[end+1:]) {
		if key, value, ok := strings.Cut(token, "="); ok {
			fields[key] = strings.Trim(value, `"'`)
		}
	}
	return line[start+1 : end], fields
}

func NewReceipt(item Resolved, registry *Registry, path, runtime, lab, topology, arch, compiler string, inputs map[string]string) Receipt {
	receipt := Receipt{Schema: ReceiptSchema, SchemaVersion: ReceiptSchemaVersion, Operation: item.Qualified, OperationSHA256: item.SHA256, Status: "pending", Runtime: runtime, Lab: lab, Topology: topology, Architecture: arch, Compiler: compiler, Inputs: map[string]string{}, Captures: map[string]string{}, DependencySHA256: map[string]string{}, Path: path, StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Execution: ExecutionMode(item.Document), ControllerPID: os.Getpid(), ControlPath: filepath.Join(filepath.Dir(path), "control.json")}
	receipt.DependencySHA256 = registry.DependencyHashes(item)
	receipt.TopologicalOrder, _ = TopologicalOrder(item.Document)
	for _, input := range item.Document.Inputs {
		if input.Sensitive {
			if value, ok := inputs[input.Name]; ok && value != "" {
				receipt.RedactedInputs = append(receipt.RedactedInputs, input.Name)
			}
			continue
		}
		if value, ok := inputs[input.Name]; ok {
			receipt.Inputs[input.Name] = value
		}
	}
	sort.Strings(receipt.RedactedInputs)
	for _, step := range item.Document.Steps {
		if step.Parallel != nil {
			parallel := &ParallelReceipt{Join: step.Parallel.Join, State: "pending", Exports: map[string]string{}}
			for _, branch := range step.Parallel.Branches {
				parallel.Branches = append(parallel.Branches, newInvocationReceipt(branch.ID, branch.Pack, branch.Operation, branch.Cleanup, registry))
			}
			state := StepReceipt{ID: step.ID, State: "pending", ContractState: "pending", DependsOn: append([]string(nil), step.DependsOn...), DependsOnReady: append([]string(nil), step.DependsOnReady...), Mode: emptyDefault(step.Mode, "foreground"), ReadyState: "pending", ReadyContractState: "pending", Parallel: parallel}
			if step.FanOut != nil {
				state.FanOut = &FanOutReceipt{Source: step.FanOut.Source, Items: append([]string(nil), step.FanOut.ResolvedItems...), MaxItems: step.FanOut.MaxItems, State: "pending"}
				SyncFanOutReceipt(step, &state)
			}
			receipt.Steps = append(receipt.Steps, state)
			continue
		}
		state := newInvocationReceipt(step.ID, step.Pack, step.Operation, step.Cleanup, registry)
		state.DependsOn = append([]string(nil), step.DependsOn...)
		state.DependsOnReady = append([]string(nil), step.DependsOnReady...)
		state.Mode = emptyDefault(step.Mode, "foreground")
		state.ReadyState, state.ReadyContractState = "pending", "pending"
		state.Attempt, state.MaxAttempts = 1, 1
		if step.Retry != nil {
			state.MaxAttempts = step.Retry.MaxAttempts
		}
		receipt.Steps = append(receipt.Steps, state)
	}
	return receipt
}

func newInvocationReceipt(id, packName, operationName string, cleanup *Cleanup, registry *Registry) StepReceipt {
	hash, operationHash := "", ""
	if packName != "" {
		if resolved, err := registry.packRegistry.Resolve(packName); err == nil {
			hash = resolved.SHA256
		}
	} else if operationName != "" {
		if resolved, err := registry.Resolve(operationName); err == nil {
			operationHash = resolved.SHA256
		}
	}
	cleanupPack, cleanupHash := "", ""
	if cleanup != nil {
		cleanupPack = cleanup.Pack
		if resolved, err := registry.packRegistry.Resolve(cleanup.Pack); err == nil {
			cleanupHash = resolved.SHA256
		}
	}
	return StepReceipt{ID: id, Pack: packName, PackSHA256: hash, Operation: operationName, OperationSHA256: operationHash, CleanupPack: cleanupPack, CleanupSHA256: cleanupHash, State: "pending", ContractState: "pending"}
}

// DependencyHashes pins the complete operation/pack closure used by a run.
func (r *Registry) DependencyHashes(item Resolved) map[string]string {
	result, seen := map[string]string{}, map[string]bool{}
	var walk func(Resolved)
	walk = func(current Resolved) {
		if seen[current.Qualified] {
			return
		}
		seen[current.Qualified] = true
		result["operation:"+current.Qualified] = current.SHA256
		for _, step := range current.Document.Steps {
			if step.Parallel != nil {
				for _, branch := range step.Parallel.Branches {
					if branch.Pack != "" {
						if pack, err := r.packRegistry.Resolve(branch.Pack); err == nil {
							result["pack:"+pack.Qualified] = pack.SHA256
						}
					}
					if branch.Cleanup != nil {
						if pack, err := r.packRegistry.Resolve(branch.Cleanup.Pack); err == nil {
							result["pack:"+pack.Qualified] = pack.SHA256
						}
					}
					if branch.Operation != "" {
						if child, err := r.Resolve(branch.Operation); err == nil {
							walk(child)
						}
					}
				}
				continue
			}
			if step.Pack != "" {
				if pack, err := r.packRegistry.Resolve(step.Pack); err == nil {
					result["pack:"+pack.Qualified] = pack.SHA256
				}
			}
			if step.Cleanup != nil {
				if pack, err := r.packRegistry.Resolve(step.Cleanup.Pack); err == nil {
					result["pack:"+pack.Qualified] = pack.SHA256
				}
			}
			if step.Operation != "" {
				if child, err := r.Resolve(step.Operation); err == nil {
					walk(child)
				}
			}
		}
	}
	walk(item)
	return result
}

func SaveReceipt(path string, receipt *Receipt) error {
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.Path = path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".operation-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func LoadReceipt(path string) (Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return Receipt{}, err
	}
	if receipt.Schema != ReceiptSchema || receipt.SchemaVersion < MinimumReceiptVersion || receipt.SchemaVersion > ReceiptSchemaVersion {
		return Receipt{}, fmt.Errorf("unsupported operation receipt schema")
	}
	if receipt.SchemaVersion < ReceiptSchemaVersion {
		previous := receipt.SchemaVersion
		receipt.SchemaVersion = ReceiptSchemaVersion
		for index := range receipt.Steps {
			if receipt.Steps[index].Attempt == 0 {
				receipt.Steps[index].Attempt, receipt.Steps[index].MaxAttempts = 1, 1
			}
			if previous == 1 && receipt.Steps[index].State == "completed" {
				receipt.Steps[index].ContractState = "legacy"
			}
			if receipt.Steps[index].State == "completed" {
				receipt.ActualPath = appendUnique(receipt.ActualPath, receipt.Steps[index].ID)
				receipt.ExpandedPath = appendUnique(receipt.ExpandedPath, receipt.Steps[index].ID)
			}
			if receipt.Steps[index].State == "skipped" {
				receipt.SkippedSteps = appendUnique(receipt.SkippedSteps, receipt.Steps[index].ID)
			}
		}
	}
	if receipt.Execution == "" {
		receipt.Execution = "linear"
	}
	if len(receipt.TopologicalOrder) == 0 {
		for _, step := range receipt.Steps {
			receipt.TopologicalOrder = append(receipt.TopologicalOrder, step.ID)
		}
	}
	return receipt, nil
}

// RefreshRuntimeReceipt reloads the adapter receipt referenced by an
// incomplete operation step. This lets an external C2 task collector update
// task state without causing operation resume to submit the BOF a second time.
func RefreshRuntimeReceipt(current runtimeadapter.Receipt) (runtimeadapter.Receipt, error) {
	if strings.TrimSpace(current.ReceiptPath) == "" {
		return current, nil
	}
	data, err := os.ReadFile(current.ReceiptPath)
	if err != nil {
		return current, err
	}
	var updated runtimeadapter.Receipt
	if err := json.Unmarshal(data, &updated); err != nil {
		return current, err
	}
	normalized, err := runtimeadapter.NormalizeReceipt(updated)
	if err != nil {
		return current, fmt.Errorf("%w at %s", err, current.ReceiptPath)
	}
	return normalized, nil
}

func Fingerprint(document Document) string {
	data, _ := json.Marshal(document)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func projectDir(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

func builtins() []Resolved {
	triage := Document{Schema: Schema, SchemaVersion: 2, ID: "process-triage", Version: "2.0.0", Title: "Process Triage", Summary: "Inspect a selected process, its loaded images, thread state, and security context", Tier: "public", Inputs: []Input{{Name: "target_pid", Type: "int", Required: true, Description: "exact process identifier"}, {Name: "result_limit", Type: "int", Default: "32"}}, Steps: []Step{
		{ID: "images", Pack: "process-image-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "module_filter": "", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "process-image-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		{ID: "threads", Pack: "thread-state-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "thread-state-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		{ID: "security", Pack: "process-security-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid"}, Expect: &packsvc.ProofExpectation{Tag: "process-security-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
	}, ProofCases: []ProofCase{{ID: "target-process", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}}}}
	network := Document{Schema: Schema, SchemaVersion: 2, ID: "network-posture", Version: "1.0.0", Title: "Network Posture", Summary: "Inventory local adapters, forwarding routes, and proxy configuration", Tier: "public", Inputs: []Input{{Name: "family", Type: "string", Default: "all"}, {Name: "result_limit", Type: "int", Default: "32"}}, Steps: []Step{
		{ID: "adapters", Pack: "network-adapter-inventory", Arguments: map[string]string{"family": "$input.family", "interface_filter": "", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "network-adapter-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		{ID: "routes", Pack: "network-route-inventory", Arguments: map[string]string{"family": "$input.family", "interface_index": "0", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "network-route-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		{ID: "proxy", Pack: "proxy-configuration-inventory", Expect: &packsvc.ProofExpectation{Tag: "proxy-configuration-inventory", Fields: map[string]string{"status": "complete"}}},
	}, ProofCases: []ProofCase{{ID: "local-network", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"family": "all", "result_limit": "16"}}}}
	waitTriage := Document{Schema: Schema, SchemaVersion: 3, ID: "wait-chain-triage", Version: "1.0.0", Title: "Wait Chain Triage", Summary: "Correlate process images, thread state, handle types, and Windows wait chains for an exact process", Tier: "public", Inputs: []Input{{Name: "target_pid", Type: "int", Required: true}, {Name: "target_tid", Type: "int", Default: "0"}, {Name: "result_limit", Type: "int", Default: "32"}}, Steps: []Step{
		{ID: "process", Pack: "process-image-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "module_filter": "", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "process-image-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		{ID: "threads", Pack: "thread-state-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "thread-state-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		{ID: "handles", Pack: "process-handle-type-summary", Arguments: map[string]string{"target_pid": "$input.target_pid", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "process-handle-type-summary", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		{ID: "waits", Pack: "thread-wait-chain-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "target_tid": "$input.target_tid", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "thread-wait-chain-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
	}, ProofCases: []ProofCase{{ID: "target-waits", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"target_pid": "$TARGET_PID", "target_tid": "$TARGET_TID", "result_limit": "16"}, ExpectPath: []string{"process", "threads", "handles", "waits"}}}}
	coordination := Document{Schema: Schema, SchemaVersion: 4, ID: "coordination-surface-triage", Version: "1.0.0", Title: "Coordination Surface Triage", Summary: "Correlate detailed process handles, exact synchronization state, and the local mailslot namespace", Tier: "public", Inputs: []Input{{Name: "target_pid", Type: "int", Required: true}, {Name: "handle_type", Type: "string", Default: "Mutant"}, {Name: "object_type", Type: "string", Required: true}, {Name: "object_name", Type: "wstring", Required: true}, {Name: "mailslot_prefix", Type: "wstring", Default: "BOFBench"}, {Name: "result_limit", Type: "int", Default: "32"}}, Steps: []Step{
		{ID: "handles", Pack: "process-handle-detail-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "type_filter": "$input.handle_type", "name_filter": "BOFBench", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "process-handle-detail-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid", "shown": "*"}}},
		{ID: "state", Pack: "synchronization-object-state", Arguments: map[string]string{"object_type": "$input.object_type", "object_name": "$input.object_name"}, Expect: &packsvc.ProofExpectation{Tag: "synchronization-object-state", Fields: map[string]string{"status": "complete", "object_type": "$input.object_type"}}},
		{ID: "mailslots", Pack: "mailslot-inventory", Arguments: map[string]string{"prefix": "$input.mailslot_prefix", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "mailslot-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
	}, ProofCases: []ProofCase{{ID: "target-coordination", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"target_pid": "$TARGET_HOLDER_PID", "handle_type": "Mutant", "object_type": "mutex", "object_name": "$TARGET_MUTEX_NAME", "mailslot_prefix": "BOFBench", "result_limit": "16"}, ExpectPath: []string{"handles", "state", "mailslots"}, ExpectExpandedPath: []string{"handles", "state", "mailslots"}}}}
	ipc := Document{
		Schema: Schema, SchemaVersion: 5, ID: "ipc-surface-triage", Version: "1.0.0",
		Title: "IPC Surface Triage", Summary: "Inventory RPC endpoints, COM registrations, and ALPC ports concurrently", Tier: "public",
		Inputs: []Input{
			{Name: "result_limit", Type: "int", Default: "32"},
			{Name: "com_scope", Type: "string", Default: "all"},
			{Name: "registry_view", Type: "string", Default: "native"},
			{Name: "clsid_filter", Type: "wstring", Default: ""},
			{Name: "alpc_directory", Type: "wstring", Default: `\RPC Control`},
			{Name: "alpc_prefix", Type: "wstring", Default: ""},
		},
		Steps: []Step{{
			ID: "surfaces",
			Parallel: &Parallel{
				Join: "all",
				Branches: []ParallelBranch{
					{ID: "rpc", Pack: "rpc-endpoint-inventory", Arguments: map[string]string{"result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "rpc-endpoint-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
					{ID: "com", Pack: "com-registration-inventory", Arguments: map[string]string{"scope": "$input.com_scope", "registry_view": "$input.registry_view", "clsid_filter": "$input.clsid_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "com-registration-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
					{ID: "alpc", Pack: "alpc-port-inventory", Arguments: map[string]string{"directory": "$input.alpc_directory", "prefix": "$input.alpc_prefix", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "alpc-port-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
				},
			},
		}},
		ProofCases: []ProofCase{{
			ID: "local-ipc", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"},
			Inputs:     map[string]string{"result_limit": "16", "com_scope": "all", "registry_view": "native", "clsid_filter": "", "alpc_directory": `\RPC Control`, "alpc_prefix": ""},
			ExpectPath: []string{"surfaces"}, ExpectExpandedPath: []string{"surfaces", "surfaces/rpc", "surfaces/com", "surfaces/alpc", "surfaces/$join"},
			ExpectParallel: map[string]map[string]string{"surfaces": {"rpc": "completed", "com": "completed", "alpc": "completed"}},
		}},
	}
	ipcActivation := Document{
		Schema: Schema, SchemaVersion: 6, Execution: "dag", ID: "ipc-activation-triage", Version: "1.0.0",
		Title: "IPC and Activation Triage", Summary: "Inventory RPC, COM registration, active COM monikers, ALPC ports, and windows as one dependency-aware ready wave", Tier: "public",
		Inputs: []Input{
			{Name: "result_limit", Type: "int", Default: "32"},
			{Name: "rpc_interface_filter", Type: "string", Default: ""},
			{Name: "rpc_protocol_filter", Type: "string", Default: ""},
			{Name: "rpc_annotation_filter", Type: "string", Default: ""},
			{Name: "com_scope", Type: "string", Default: "all"},
			{Name: "registry_view", Type: "string", Default: "native"},
			{Name: "clsid_filter", Type: "wstring", Default: ""},
			{Name: "rot_filter", Type: "string", Default: ""},
			{Name: "alpc_directory", Type: "wstring", Default: `\RPC Control`},
			{Name: "alpc_prefix", Type: "wstring", Default: ""},
			{Name: "window_scope", Type: "string", Default: "all"},
			{Name: "window_class_filter", Type: "wstring", Default: ""},
			{Name: "window_title_filter", Type: "wstring", Default: ""},
		},
		Steps: []Step{
			{ID: "rpc", Pack: "rpc-endpoint-inventory", Arguments: map[string]string{"interface_filter": "$input.rpc_interface_filter", "protocol_filter": "$input.rpc_protocol_filter", "annotation_filter": "$input.rpc_annotation_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "rpc-endpoint-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "com-registration", Pack: "com-registration-inventory", Arguments: map[string]string{"scope": "$input.com_scope", "registry_view": "$input.registry_view", "clsid_filter": "$input.clsid_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "com-registration-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "rot", Pack: "com-running-object-inventory", Arguments: map[string]string{"display_filter": "$input.rot_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "com-running-object-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "alpc", Pack: "alpc-port-inventory", Arguments: map[string]string{"directory": "$input.alpc_directory", "prefix": "$input.alpc_prefix", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "alpc-port-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "windows", Pack: "window-inventory", Arguments: map[string]string{"scope": "$input.window_scope", "class_filter": "$input.window_class_filter", "title_filter": "$input.window_title_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "window-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{
			ID: "target-ipc", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"},
			Inputs:      map[string]string{"result_limit": "16", "rpc_interface_filter": "", "rpc_protocol_filter": "", "rpc_annotation_filter": "", "com_scope": "all", "registry_view": "native", "clsid_filter": "", "rot_filter": "", "alpc_directory": `\RPC Control`, "alpc_prefix": "BOFBench", "window_scope": "top", "window_class_filter": "$TARGET_WINDOW_CLASS", "window_title_filter": ""},
			ExpectWaves: [][]string{{"rpc", "com-registration", "rot", "alpc", "windows"}},
			ExpectSteps: map[string]string{"rpc": "completed", "com-registration": "completed", "rot": "completed", "alpc": "completed", "windows": "completed"},
		}},
	}
	eventing := Document{
		Schema: Schema, SchemaVersion: 7, Execution: "dag", ID: "windows-eventing-posture", Version: "1.0.0",
		Title: "Windows Eventing Posture", Summary: "Inventory Event Log channels, query bounded events, and enumerate ETW providers as concurrent roots", Tier: "public",
		Inputs: []Input{
			{Name: "channel_filter", Type: "wstring", Default: "System"},
			{Name: "channel", Type: "wstring", Default: "System"},
			{Name: "xpath", Type: "wstring", Default: "*"},
			{Name: "provider_filter", Type: "wstring", Default: ""},
			{Name: "result_limit", Type: "int", Default: "16"},
		},
		Steps: []Step{
			{ID: "channels", Pack: "event-log-channel-inventory", Arguments: map[string]string{"channel_filter": "$input.channel_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "event-log-channel-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "events", Pack: "event-log-query", Arguments: map[string]string{"path": "$input.channel", "xpath": "$input.xpath", "direction": "reverse", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "event-log-query", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "providers", Pack: "etw-provider-inventory", Arguments: map[string]string{"name_filter": "$input.provider_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "etw-provider-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{
			ID: "local-eventing", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"},
			Inputs:      map[string]string{"channel_filter": "System", "channel": "System", "xpath": "*", "provider_filter": "", "result_limit": "8"},
			ExpectWaves: [][]string{{"channels", "events", "providers"}},
			ExpectSteps: map[string]string{"channels": "completed", "events": "completed", "providers": "completed"},
		}},
	}
	networkConnectivity := Document{
		Schema: Schema, SchemaVersion: 8, Execution: "dag", ID: "network-connectivity-triage", Version: "1.0.0",
		Title: "Network Connectivity Triage", Summary: "Inventory local network profiles, socket endpoints, and DNS cache state as one concurrent ready wave", Tier: "public",
		Inputs: []Input{{Name: "protocol", Type: "string", Default: "all"}, {Name: "family", Type: "string", Default: "all"}, {Name: "result_limit", Type: "int", Default: "32"}},
		Steps: []Step{
			{ID: "profiles", Pack: "network-profile-inventory", Arguments: map[string]string{"result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "network-profile-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "sockets", Pack: "socket-endpoint-inventory", Arguments: map[string]string{"protocol": "$input.protocol", "family": "$input.family", "pid": "0", "state": "0", "local_port": "0", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "socket-endpoint-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "dns-cache", Pack: "dns-cache-inventory", Arguments: map[string]string{"name_filter": "", "record_type": "0", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "dns-cache-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{ID: "local-connectivity", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"protocol": "all", "family": "all", "result_limit": "32"}, ExpectWaves: [][]string{{"profiles", "sockets", "dns-cache"}}, ExpectSteps: map[string]string{"profiles": "completed", "sockets": "completed", "dns-cache": "completed"}}},
	}
	secureNetwork := Document{
		Schema: Schema, SchemaVersion: 9, Execution: "dag", ID: "secure-network-posture", Version: "1.0.0",
		Title: "Secure Network Posture", Summary: "Inspect one HTTPS endpoint certificate and response metadata while inventorying current-user BITS jobs", Tier: "public",
		Inputs: []Input{{Name: "https_url", Type: "wstring", Required: true}, {Name: "allow_invalid", Type: "int", Default: "0"}, {Name: "bits_filter", Type: "wstring", Default: ""}, {Name: "result_limit", Type: "int", Default: "16"}},
		Steps: []Step{
			{ID: "certificate", Pack: "tls-certificate-inventory", Arguments: map[string]string{"url": "$input.https_url", "allow_invalid": "$input.allow_invalid", "timeout_ms": "10000"}, Expect: &packsvc.ProofExpectation{Tag: "tls-certificate-inventory", Fields: map[string]string{"status": "complete", "sha256": "*"}}},
			{ID: "response", Pack: "http-response-metadata", Arguments: map[string]string{"url": "$input.https_url", "method": "HEAD", "follow_redirects": "0", "allow_invalid": "$input.allow_invalid", "timeout_ms": "10000"}, Expect: &packsvc.ProofExpectation{Tag: "http-response-metadata", Fields: map[string]string{"status": "complete", "http_status": "200"}}},
			{ID: "bits", Pack: "bits-job-inventory", Arguments: map[string]string{"name_filter": "$input.bits_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "bits-job-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{ID: "fixture-https", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"https_url": "$TARGET_HTTPS_BLOB_URL", "allow_invalid": "1", "bits_filter": "BOFBench", "result_limit": "16"}, ExpectWaves: [][]string{{"certificate", "response", "bits"}}, ExpectSteps: map[string]string{"certificate": "completed", "response": "completed", "bits": "completed"}}},
	}
	filesystemSMB := Document{
		Schema: Schema, SchemaVersion: 10, Execution: "dag", ID: "filesystem-and-smb-posture", Version: "1.0.0",
		Title: "Filesystem and SMB Posture", Summary: "Inspect NTFS streams, reparse metadata, and active SMB connections as one concurrent ready wave", Tier: "public",
		Inputs: []Input{{Name: "path", Type: "wstring", Required: true}, {Name: "stream_filter", Type: "wstring", Default: ""}, {Name: "remote_filter", Type: "wstring", Default: ""}, {Name: "result_limit", Type: "int", Default: "32"}},
		Steps: []Step{
			{ID: "streams", Pack: "file-stream-inventory", Arguments: map[string]string{"path": "$input.path", "stream_filter": "$input.stream_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "file-stream-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "reparse", Pack: "file-reparse-point-inventory", Arguments: map[string]string{"path": "$input.path"}, Expect: &packsvc.ProofExpectation{Tag: "file-reparse-point-inventory", Fields: map[string]string{"status": "complete", "reparse": "*"}}},
			{ID: "smb", Pack: "smb-connection-inventory", Arguments: map[string]string{"remote_filter": "$input.remote_filter", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "smb-connection-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{ID: "canary-filesystem", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"path": "$CANARY_PATH", "stream_filter": "", "remote_filter": "", "result_limit": "16"}, ExpectWaves: [][]string{{"streams", "reparse", "smb"}}, ExpectSteps: map[string]string{"streams": "completed", "reparse": "completed", "smb": "completed"}}},
	}
	domainIdentity := Document{
		Schema: Schema, SchemaVersion: 11, Execution: "dag", ID: "domain-identity-posture", Version: "1.0.0", Title: "Domain Identity Posture", Summary: "Inventory Active Directory sites, organizational units, managed service accounts, and Kerberos policy as concurrent domain queries", Tier: "public", Roles: []string{"execution", "domain_controller"},
		Inputs: []Input{{Name: "server", Type: "string", TopologyValue: "domain_controller.computer_name"}, {Name: "base_dn", Type: "string", Default: ""}, {Name: "result_limit", Type: "int", Default: "50"}},
		Steps: []Step{
			{ID: "sites", Pack: "ad-site-inventory", Arguments: map[string]string{"server": "$input.server", "base_dn": "$input.base_dn", "filter": "(|(objectClass=site)(objectClass=subnet))", "attributes": "distinguishedName,name,location,siteObject", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "ldap-query", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "ous", Pack: "ldap-ou-inventory", Arguments: map[string]string{"server": "$input.server", "base_dn": "$input.base_dn", "filter": "(objectClass=organizationalUnit)", "attributes": "distinguishedName,name,gPLink,gPOptions", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "ldap-query", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "service-accounts", Pack: "ldap-managed-service-account-inventory", Arguments: map[string]string{"server": "$input.server", "base_dn": "$input.base_dn", "filter": "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))", "attributes": "distinguishedName,sAMAccountName,dNSHostName,servicePrincipalName", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "ldap-query", Fields: map[string]string{"status": "complete", "shown": "*"}}},
			{ID: "kerberos-policy", Pack: "kerberos-policy-inventory", Arguments: map[string]string{"server": "$input.server", "base_dn": "$input.base_dn", "filter": "(objectClass=domainDNS)", "attributes": "distinguishedName,maxTicketAge,maxRenewAge,maxServiceAge,maxClockSkew", "result_limit": "4"}, Expect: &packsvc.ProofExpectation{Tag: "ldap-query", Fields: map[string]string{"status": "complete", "shown": "*"}}},
		},
		ProofCases: []ProofCase{{ID: "domain", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Roles: []string{"execution", "domain_controller"}, Inputs: map[string]string{"server": "$LAB_HOST", "base_dn": "", "result_limit": "25"}, ExpectWaves: [][]string{{"sites", "ous", "service-accounts", "kerberos-policy"}}, ExpectSteps: map[string]string{"sites": "completed", "ous": "completed", "service-accounts": "completed", "kerberos-policy": "completed"}}},
	}
	remotePosture := Document{
		Schema: Schema, SchemaVersion: 11, Execution: "dag", ID: "remote-host-posture", Version: "1.0.0", Title: "Remote Host Posture", Summary: "Inspect exact-host identity, Event Log, share permissions, and firewall policy as one bounded remote operation", Tier: "public", Roles: []string{"execution", "target"},
		Inputs: []Input{{Name: "target_host", Type: "wstring", TopologyValue: "target.computer_name"}, {Name: "result_limit", Type: "int", Default: "16"}},
		Steps: []Step{
			{ID: "identity", Pack: "remote-host-info", Arguments: map[string]string{"target_host": "$input.target_host"}, Expect: &packsvc.ProofExpectation{Tag: "remote-host-info", Fields: map[string]string{"status": "complete", "target": "$input.target_host"}}},
			{ID: "events", Pack: "remote-event-log-query", Arguments: map[string]string{"target_host": "$input.target_host", "channel": "System", "xpath": "*", "direction": "reverse", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "remote-event-log-query", Fields: map[string]string{"status": "complete", "target": "$input.target_host"}}},
			{ID: "shares", Pack: "remote-share-permission-inventory", Arguments: map[string]string{"target_host": "$input.target_host", "share_filter": "", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "remote-share-permission-inventory", Fields: map[string]string{"status": "complete", "target": "$input.target_host"}}},
			{ID: "firewall", Pack: "remote-firewall-profile-inventory", Arguments: map[string]string{"target_host": "$input.target_host"}, Expect: &packsvc.ProofExpectation{Tag: "remote-firewall-profile-inventory", Fields: map[string]string{"status": "complete", "target": "$input.target_host"}}},
		},
		ProofCases: []ProofCase{{ID: "target", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Roles: []string{"execution", "target"}, Inputs: map[string]string{"target_host": "$LAB_HOST", "result_limit": "8"}, ExpectWaves: [][]string{{"identity", "events", "shares", "firewall"}}, ExpectSteps: map[string]string{"identity": "completed", "events": "completed", "shares": "completed", "firewall": "completed"}}},
	}
	executionSurface := Document{
		Schema: Schema, SchemaVersion: 11, Execution: "dag", ID: "process-execution-surface", Version: "1.0.0", Title: "Process Execution Surface", Summary: "Inspect mitigation policy, CFG executable regions, and instrumentation callback state for one exact process", Tier: "public",
		Inputs: []Input{{Name: "target_pid", Type: "int", Required: true}, {Name: "result_limit", Type: "int", Default: "32"}},
		Steps: []Step{
			{ID: "mitigations", Pack: "process-mitigation-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid"}, Expect: &packsvc.ProofExpectation{Tag: "process-mitigation-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
			{ID: "cfg", Pack: "process-cfg-target-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid", "result_limit": "$input.result_limit"}, Expect: &packsvc.ProofExpectation{Tag: "process-cfg-target-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
			{ID: "instrumentation", Pack: "process-instrumentation-callback-inventory", Arguments: map[string]string{"target_pid": "$input.target_pid"}, Expect: &packsvc.ProofExpectation{Tag: "process-instrumentation-callback-inventory", Fields: map[string]string{"status": "complete", "target_pid": "$input.target_pid"}}},
		},
		ProofCases: []ProofCase{{ID: "target", Via: []string{"lab", "sliver"}, Architectures: []string{"x64", "x86"}, Inputs: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}, ExpectWaves: [][]string{{"mitigations", "cfg", "instrumentation"}}, ExpectSteps: map[string]string{"mitigations": "completed", "cfg": "completed", "instrumentation": "completed"}}},
	}
	documents := []Document{triage, network, waitTriage, coordination, ipc, ipcActivation, eventing, networkConnectivity, secureNetwork, filesystemSMB, domainIdentity, remotePosture, executionSurface}
	items := make([]Resolved, 0, len(documents))
	for _, document := range documents {
		item := Resolved{Document: document, Catalog: "builtin", Qualified: "builtin/" + document.ID}
		item.SHA256 = Fingerprint(document)
		items = append(items, item)
	}
	return items
}

type GraphNode struct {
	ID               string   `json:"id"`
	Pack             string   `json:"pack,omitempty"`
	Operation        string   `json:"operation,omitempty"`
	Kind             string   `json:"kind"`
	FanOutSource     string   `json:"fan_out_source,omitempty"`
	FanOutMaxItems   int      `json:"fan_out_max_items,omitempty"`
	RetryMaxAttempts int      `json:"retry_max_attempts,omitempty"`
	RetryReasons     []string `json:"retry_reasons,omitempty"`
}

type GraphEdge struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Outcome string `json:"outcome,omitempty"`
}

type GraphDocument struct {
	Schema        string      `json:"schema"`
	SchemaVersion int         `json:"schema_version"`
	Operation     string      `json:"operation"`
	Nodes         []GraphNode `json:"nodes"`
	Edges         []GraphEdge `json:"edges"`
}

func Graph(document Document, format string) (string, error) {
	graph := graphDocument(document, "", nil, false)
	return renderGraph(graph, format)
}

// Graph renders a resolved operation. Expanded graphs retain the parent node
// and add slash-qualified child nodes and containment edges.
func (r *Registry) Graph(item Resolved, format string, expand bool) (string, error) {
	graph := graphDocument(item.Document, "", r, expand)
	return renderGraph(graph, format)
}

func graphDocument(document Document, prefix string, registry *Registry, expand bool) GraphDocument {
	graph := GraphDocument{Schema: "bofbench.operation-graph", SchemaVersion: 5, Operation: document.ID}
	if IsDAG(document) {
		graph.Nodes = append(graph.Nodes, GraphNode{ID: prefix + "$start", Kind: "start"})
		dependents := map[string]bool{}
		for _, step := range document.Steps {
			id := prefix + step.ID
			kind := "pack"
			if step.Operation != "" {
				kind = "operation"
			}
			node := GraphNode{ID: id, Pack: step.Pack, Operation: step.Operation, Kind: kind}
			if step.Retry != nil {
				node.RetryMaxAttempts = step.Retry.MaxAttempts
				for _, condition := range step.Retry.When {
					node.RetryReasons = append(node.RetryReasons, condition.ID)
				}
			}
			graph.Nodes = append(graph.Nodes, node)
			if len(step.DependsOn) == 0 {
				graph.Edges = append(graph.Edges, GraphEdge{From: prefix + "$start", To: id, Outcome: "ready"})
			}
			for _, dependency := range step.DependsOn {
				dependents[dependency] = true
				graph.Edges = append(graph.Edges, GraphEdge{From: prefix + dependency, To: id, Outcome: "depends"})
			}
			if expand && registry != nil && step.Operation != "" {
				if child, err := registry.Resolve(step.Operation); err == nil {
					childGraph := graphDocument(child.Document, id+"/", registry, true)
					graph.Nodes = append(graph.Nodes, childGraph.Nodes...)
					entry := id + "/" + child.Document.Steps[0].ID
					if IsDAG(child.Document) {
						entry = id + "/$start"
					}
					graph.Edges = append(graph.Edges, GraphEdge{From: id, To: entry, Outcome: "contains"})
					for _, edge := range childGraph.Edges {
						if edge.To == "$complete" || edge.To == "$fail" {
							edge.To = id
						}
						graph.Edges = append(graph.Edges, edge)
					}
				}
			}
		}
		for _, step := range document.Steps {
			if !dependents[step.ID] {
				graph.Edges = append(graph.Edges, GraphEdge{From: prefix + step.ID, To: "$complete"})
			}
		}
		return graph
	}
	for index, step := range document.Steps {
		id := prefix + step.ID
		kind := "pack"
		if step.Operation != "" {
			kind = "operation"
		} else if step.Parallel != nil {
			kind = "parallel"
		} else if step.FanOut != nil {
			kind = "fan-out"
		}
		node := GraphNode{ID: id, Pack: step.Pack, Operation: step.Operation, Kind: kind}
		if step.FanOut != nil {
			node.FanOutSource, node.FanOutMaxItems = step.FanOut.Source, step.FanOut.MaxItems
		}
		graph.Nodes = append(graph.Nodes, node)
		outgoing := id
		if step.Parallel != nil {
			joinID := id + "/$join"
			graph.Nodes = append(graph.Nodes, GraphNode{ID: joinID, Kind: "join"})
			outgoing = joinID
			for _, branch := range step.Parallel.Branches {
				branchID := id + "/" + branch.ID
				branchKind := "pack"
				if branch.Operation != "" {
					branchKind = "operation"
				}
				graph.Nodes = append(graph.Nodes, GraphNode{ID: branchID, Pack: branch.Pack, Operation: branch.Operation, Kind: branchKind})
				graph.Edges = append(graph.Edges, GraphEdge{From: id, To: branchID, Outcome: "fork"})
				graph.Edges = append(graph.Edges, GraphEdge{From: branchID, To: joinID, Outcome: "join"})
				if expand && registry != nil && branch.Operation != "" {
					if child, err := registry.Resolve(branch.Operation); err == nil {
						childGraph := graphDocument(child.Document, branchID+"/", registry, true)
						graph.Nodes = append(graph.Nodes, childGraph.Nodes...)
						graph.Edges = append(graph.Edges, GraphEdge{From: branchID, To: branchID + "/" + child.Document.Steps[0].ID, Outcome: "contains"})
						for _, edge := range childGraph.Edges {
							if edge.To == "$complete" || edge.To == "$fail" {
								edge.To = branchID
							}
							graph.Edges = append(graph.Edges, edge)
						}
					}
				}
			}
		}
		if len(step.Outcomes) > 0 {
			for _, outcome := range step.Outcomes {
				to := outcome.Next
				if !strings.HasPrefix(to, "$") {
					to = prefix + to
				}
				graph.Edges = append(graph.Edges, GraphEdge{From: id, To: to, Outcome: outcome.ID})
			}
		} else if index+1 < len(document.Steps) {
			graph.Edges = append(graph.Edges, GraphEdge{From: outgoing, To: prefix + document.Steps[index+1].ID})
		} else {
			graph.Edges = append(graph.Edges, GraphEdge{From: outgoing, To: "$complete"})
		}
		if expand && registry != nil && step.Operation != "" {
			if child, err := registry.Resolve(step.Operation); err == nil {
				childGraph := graphDocument(child.Document, id+"/", registry, true)
				graph.Nodes = append(graph.Nodes, childGraph.Nodes...)
				graph.Edges = append(graph.Edges, GraphEdge{From: id, To: id + "/" + child.Document.Steps[0].ID, Outcome: "contains"})
				for _, edge := range childGraph.Edges {
					if edge.To == "$complete" || edge.To == "$fail" {
						edge.To = id
					}
					graph.Edges = append(graph.Edges, edge)
				}
			}
		}
	}
	return graph
}

func renderGraph(graph GraphDocument, format string) (string, error) {
	switch strings.ToLower(format) {
	case "", "text":
		var body strings.Builder
		fmt.Fprintf(&body, "OPERATION GRAPH\noperation  %s\n", graph.Operation)
		for _, edge := range graph.Edges {
			label := ""
			if edge.Outcome != "" {
				label = " [" + edge.Outcome + "]"
			}
			fmt.Fprintf(&body, "%s -> %s%s\n", edge.From, edge.To, label)
		}
		return body.String(), nil
	case "mermaid":
		var body strings.Builder
		body.WriteString("flowchart TD\n")
		for _, node := range graph.Nodes {
			target := node.Pack
			if node.Operation != "" {
				target = node.Operation
			}
			if target == "" {
				target = node.Kind
			}
			if node.Kind == "fan-out" {
				target = fmt.Sprintf("fan-out %s · max %d · %s", node.FanOutSource, node.FanOutMaxItems, target)
			}
			if node.RetryMaxAttempts > 1 {
				target += fmt.Sprintf(" · retry≤%d (%s)", node.RetryMaxAttempts, strings.Join(node.RetryReasons, ","))
			}
			fmt.Fprintf(&body, "  %s[\"%s · %s\"]\n", mermaidID(node.ID), node.ID, strings.ReplaceAll(target, "\"", "'"))
		}
		body.WriteString("  complete([\"complete\"])\n  fail([\"fail\"])\n")
		for _, edge := range graph.Edges {
			to := mermaidID(edge.To)
			if edge.To == "$complete" {
				to = "complete"
			} else if edge.To == "$fail" {
				to = "fail"
			}
			if edge.Outcome != "" {
				fmt.Fprintf(&body, "  %s -- \"%s\" --> %s\n", mermaidID(edge.From), strings.ReplaceAll(edge.Outcome, "\"", "'"), to)
			} else {
				fmt.Fprintf(&body, "  %s --> %s\n", mermaidID(edge.From), to)
			}
		}
		return body.String(), nil
	case "json":
		data, err := json.MarshalIndent(graph, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	default:
		return "", fmt.Errorf("unsupported graph format %q; use text, mermaid, or json", format)
	}
}

func mermaidID(value string) string {
	value = strings.TrimPrefix(value, "$")
	value = strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(value)
	return "step_" + value
}

func ReferenceMarkdown(items []Resolved) string {
	var body strings.Builder
	body.WriteString("# Operation Reference\n\nGenerated from resolved `bofbench.operation` manifests.\n\n")
	for _, item := range items {
		fmt.Fprintf(&body, "## `%s`\n\n%s\n\n", item.Qualified, item.Document.Summary)
		fmt.Fprintf(&body, "- Schema version: `%d`\n- Execution: `%s`\n- Tier: `%s`\n- Steps: `%d`\n- Proof cases: `%d`\n\n", item.Document.SchemaVersion, ExecutionMode(item.Document), item.Document.Tier, len(item.Document.Steps), len(item.Document.ProofCases))
		if len(item.Document.Inputs) > 0 {
			body.WriteString("### Inputs\n\n| Name | Type | Required | Sensitive | Topology value |\n|---|---|---:|---:|---|\n")
			for _, in := range item.Document.Inputs {
				fmt.Fprintf(&body, "| `%s` | `%s` | %t | %t | `%s` |\n", in.Name, in.Type, in.Required, in.Sensitive, in.TopologyValue)
			}
			body.WriteString("\n")
		}
		body.WriteString("### Steps\n\n")
		for i, step := range item.Document.Steps {
			target := step.Pack
			if step.Operation != "" {
				target = "operation:" + step.Operation
			} else if step.Parallel != nil {
				target = fmt.Sprintf("parallel:%s (%d branches)", step.Parallel.Join, len(step.Parallel.Branches))
			} else if step.FanOut != nil {
				target = fmt.Sprintf("fan-out:%s → %s (max %d)", step.FanOut.Source, step.Pack, step.FanOut.MaxItems)
			}
			fmt.Fprintf(&body, "%d. `%s` → `%s`", i+1, step.ID, target)
			if len(step.DependsOn) > 0 {
				fmt.Fprintf(&body, "; depends on `%s`", strings.Join(step.DependsOn, "`, `"))
			}
			if step.Cleanup != nil {
				fmt.Fprintf(&body, "; cleanup `%s`", step.Cleanup.Pack)
			}
			body.WriteString("\n")
			if step.Parallel != nil {
				for _, branch := range step.Parallel.Branches {
					branchTarget := branch.Pack
					if branch.Operation != "" {
						branchTarget = "operation:" + branch.Operation
					}
					fmt.Fprintf(&body, "    - branch `%s` → `%s`\n", branch.ID, branchTarget)
				}
				for name, reference := range step.Parallel.Exports {
					fmt.Fprintf(&body, "    - export `%s` ← `%s`\n", name, reference)
				}
			}
			for _, outcome := range step.Outcomes {
				fmt.Fprintf(&body, "    - outcome `%s` → `%s` when `[%s]` matches\n", outcome.ID, outcome.Next, outcome.Expect.Tag)
			}
			if step.Retry != nil {
				var reasons []string
				for _, condition := range step.Retry.When {
					reasons = append(reasons, condition.ID)
				}
				fmt.Fprintf(&body, "    - retry: up to `%d` attempts, `%s` backoff from `%dms`, when `%s` matches\n", step.Retry.MaxAttempts, step.Retry.Backoff, step.Retry.DelayMS, strings.Join(reasons, "`, `"))
			}
		}
		if len(item.Document.ProofCases) > 0 {
			body.WriteString("\n### Proof cases\n\n")
			for _, proof := range item.Document.ProofCases {
				fmt.Fprintf(&body, "- `%s`: via `%s`, architectures `%s`", proof.ID, strings.Join(proof.Via, ","), strings.Join(proof.Architectures, ","))
				if len(proof.ExpectPath) > 0 {
					fmt.Fprintf(&body, ", expected path `%s`", strings.Join(proof.ExpectPath, " → "))
				}
				if len(proof.ExpectExpandedPath) > 0 {
					fmt.Fprintf(&body, ", expanded path `%s`", strings.Join(proof.ExpectExpandedPath, " → "))
				}
				if len(proof.ExpectWaves) > 0 {
					var waves []string
					for _, wave := range proof.ExpectWaves {
						waves = append(waves, strings.Join(wave, "+"))
					}
					fmt.Fprintf(&body, ", waves `%s`", strings.Join(waves, " → "))
				}
				body.WriteString("\n")
			}
		}
		body.WriteString("\n")
	}
	return body.String()
}
