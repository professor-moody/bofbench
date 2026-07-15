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

	packsvc "bofbench/internal/pack"
	"bofbench/internal/runtimeadapter"
)

const (
	Schema                = "bofbench.operation"
	SchemaVersion         = 2
	MinimumSchemaVersion  = 1
	ReceiptSchema         = "bofbench.operation-receipt"
	ReceiptSchemaVersion  = 2
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
	Tag   string `json:"tag"`
	Field string `json:"field"`
}

type Cleanup struct {
	Pack      string            `json:"pack"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type Step struct {
	ID        string                    `json:"id"`
	Pack      string                    `json:"pack"`
	Arguments map[string]string         `json:"arguments,omitempty"`
	Captures  map[string]Capture        `json:"captures,omitempty"`
	Cleanup   *Cleanup                  `json:"cleanup,omitempty"`
	Expect    *packsvc.ProofExpectation `json:"expect,omitempty"`
}

type ProofCase struct {
	ID             string                    `json:"id"`
	Via            []string                  `json:"via"`
	Architectures  []string                  `json:"architectures,omitempty"`
	Roles          []string                  `json:"roles,omitempty"`
	Inputs         map[string]string         `json:"inputs,omitempty"`
	ExpectCaptures map[string]string         `json:"expect_captures,omitempty"`
	Cleanup        bool                      `json:"cleanup,omitempty"`
	StateChecks    []packsvc.ProofStateCheck `json:"state_checks,omitempty"`
}

type Document struct {
	Schema        string      `json:"schema"`
	SchemaVersion int         `json:"schema_version"`
	ID            string      `json:"id"`
	Version       string      `json:"version"`
	Title         string      `json:"title"`
	Summary       string      `json:"summary"`
	Tier          string      `json:"tier"`
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
	ID              string                  `json:"id"`
	Pack            string                  `json:"pack"`
	PackSHA256      string                  `json:"pack_sha256"`
	CleanupPack     string                  `json:"cleanup_pack,omitempty"`
	CleanupSHA256   string                  `json:"cleanup_pack_sha256,omitempty"`
	State           string                  `json:"state"`
	ObjectSHA256    string                  `json:"object_sha256,omitempty"`
	OutputComplete  bool                    `json:"output_complete"`
	Runtime         runtimeadapter.Receipt  `json:"runtime_receipt,omitempty"`
	Captures        map[string]string       `json:"captures,omitempty"`
	Error           string                  `json:"error,omitempty"`
	CleanupState    string                  `json:"cleanup_state,omitempty"`
	CleanupRuntime  *runtimeadapter.Receipt `json:"cleanup_runtime_receipt,omitempty"`
	ContractState   string                  `json:"contract_state,omitempty"`
	MatchedTag      string                  `json:"matched_tag,omitempty"`
	MatchedFields   []string                `json:"matched_fields,omitempty"`
	PayloadVerified bool                    `json:"payload_verified,omitempty"`
}

type Receipt struct {
	Schema          string            `json:"schema"`
	SchemaVersion   int               `json:"schema_version"`
	Operation       string            `json:"operation"`
	OperationSHA256 string            `json:"operation_sha256"`
	Status          string            `json:"status"`
	Runtime         string            `json:"runtime"`
	Lab             string            `json:"lab,omitempty"`
	Topology        string            `json:"topology,omitempty"`
	Architecture    string            `json:"architecture"`
	Compiler        string            `json:"compiler"`
	Inputs          map[string]string `json:"inputs,omitempty"`
	RedactedInputs  []string          `json:"redacted_inputs,omitempty"`
	Captures        map[string]string `json:"captures,omitempty"`
	Steps           []StepReceipt     `json:"steps"`
	CleanupState    string            `json:"cleanup_state,omitempty"`
	StartedAt       string            `json:"started_at"`
	UpdatedAt       string            `json:"updated_at"`
	CompletedAt     string            `json:"completed_at,omitempty"`
	Path            string            `json:"path"`
	Error           string            `json:"error,omitempty"`
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

// ValidatePackReferences checks a parsed operation against a resolved pack
// registry. It is used both during catalog loading and when validating an
// operation file before it is installed.
func ValidatePackReferences(document Document, packs *packsvc.Registry) error {
	for _, step := range document.Steps {
		resolved, err := packs.Resolve(step.Pack)
		if err != nil {
			return fmt.Errorf("step %s: %w", step.ID, err)
		}
		if err := validateStepArguments(step.Arguments, resolved.Document.Arguments); err != nil {
			return fmt.Errorf("step %s: %w", step.ID, err)
		}
		for name, capture := range step.Captures {
			if contains(resolved.Document.SensitiveOutputFields, capture.Field) {
				return fmt.Errorf("step %s capture %s selects sensitive output field %s; sensitive captures cannot be persisted", step.ID, name, capture.Field)
			}
		}
		if step.Cleanup != nil {
			cleanup, err := packs.Resolve(step.Cleanup.Pack)
			if err != nil {
				return fmt.Errorf("step %s cleanup: %w", step.ID, err)
			}
			if err := validateStepArguments(step.Cleanup.Arguments, cleanup.Document.Arguments); err != nil {
				return fmt.Errorf("step %s cleanup: %w", step.ID, err)
			}
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
			if len(parts) < 2 || (parts[0] != "execution" && parts[0] != "target" && parts[0] != "domain_controller" && parts[0] != "domain") {
				return fmt.Errorf("input %s has invalid topology value %q", input.Name, input.TopologyValue)
			}
		}
		inputs[input.Name] = input
	}
	for _, step := range document.Steps {
		if !idPattern.MatchString(step.ID) || step.Pack == "" {
			return fmt.Errorf("each step needs a valid id and pack")
		}
		if steps[step.ID] {
			return fmt.Errorf("duplicate step %q", step.ID)
		}
		steps[step.ID] = true
		if document.SchemaVersion >= 2 && step.Expect == nil {
			return fmt.Errorf("step %s requires expect in operation schema version 2", step.ID)
		}
		if step.Expect != nil {
			if !idPattern.MatchString(step.Expect.Tag) {
				return fmt.Errorf("step %s has invalid expected tag %q", step.ID, step.Expect.Tag)
			}
			for _, value := range step.Expect.Fields {
				if value != "*" {
					if err := validateReference(value, inputs, captures, steps); err != nil {
						return fmt.Errorf("step %s expectation: %w", step.ID, err)
					}
				}
			}
			if payload := step.Expect.Payload; payload != nil {
				if !idPattern.MatchString(payload.Tag) || !idPattern.MatchString(payload.Field) || (payload.Encoding != "hex" && payload.Encoding != "base64") || payload.SHA256 == "" {
					return fmt.Errorf("step %s has invalid payload expectation", step.ID)
				}
				if strings.HasPrefix(payload.SHA256, "$") {
					if err := validateReference(payload.SHA256, inputs, captures, steps); err != nil {
						return fmt.Errorf("step %s payload expectation: %w", step.ID, err)
					}
				}
			}
		}
		for _, value := range step.Arguments {
			if err := validateReference(value, inputs, captures, steps); err != nil {
				return fmt.Errorf("step %s: %w", step.ID, err)
			}
		}
		for name, capture := range step.Captures {
			if !idPattern.MatchString(name) || capture.Tag == "" || capture.Field == "" {
				return fmt.Errorf("step %s has invalid capture %q", step.ID, name)
			}
			if captures[name] != "" {
				return fmt.Errorf("capture %q is declared more than once", name)
			}
			captures[name] = step.ID
		}
		if step.Cleanup != nil {
			for _, value := range step.Cleanup.Arguments {
				if err := validateReference(value, inputs, captures, steps); err != nil {
					return fmt.Errorf("step %s cleanup: %w", step.ID, err)
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
	}
	return nil
}

func validateReference(value string, inputs map[string]Input, captures map[string]string, steps map[string]bool) error {
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

func validType(value string) bool {
	switch strings.ToLower(value) {
	case "string", "wstring", "int", "short", "bytes", "file":
		return true
	}
	return false
}

func ResolveValue(value string, inputs, captures, topology map[string]string) (string, error) {
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

// RunnableStepIndexes returns unfinished steps in definition order. Completed
// steps are deliberately skipped when an operation is resumed.
func RunnableStepIndexes(receipt Receipt) []int {
	indexes := make([]int, 0, len(receipt.Steps))
	for index, step := range receipt.Steps {
		if step.State != "completed" {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

// CleanupStepIndexes returns completed stateful steps in reverse order.
func CleanupStepIndexes(document Document, receipt Receipt) []int {
	var indexes []int
	for index := len(document.Steps) - 1; index >= 0; index-- {
		if index >= len(receipt.Steps) {
			continue
		}
		step, state := document.Steps[index], receipt.Steps[index]
		if state.State == "completed" && step.Cleanup != nil && state.CleanupState != "completed" {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

// ClassifyExecution converts a runtime result into operation step and receipt
// states without treating submission as completion.
func ClassifyExecution(executionState string, outputComplete, failed bool) (string, string) {
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

func NewReceipt(item Resolved, packs *packsvc.Registry, path, runtime, lab, topology, arch, compiler string, inputs map[string]string) Receipt {
	receipt := Receipt{Schema: ReceiptSchema, SchemaVersion: ReceiptSchemaVersion, Operation: item.Qualified, OperationSHA256: item.SHA256, Status: "pending", Runtime: runtime, Lab: lab, Topology: topology, Architecture: arch, Compiler: compiler, Inputs: map[string]string{}, Captures: map[string]string{}, Path: path, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
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
		hash := ""
		if resolved, err := packs.Resolve(step.Pack); err == nil {
			hash = resolved.SHA256
		}
		cleanupPack, cleanupHash := "", ""
		if step.Cleanup != nil {
			cleanupPack = step.Cleanup.Pack
			if resolved, err := packs.Resolve(step.Cleanup.Pack); err == nil {
				cleanupHash = resolved.SHA256
			}
		}
		receipt.Steps = append(receipt.Steps, StepReceipt{ID: step.ID, Pack: step.Pack, PackSHA256: hash, CleanupPack: cleanupPack, CleanupSHA256: cleanupHash, State: "pending", ContractState: "pending"})
	}
	return receipt
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
	return os.WriteFile(path, data, 0o600)
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
	if receipt.SchemaVersion == 1 {
		receipt.SchemaVersion = ReceiptSchemaVersion
		for index := range receipt.Steps {
			if receipt.Steps[index].State == "completed" {
				receipt.Steps[index].ContractState = "legacy"
			}
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
	if updated.Schema != runtimeadapter.ReceiptSchema || updated.SchemaVersion != runtimeadapter.ReceiptSchemaVersion {
		return current, fmt.Errorf("unsupported runtime receipt at %s", current.ReceiptPath)
	}
	return updated, nil
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
	documents := []Document{triage, network}
	items := make([]Resolved, 0, len(documents))
	for _, document := range documents {
		item := Resolved{Document: document, Catalog: "builtin", Qualified: "builtin/" + document.ID}
		item.SHA256 = Fingerprint(document)
		items = append(items, item)
	}
	return items
}

func ReferenceMarkdown(items []Resolved) string {
	var body strings.Builder
	body.WriteString("# Operation Reference\n\nGenerated from resolved `bofbench.operation` manifests.\n\n")
	for _, item := range items {
		fmt.Fprintf(&body, "## `%s`\n\n%s\n\n", item.Qualified, item.Document.Summary)
		if len(item.Document.Inputs) > 0 {
			body.WriteString("### Inputs\n\n| Name | Type | Required | Sensitive |\n|---|---|---:|---:|\n")
			for _, in := range item.Document.Inputs {
				fmt.Fprintf(&body, "| `%s` | `%s` | %t | %t |\n", in.Name, in.Type, in.Required, in.Sensitive)
			}
			body.WriteString("\n")
		}
		body.WriteString("### Steps\n\n")
		for i, step := range item.Document.Steps {
			fmt.Fprintf(&body, "%d. `%s` → `%s`\n", i+1, step.ID, step.Pack)
		}
		body.WriteString("\n")
	}
	return body.String()
}
