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
	SchemaVersion         = 4
	MinimumSchemaVersion  = 1
	ReceiptSchema         = "bofbench.operation-receipt"
	ReceiptSchemaVersion  = 4
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

type Step struct {
	ID        string                    `json:"id"`
	Pack      string                    `json:"pack,omitempty"`
	Operation string                    `json:"operation,omitempty"`
	Arguments map[string]string         `json:"arguments,omitempty"`
	Captures  map[string]Capture        `json:"captures,omitempty"`
	Cleanup   *Cleanup                  `json:"cleanup,omitempty"`
	Expect    *packsvc.ProofExpectation `json:"expect,omitempty"`
	Outcomes  []Outcome                 `json:"outcomes,omitempty"`
}

type ProofCase struct {
	ID                 string                    `json:"id"`
	Via                []string                  `json:"via"`
	Architectures      []string                  `json:"architectures,omitempty"`
	Roles              []string                  `json:"roles,omitempty"`
	Inputs             map[string]string         `json:"inputs,omitempty"`
	ExpectCaptures     map[string]string         `json:"expect_captures,omitempty"`
	Cleanup            bool                      `json:"cleanup,omitempty"`
	StateChecks        []packsvc.ProofStateCheck `json:"state_checks,omitempty"`
	ExpectPath         []string                  `json:"expect_path,omitempty"`
	ExpectExpandedPath []string                  `json:"expect_expanded_path,omitempty"`
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
	ID                string                  `json:"id"`
	Pack              string                  `json:"pack"`
	PackSHA256        string                  `json:"pack_sha256"`
	CleanupPack       string                  `json:"cleanup_pack,omitempty"`
	CleanupSHA256     string                  `json:"cleanup_pack_sha256,omitempty"`
	State             string                  `json:"state"`
	ObjectSHA256      string                  `json:"object_sha256,omitempty"`
	OutputComplete    bool                    `json:"output_complete"`
	Runtime           runtimeadapter.Receipt  `json:"runtime_receipt,omitempty"`
	Captures          map[string]string       `json:"captures,omitempty"`
	Error             string                  `json:"error,omitempty"`
	CleanupState      string                  `json:"cleanup_state,omitempty"`
	CleanupRuntime    *runtimeadapter.Receipt `json:"cleanup_runtime_receipt,omitempty"`
	ContractState     string                  `json:"contract_state,omitempty"`
	MatchedTag        string                  `json:"matched_tag,omitempty"`
	MatchedFields     []string                `json:"matched_fields,omitempty"`
	PayloadVerified   bool                    `json:"payload_verified,omitempty"`
	MatchedOutcome    string                  `json:"matched_outcome,omitempty"`
	NextStep          string                  `json:"next_step,omitempty"`
	Operation         string                  `json:"operation,omitempty"`
	OperationSHA256   string                  `json:"operation_sha256,omitempty"`
	ChildReceipt      string                  `json:"child_receipt,omitempty"`
	ChildCleanupState string                  `json:"child_cleanup_state,omitempty"`
}

type Receipt struct {
	Schema           string            `json:"schema"`
	SchemaVersion    int               `json:"schema_version"`
	Operation        string            `json:"operation"`
	OperationSHA256  string            `json:"operation_sha256"`
	Status           string            `json:"status"`
	Runtime          string            `json:"runtime"`
	Lab              string            `json:"lab,omitempty"`
	Topology         string            `json:"topology,omitempty"`
	Architecture     string            `json:"architecture"`
	Compiler         string            `json:"compiler"`
	Inputs           map[string]string `json:"inputs,omitempty"`
	RedactedInputs   []string          `json:"redacted_inputs,omitempty"`
	Captures         map[string]string `json:"captures,omitempty"`
	ActualPath       []string          `json:"actual_path,omitempty"`
	ExpandedPath     []string          `json:"expanded_path,omitempty"`
	SkippedSteps     []string          `json:"skipped_steps,omitempty"`
	DependencySHA256 map[string]string `json:"dependency_sha256,omitempty"`
	Steps            []StepReceipt     `json:"steps"`
	CleanupState     string            `json:"cleanup_state,omitempty"`
	StartedAt        string            `json:"started_at"`
	UpdatedAt        string            `json:"updated_at"`
	CompletedAt      string            `json:"completed_at,omitempty"`
	Path             string            `json:"path"`
	Error            string            `json:"error,omitempty"`
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
		if step.Operation == "" {
			continue
		}
		child, err := r.Resolve(step.Operation)
		if err != nil {
			return fmt.Errorf("step %s: %w", step.ID, err)
		}
		if err := validateStepArguments(step.Arguments, operationArguments(child.Document.Inputs)); err != nil {
			return fmt.Errorf("step %s: %w", step.ID, err)
		}
		available := operationCaptureNames(child.Document)
		for name, capture := range step.Captures {
			if capture.Capture == "" || !available[capture.Capture] {
				return fmt.Errorf("step %s export %s selects unknown child capture %q", step.ID, name, capture.Capture)
			}
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
		if step.Operation != "" {
			continue
		}
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
		if document.SchemaVersion >= 4 && (step.Pack == "") == (step.Operation == "") {
			return fmt.Errorf("step %s must declare exactly one of pack or operation", step.ID)
		}
		if step.Operation != "" && step.Cleanup != nil {
			return fmt.Errorf("step %s child operation owns its cleanup; cleanup cannot be declared on the parent step", step.ID)
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
			if len(parts) < 2 || (parts[0] != "execution" && parts[0] != "target" && parts[0] != "domain_controller" && parts[0] != "domain") {
				return fmt.Errorf("input %s has invalid topology value %q", input.Name, input.TopologyValue)
			}
		}
		inputs[input.Name] = input
	}
	for stepIndex, step := range document.Steps {
		steps[step.ID] = true
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
			if err := validateExpectation(step.ID, *step.Expect, inputs, captures, steps); err != nil {
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
	if len(receipt.ActualPath) > 0 {
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
		childCleanup := step.Operation != "" && state.ChildReceipt != "" && state.ChildCleanupState != "completed"
		packCleanup := step.Cleanup != nil && state.CleanupState != "completed" && cleanupReferencesAvailable(step.Cleanup, receipt.Captures)
		if state.State == "completed" && (childCleanup || packCleanup) {
			indexes = append(indexes, index)
		}
	}
	return indexes
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
	receipt := Receipt{Schema: ReceiptSchema, SchemaVersion: ReceiptSchemaVersion, Operation: item.Qualified, OperationSHA256: item.SHA256, Status: "pending", Runtime: runtime, Lab: lab, Topology: topology, Architecture: arch, Compiler: compiler, Inputs: map[string]string{}, Captures: map[string]string{}, DependencySHA256: map[string]string{}, Path: path, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	receipt.DependencySHA256 = registry.DependencyHashes(item)
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
		hash, operationHash := "", ""
		if step.Pack != "" {
			if resolved, err := registry.packRegistry.Resolve(step.Pack); err == nil {
				hash = resolved.SHA256
			}
		} else if resolved, err := registry.Resolve(step.Operation); err == nil {
			operationHash = resolved.SHA256
		}
		cleanupPack, cleanupHash := "", ""
		if step.Cleanup != nil {
			cleanupPack = step.Cleanup.Pack
			if resolved, err := registry.packRegistry.Resolve(step.Cleanup.Pack); err == nil {
				cleanupHash = resolved.SHA256
			}
		}
		receipt.Steps = append(receipt.Steps, StepReceipt{ID: step.ID, Pack: step.Pack, PackSHA256: hash, Operation: step.Operation, OperationSHA256: operationHash, CleanupPack: cleanupPack, CleanupSHA256: cleanupHash, State: "pending", ContractState: "pending"})
	}
	return receipt
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
	if receipt.SchemaVersion < ReceiptSchemaVersion {
		previous := receipt.SchemaVersion
		receipt.SchemaVersion = ReceiptSchemaVersion
		for index := range receipt.Steps {
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
	documents := []Document{triage, network, waitTriage, coordination}
	items := make([]Resolved, 0, len(documents))
	for _, document := range documents {
		item := Resolved{Document: document, Catalog: "builtin", Qualified: "builtin/" + document.ID}
		item.SHA256 = Fingerprint(document)
		items = append(items, item)
	}
	return items
}

type GraphNode struct {
	ID        string `json:"id"`
	Pack      string `json:"pack,omitempty"`
	Operation string `json:"operation,omitempty"`
	Kind      string `json:"kind"`
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
	graph := GraphDocument{Schema: "bofbench.operation-graph", SchemaVersion: 2, Operation: document.ID}
	for index, step := range document.Steps {
		id := prefix + step.ID
		kind := "pack"
		if step.Operation != "" {
			kind = "operation"
		}
		graph.Nodes = append(graph.Nodes, GraphNode{ID: id, Pack: step.Pack, Operation: step.Operation, Kind: kind})
		if len(step.Outcomes) > 0 {
			for _, outcome := range step.Outcomes {
				to := outcome.Next
				if !strings.HasPrefix(to, "$") {
					to = prefix + to
				}
				graph.Edges = append(graph.Edges, GraphEdge{From: id, To: to, Outcome: outcome.ID})
			}
		} else if index+1 < len(document.Steps) {
			graph.Edges = append(graph.Edges, GraphEdge{From: id, To: prefix + document.Steps[index+1].ID})
		} else {
			graph.Edges = append(graph.Edges, GraphEdge{From: id, To: "$complete"})
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
		fmt.Fprintf(&body, "- Schema version: `%d`\n- Tier: `%s`\n- Steps: `%d`\n- Proof cases: `%d`\n\n", item.Document.SchemaVersion, item.Document.Tier, len(item.Document.Steps), len(item.Document.ProofCases))
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
			}
			fmt.Fprintf(&body, "%d. `%s` → `%s`", i+1, step.ID, target)
			if step.Cleanup != nil {
				fmt.Fprintf(&body, "; cleanup `%s`", step.Cleanup.Pack)
			}
			body.WriteString("\n")
			for _, outcome := range step.Outcomes {
				fmt.Fprintf(&body, "    - outcome `%s` → `%s` when `[%s]` matches\n", outcome.ID, outcome.Next, outcome.Expect.Tag)
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
				body.WriteString("\n")
			}
		}
		body.WriteString("\n")
	}
	return body.String()
}
