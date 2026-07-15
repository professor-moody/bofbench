package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"bofbench/internal/recipe"
	"bofbench/internal/scaffold"
)

const (
	Schema               = "bofbench.pack"
	SchemaVersion        = 4
	MinimumSchemaVersion = 1
	LockSchema           = "bofbench.pack-lock"
	LockSchemaVersion    = 1
	LockName             = "bofbench.lock.json"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
var placeholderPattern = regexp.MustCompile(`\$[A-Z][A-Z0-9_]*`)

type Argument struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	Required      bool   `json:"required,omitempty"`
	Default       string `json:"default,omitempty"`
	Sensitive     bool   `json:"sensitive,omitempty"`
	TopologyValue string `json:"topology_value,omitempty"`
}

type Source struct {
	Features        []string `json:"features,omitempty"`
	HeaderFragments []string `json:"header_fragments,omitempty"`
	Calls           []string `json:"calls,omitempty"`
}

type AnalysisStep struct {
	Action string   `json:"action"`
	APIs   []string `json:"apis"`
}

type AnalysisSignature struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Summary         string         `json:"summary"`
	Steps           []AnalysisStep `json:"steps"`
	RequiredStrings []string       `json:"required_strings,omitempty"`
	Effects         []string       `json:"effects"`
	Requirements    []string       `json:"requirements,omitempty"`
}

type ProofExpectation struct {
	Tag     string                   `json:"tag"`
	Fields  map[string]string        `json:"fields,omitempty"`
	Payload *ProofPayloadExpectation `json:"payload,omitempty"`
}

type ProofPayloadExpectation struct {
	Tag      string `json:"tag"`
	Field    string `json:"field"`
	Encoding string `json:"encoding"`
	SHA256   string `json:"sha256"`
}

type ProofStateCheck struct {
	Phase      string            `json:"phase"`
	Kind       string            `json:"kind"`
	Expect     string            `json:"expect"`
	Parameters map[string]string `json:"parameters"`
	Role       string            `json:"role,omitempty"`
}

type ProofCapture struct {
	Tag   string `json:"tag"`
	Field string `json:"field"`
}

type ProofCleanupStep struct {
	Pack      string            `json:"pack"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type ProofCase struct {
	ID           string                  `json:"id"`
	Via          []string                `json:"via"`
	Arguments    map[string]string       `json:"arguments,omitempty"`
	Expect       ProofExpectation        `json:"expect"`
	Cleanup      bool                    `json:"cleanup,omitempty"`
	CleanupSteps []ProofCleanupStep      `json:"cleanup_steps,omitempty"`
	StateChecks  []ProofStateCheck       `json:"state_checks,omitempty"`
	Roles        []string                `json:"roles,omitempty"`
	Captures     map[string]ProofCapture `json:"captures,omitempty"`
}

type Document struct {
	Schema                string              `json:"schema"`
	SchemaVersion         int                 `json:"schema_version"`
	ID                    string              `json:"id"`
	Version               string              `json:"version"`
	Title                 string              `json:"title"`
	Summary               string              `json:"summary"`
	Tier                  string              `json:"tier"`
	Capabilities          []string            `json:"capabilities"`
	Effects               []string            `json:"effects"`
	Platforms             []string            `json:"platforms"`
	Architecture          []string            `json:"architecture"`
	Privilege             string              `json:"privilege"`
	Network               string              `json:"network"`
	Arguments             []Argument          `json:"arguments,omitempty"`
	Dependencies          []string            `json:"dependencies,omitempty"`
	Source                Source              `json:"source"`
	ExpectedAnalysis      []string            `json:"expected_analysis,omitempty"`
	AnalysisSignatures    []AnalysisSignature `json:"analysis_signatures,omitempty"`
	ProofCases            []ProofCase         `json:"proof_cases,omitempty"`
	OutputFields          []string            `json:"output_fields,omitempty"`
	SensitiveOutputFields []string            `json:"sensitive_output_fields,omitempty"`
	CleanupPack           string              `json:"cleanup_pack,omitempty"`
	CleanupArguments      map[string]string   `json:"cleanup_arguments,omitempty"`
	TargetSupport         []string            `json:"target_support"`
}

type Resolved struct {
	Document    Document `json:"pack"`
	Catalog     string   `json:"catalog"`
	CatalogRoot string   `json:"catalog_root,omitempty"`
	Root        string   `json:"root,omitempty"`
	Manifest    string   `json:"manifest,omitempty"`
	Qualified   string   `json:"qualified"`
	SHA256      string   `json:"sha256"`
}

type Registry struct {
	items       map[string]Resolved
	unqualified map[string][]string
}

type LoadOptions struct {
	Project       string
	ExtraCatalogs []string
}

type LockRecord struct {
	ID                    string            `json:"id"`
	Qualified             string            `json:"qualified"`
	Catalog               string            `json:"catalog"`
	CatalogRoot           string            `json:"catalog_root,omitempty"`
	Version               string            `json:"version"`
	SHA256                string            `json:"sha256"`
	Arguments             []Argument        `json:"arguments,omitempty"`
	Cleanup               string            `json:"cleanup_pack,omitempty"`
	CleanupArguments      map[string]string `json:"cleanup_arguments,omitempty"`
	SensitiveOutputFields []string          `json:"sensitive_output_fields,omitempty"`
}

type Lock struct {
	Schema        string       `json:"schema"`
	SchemaVersion int          `json:"schema_version"`
	Packs         []LockRecord `json:"packs"`
	UpdatedAt     string       `json:"updated_at"`
}

type ApplyResult struct {
	Project  string               `json:"project"`
	Packs    []LockRecord         `json:"packs"`
	Added    []string             `json:"added,omitempty"`
	Existing []string             `json:"existing,omitempty"`
	Sources  []scaffold.AddResult `json:"sources,omitempty"`
	LockPath string               `json:"lock_path"`
	Migrated string               `json:"migrated_recipe,omitempty"`
}

type CatalogRef struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Source string `json:"source,omitempty"`
}

type CatalogConfig struct {
	Schema        string       `json:"schema"`
	SchemaVersion int          `json:"schema_version"`
	Catalogs      []CatalogRef `json:"catalogs"`
}

func Load(opts LoadOptions) (*Registry, error) {
	r := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}}
	loadedCatalogs := map[string]bool{}
	loadCatalog := func(root, name string) error {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		absolute = filepath.Clean(absolute)
		if loadedCatalogs[absolute] {
			return nil
		}
		if err := r.loadCatalog(absolute, name); err != nil {
			return err
		}
		loadedCatalogs[absolute] = true
		return nil
	}
	for _, item := range builtins() {
		if err := r.add(item); err != nil {
			return nil, err
		}
	}
	if opts.Project != "" {
		root := filepath.Join(projectDir(opts.Project), ".bofbench", "packs")
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			if err := loadCatalog(root, "project"); err != nil {
				return nil, err
			}
		}
		if lock, err := loadLock(projectDir(opts.Project)); err == nil {
			for _, record := range lock.Packs {
				if record.CatalogRoot != "" {
					if err := loadCatalog(record.CatalogRoot, record.Catalog); err != nil {
						return nil, fmt.Errorf("locked catalog %s: %w", record.Catalog, err)
					}
				}
			}
		}
	}
	config, err := LoadCatalogConfig()
	if err != nil {
		return nil, err
	}
	for _, catalog := range config.Catalogs {
		if err := loadCatalog(catalog.Path, catalog.Name); err != nil {
			return nil, fmt.Errorf("catalog %s: %w", catalog.Name, err)
		}
	}
	for _, path := range opts.ExtraCatalogs {
		if path == "builtin" {
			continue
		}
		resolvedPath := path
		name := strings.ToLower(filepath.Base(filepath.Clean(path)))
		for _, configured := range config.Catalogs {
			if configured.Name == path {
				resolvedPath = configured.Path
				name = configured.Name
				break
			}
		}
		if err := loadCatalog(resolvedPath, name); err != nil {
			return nil, err
		}
	}
	if err := r.validateReferences(); err != nil {
		return nil, err
	}
	return r, nil
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
		haystack := strings.ToLower(strings.Join([]string{
			item.Qualified, item.Document.Title, item.Document.Summary,
			strings.Join(item.Document.Capabilities, " "), strings.Join(item.Document.Effects, " "),
		}, " "))
		match := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				match = false
				break
			}
		}
		if match {
			out = append(out, item)
		}
	}
	return out
}

func (r *Registry) ResolveRelated(owner Resolved, reference string) (Resolved, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Resolved{}, fmt.Errorf("empty related pack reference")
	}
	if strings.Contains(reference, "/") {
		return r.Resolve(reference)
	}
	if item, ok := r.items[owner.Catalog+"/"+reference]; ok {
		return item, nil
	}
	return r.Resolve(reference)
}

func (r *Registry) validateReferences() error {
	for _, item := range r.List() {
		for _, dependency := range item.Document.Dependencies {
			if _, err := r.ResolveRelated(item, dependency); err != nil {
				return fmt.Errorf("pack %s dependency %s: %w", item.Qualified, dependency, err)
			}
		}
		if item.Document.CleanupPack != "" {
			if _, err := r.ResolveRelated(item, item.Document.CleanupPack); err != nil {
				return fmt.Errorf("pack %s cleanup %s: %w", item.Qualified, item.Document.CleanupPack, err)
			}
		}
		for _, proof := range item.Document.ProofCases {
			for _, step := range proof.CleanupSteps {
				if _, err := r.ResolveRelated(item, step.Pack); err != nil {
					return fmt.Errorf("pack %s proof %s cleanup %s: %w", item.Qualified, proof.ID, step.Pack, err)
				}
			}
		}
	}
	return nil
}

func (r *Registry) Resolve(name string) (Resolved, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if item, ok := r.items[name]; ok {
		return item, nil
	}
	qualified := r.unqualified[name]
	if len(qualified) == 1 {
		return r.items[qualified[0]], nil
	}
	if len(qualified) > 1 {
		return Resolved{}, fmt.Errorf("pack %q exists in multiple catalogs; choose %s", name, strings.Join(qualified, ", "))
	}
	return Resolved{}, fmt.Errorf("unknown pack %q; use 'bofbench pack search %s'", name, name)
}

func (r *Registry) Apply(project string, names []string) (ApplyResult, error) {
	if len(names) == 0 {
		return ApplyResult{}, errors.New("provide at least one pack")
	}
	root := projectDir(project)
	info, err := os.Stat(root)
	if err != nil {
		return ApplyResult{}, err
	}
	if !info.IsDir() {
		return ApplyResult{}, fmt.Errorf("pack project must be a directory: %s", root)
	}
	lock, err := loadLock(root)
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Project: root, LockPath: filepath.Join(root, LockName)}
	if len(lock.Packs) == 0 {
		if migrated, record, migrateErr := r.recipeRecord(root); migrateErr != nil {
			return ApplyResult{}, migrateErr
		} else if migrated != "" {
			lock.Packs = append(lock.Packs, record)
			result.Migrated = migrated
		}
	}
	existing := map[string]LockRecord{}
	for _, record := range lock.Packs {
		existing[record.Qualified] = record
	}
	visiting := map[string]bool{}
	var apply func(string) error
	apply = func(name string) error {
		item, resolveErr := r.Resolve(name)
		if resolveErr != nil {
			return resolveErr
		}
		if _, ok := existing[item.Qualified]; ok {
			result.Existing = appendUnique(result.Existing, item.Qualified)
			return nil
		}
		if visiting[item.Qualified] {
			return fmt.Errorf("pack dependency cycle includes %s", item.Qualified)
		}
		visiting[item.Qualified] = true
		for _, dependency := range item.Document.Dependencies {
			resolvedDependency, resolveErr := r.ResolveRelated(item, dependency)
			if resolveErr != nil {
				return resolveErr
			}
			if err := apply(resolvedDependency.Qualified); err != nil {
				return fmt.Errorf("%s dependency %s: %w", item.Qualified, dependency, err)
			}
		}
		delete(visiting, item.Qualified)
		if len(item.Document.Source.Features) > 0 {
			sourceResult, sourceErr := scaffold.AddFeatures(root, item.Document.Source.Features)
			if sourceErr != nil {
				return fmt.Errorf("apply %s: %w", item.Qualified, sourceErr)
			}
			result.Sources = append(result.Sources, sourceResult)
		}
		if len(item.Document.Source.HeaderFragments) > 0 {
			declaration, sourceErr := item.sourceDeclaration()
			if sourceErr != nil {
				return sourceErr
			}
			markerID := strings.ReplaceAll(item.Qualified, "/", "--")
			sourceResult, sourceErr := scaffold.AddPackFragments(root, markerID, declaration, item.Document.Source.Calls)
			if sourceErr != nil {
				return fmt.Errorf("apply %s: %w", item.Qualified, sourceErr)
			}
			result.Sources = append(result.Sources, sourceResult)
		}
		record := lockRecord(item)
		existing[item.Qualified] = record
		lock.Packs = append(lock.Packs, record)
		result.Added = appendUnique(result.Added, item.Qualified)
		return nil
	}
	for _, raw := range splitNames(names) {
		if err := apply(raw); err != nil {
			return ApplyResult{}, err
		}
	}
	lock.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeJSON(result.LockPath, lock); err != nil {
		return ApplyResult{}, err
	}
	result.Packs = append([]LockRecord(nil), lock.Packs...)
	sort.Strings(result.Added)
	sort.Strings(result.Existing)
	return result, nil
}

func LoadLock(project string) (Lock, string, error) {
	root := projectDir(project)
	lock, err := loadLock(root)
	return lock, filepath.Join(root, LockName), err
}

func ValidateFile(path string) (Document, error) {
	document, err := decodeDocument(path)
	if err != nil {
		return Document{}, err
	}
	if err := validate(document, filepath.Dir(path)); err != nil {
		return Document{}, err
	}
	return document, nil
}

func LoadCatalogConfig() (CatalogConfig, error) {
	path, err := catalogConfigPath()
	if err != nil {
		return CatalogConfig{}, err
	}
	config := CatalogConfig{Schema: "bofbench.catalogs", SchemaVersion: 1, Catalogs: []CatalogRef{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return CatalogConfig{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return CatalogConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if config.Schema != "bofbench.catalogs" || config.SchemaVersion != 1 {
		return CatalogConfig{}, fmt.Errorf("unsupported catalog configuration in %s", path)
	}
	return config, nil
}

func AddCatalog(source, name string) (CatalogRef, error) {
	config, err := LoadCatalogConfig()
	if err != nil {
		return CatalogRef{}, err
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return CatalogRef{}, errors.New("catalog path or Git URL is required")
	}
	if name == "" {
		name = catalogName(source)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if !idPattern.MatchString(name) {
		return CatalogRef{}, fmt.Errorf("invalid catalog name %q", name)
	}
	for _, item := range config.Catalogs {
		if item.Name == name {
			return CatalogRef{}, fmt.Errorf("catalog %s already exists", name)
		}
	}
	ref := CatalogRef{Name: name, Source: source}
	if isGitSource(source) {
		cache, cacheErr := catalogCacheDir()
		if cacheErr != nil {
			return CatalogRef{}, cacheErr
		}
		ref.Path = filepath.Join(cache, name)
		if err := os.MkdirAll(filepath.Dir(ref.Path), 0o755); err != nil {
			return CatalogRef{}, err
		}
		if output, cloneErr := exec.Command("git", "clone", "--depth", "1", source, ref.Path).CombinedOutput(); cloneErr != nil {
			return CatalogRef{}, fmt.Errorf("clone catalog: %w: %s", cloneErr, strings.TrimSpace(string(output)))
		}
	} else {
		absolute, absErr := filepath.Abs(source)
		if absErr != nil {
			return CatalogRef{}, absErr
		}
		if info, statErr := os.Stat(absolute); statErr != nil || !info.IsDir() {
			if statErr != nil {
				return CatalogRef{}, statErr
			}
			return CatalogRef{}, fmt.Errorf("catalog is not a directory: %s", absolute)
		}
		ref.Path = absolute
	}
	registry := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}}
	if err := registry.loadCatalog(ref.Path, ref.Name); err != nil {
		return CatalogRef{}, err
	}
	config.Catalogs = append(config.Catalogs, ref)
	sort.Slice(config.Catalogs, func(i, j int) bool { return config.Catalogs[i].Name < config.Catalogs[j].Name })
	if err := saveCatalogConfig(config); err != nil {
		return CatalogRef{}, err
	}
	return ref, nil
}

func RemoveCatalog(name string) error {
	config, err := LoadCatalogConfig()
	if err != nil {
		return err
	}
	name = strings.ToLower(strings.TrimSpace(name))
	found := false
	out := config.Catalogs[:0]
	for _, item := range config.Catalogs {
		if item.Name == name {
			found = true
			continue
		}
		out = append(out, item)
	}
	if !found {
		return fmt.Errorf("catalog %s is not configured", name)
	}
	config.Catalogs = out
	return saveCatalogConfig(config)
}

func UpdateCatalog(name string) error {
	config, err := LoadCatalogConfig()
	if err != nil {
		return err
	}
	for _, item := range config.Catalogs {
		if item.Name != name {
			continue
		}
		if !isGitSource(item.Source) {
			return fmt.Errorf("catalog %s is local and does not require update", name)
		}
		output, updateErr := exec.Command("git", "-C", item.Path, "pull", "--ff-only").CombinedOutput()
		if updateErr != nil {
			return fmt.Errorf("update catalog: %w: %s", updateErr, strings.TrimSpace(string(output)))
		}
		return nil
	}
	return fmt.Errorf("catalog %s is not configured", name)
}

func (r *Registry) add(item Resolved) error {
	if _, exists := r.items[item.Qualified]; exists {
		return fmt.Errorf("duplicate pack %s", item.Qualified)
	}
	r.items[item.Qualified] = item
	r.unqualified[item.Document.ID] = append(r.unqualified[item.Document.ID], item.Qualified)
	sort.Strings(r.unqualified[item.Document.ID])
	return nil
}

func (r *Registry) loadCatalog(root, catalog string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	var manifests []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".") && path != root {
			return filepath.SkipDir
		}
		if !entry.IsDir() && entry.Name() == "pack.json" {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(manifests) == 0 {
		return fmt.Errorf("no pack.json files found under %s", root)
	}
	sort.Strings(manifests)
	for _, path := range manifests {
		document, decodeErr := decodeDocument(path)
		if decodeErr != nil {
			return decodeErr
		}
		packRoot := filepath.Dir(path)
		if validateErr := validate(document, packRoot); validateErr != nil {
			return fmt.Errorf("%s: %w", path, validateErr)
		}
		item := Resolved{Document: document, Catalog: catalog, CatalogRoot: root, Root: packRoot, Manifest: path, Qualified: catalog + "/" + document.ID}
		item.SHA256, err = fingerprint(item)
		if err != nil {
			return err
		}
		if err := r.add(item); err != nil {
			return err
		}
	}
	return nil
}

func builtins() []Resolved {
	byID := map[string]Document{}
	for _, feature := range scaffold.Features() {
		byID[feature.Name] = baseBuiltin(feature.Name, strings.Title(strings.ReplaceAll(feature.Name, "-", " ")), feature.Description, []string{feature.Name}, effectForFeature(feature.Name))
	}
	for _, featurePack := range scaffold.FeaturePacks() {
		document := baseBuiltin(featurePack.Name, strings.Title(strings.ReplaceAll(featurePack.Name, "-", " ")), featurePack.Description, featurePack.Features, effectsForImpact(featurePack.Impact))
		if featurePack.Name == "active-lab" || featurePack.Name == "offensive-lab" {
			document.CleanupPack = "active-cleanup"
		}
		byID[featurePack.Name] = document
	}
	for _, scenario := range recipe.Builtins() {
		document := baseBuiltin(scenario.Name, scenario.Title, scenario.Description, scenario.Features, effectsForImpact(scenario.Impact))
		document.Privilege = scenario.Privilege
		document.Network = scenario.Network
		document.Capabilities = append([]string(nil), scenario.Features...)
		if scenario.Name == "active-actions" || scenario.Name == "offensive-survey" {
			document.CleanupPack = "active-cleanup"
		}
		byID[scenario.Name] = document
	}
	for _, starter := range []struct {
		ID, Title, Summary string
		Features           []string
	}{
		{ID: "survey", Title: "Windows Host Survey", Summary: "Collect compact host, identity, token, process, service, network, registry, and domain context", Features: []string{"process", "host", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context"}},
		{ID: "identity-discovery", Title: "Identity and Token Discovery", Summary: "Report the current account and its token elevation and integrity context", Features: []string{"identity", "token-context"}},
		{ID: "process-discovery", Title: "Process Discovery", Summary: "Enumerate a bounded local process snapshot", Features: []string{"process-list"}},
		{ID: "service-discovery", Title: "Service Discovery", Summary: "Enumerate a bounded local Windows service snapshot", Features: []string{"service-list"}},
		{ID: "network-inventory", Title: "Network Inventory", Summary: "Report the host name and a bounded set of local TCP endpoints", Features: []string{"network", "tcp-connections"}},
		{ID: "domain-discovery", Title: "Domain Discovery", Summary: "Report domain join state and the local join name", Features: []string{"domain-context"}},
		{ID: "registry-query", Title: "Registry Query", Summary: "Read the local Windows product name from the registry", Features: []string{"registry"}},
	} {
		document := baseBuiltin(starter.ID, starter.Title, starter.Summary, starter.Features, []string{"reads data"})
		if starter.ID == "network-inventory" || starter.ID == "domain-discovery" {
			document.Network = "local"
		}
		byID[starter.ID] = document
	}
	processArguments := []Argument{
		{Name: "process_filter", Type: "string", Description: "case-insensitive process image substring; empty matches all", Default: ""},
		{Name: "result_limit", Type: "int", Description: "maximum matching process rows (1-256)", Default: "25"},
	}
	processDiscovery := byID["process-discovery"]
	processDiscovery.Source.Features = []string{"process-search"}
	processDiscovery.Capabilities = []string{"filtered process discovery"}
	processDiscovery.Arguments = append([]Argument(nil), processArguments...)
	processDiscovery.OutputFields = []string{"pid", "ppid", "threads", "image", "matched", "examined", "limit", "filter", "status"}
	processDiscovery.ExpectedAnalysis = []string{"process enumeration", "Beacon argument parsing"}
	byID["process-discovery"] = processDiscovery
	deepSurvey := byID["deep-survey"]
	for index, feature := range deepSurvey.Source.Features {
		if feature == "process-list" {
			deepSurvey.Source.Features[index] = "process-search"
		}
	}
	deepSurvey.Arguments = append([]Argument(nil), processArguments...)
	deepSurvey.OutputFields = []string{"pid", "image", "matched", "examined", "limit", "filter", "elevated", "integrity", "service", "tcp", "domain", "status"}
	deepSurvey.ExpectedAnalysis = append(deepSurvey.ExpectedAnalysis, "Beacon argument parsing")
	byID["deep-survey"] = deepSurvey
	systemDiscovery := byID["system-discovery"]
	systemDiscovery.Source.Features = []string{"process-search", "token-context", "service-list"}
	systemDiscovery.Capabilities = []string{"filtered process discovery", "token context discovery", "service discovery"}
	systemDiscovery.Arguments = append([]Argument(nil), processArguments...)
	systemDiscovery.OutputFields = []string{"pid", "image", "elevated", "integrity", "service", "state", "status"}
	systemDiscovery.ExpectedAnalysis = []string{"process enumeration", "token inspection", "service enumeration", "Beacon argument parsing"}
	byID["system-discovery"] = systemDiscovery
	processTree := byID["process-tree"]
	processTree.Title = "Process Tree Inventory"
	processTree.Capabilities = []string{"bounded process tree inventory", "process session and architecture context"}
	processTree.Arguments = []Argument{{Name: "process_filter", Type: "string", Description: "case-insensitive image substring; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum rows (1-256)", Default: "25"}}
	processTree.ExpectedAnalysis = []string{"process_tree_inventory"}
	processTree.OutputFields = []string{"pid", "ppid", "session", "arch", "image", "shown", "limit", "filter", "status"}
	processTree.AnalysisSignatures = []AnalysisSignature{{ID: "process_tree_inventory", Name: "Process-tree inventory", Summary: "Enumerate processes and correlate parent, session, and architecture context.", Steps: []AnalysisStep{{Action: "enumerate processes", APIs: []string{"CreateToolhelp32Snapshot"}}, {Action: "read process rows", APIs: []string{"Process32First", "Process32FirstW"}}, {Action: "resolve sessions", APIs: []string{"ProcessIdToSessionId"}}}, Effects: []string{"reads process metadata"}, Requirements: []string{"process snapshot access"}}}
	processTree.ProofCases = []ProofCase{{ID: "bounded", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"process_filter": "", "result_limit": "10"}, Expect: ProofExpectation{Tag: "process-tree", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["process-tree"] = processTree
	threadInventory := byID["thread-inventory"]
	threadInventory.Title = "Thread Inventory"
	threadInventory.Capabilities = []string{"bounded thread inventory for one process"}
	threadInventory.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "exact process identifier", Required: true}, {Name: "result_limit", Type: "int", Description: "maximum rows (1-512)", Default: "64"}}
	threadInventory.ExpectedAnalysis = []string{"thread_inventory"}
	threadInventory.OutputFields = []string{"pid", "tid", "base_priority", "delta_priority", "shown", "limit", "status"}
	threadInventory.AnalysisSignatures = []AnalysisSignature{{ID: "thread_inventory", Name: "Thread inventory", Summary: "Enumerate thread identifiers owned by one selected process.", Steps: []AnalysisStep{{Action: "create thread snapshot", APIs: []string{"CreateToolhelp32Snapshot"}}, {Action: "enumerate threads", APIs: []string{"Thread32First"}}}, Effects: []string{"reads process metadata"}, Requirements: []string{"an exact target PID"}}}
	threadInventory.ProofCases = []ProofCase{{ID: "target-threads", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}, Expect: ProofExpectation{Tag: "thread-inventory", Fields: map[string]string{"status": "complete", "pid": "*"}}}}
	byID["thread-inventory"] = threadInventory
	mitigations := byID["process-mitigation-inventory"]
	mitigations.Title = "Process Mitigation Inventory"
	mitigations.Capabilities = []string{"bounded process mitigation policy inventory", "DEP, ASLR, dynamic-code, CFG, signature, and child-process policy discovery"}
	mitigations.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "exact process identifier", Required: true}}
	mitigations.ExpectedAnalysis = []string{"process_mitigation_inventory"}
	mitigations.OutputFields = []string{"target_pid", "dep", "aslr", "dynamic_code", "cfg", "signature", "child_process", "policies", "status"}
	mitigations.AnalysisSignatures = []AnalysisSignature{{ID: "process_mitigation_inventory", Name: "Process mitigation inventory", Summary: "Open one selected process and inspect its configured mitigation policies.", Steps: []AnalysisStep{{Action: "open selected process", APIs: []string{"OpenProcess"}}, {Action: "read mitigation policies", APIs: []string{"GetProcessMitigationPolicy"}}}, Effects: []string{"reads process security metadata"}, Requirements: []string{"an exact target PID", "process query access"}}}
	mitigations.ProofCases = []ProofCase{{ID: "target-policies", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID"}, Expect: ProofExpectation{Tag: "process-mitigation-inventory", Fields: map[string]string{"status": "complete", "target_pid": "*"}}}}
	byID["process-mitigation-inventory"] = mitigations
	memoryMap := byID["process-memory-map"]
	memoryMap.Title = "Process Memory Map"
	memoryMap.Capabilities = []string{"bounded committed-memory region inventory", "mapped image and protection discovery"}
	memoryMap.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "exact process identifier", Required: true}, {Name: "result_limit", Type: "int", Description: "maximum committed regions (1-512)", Default: "64"}}
	memoryMap.ExpectedAnalysis = []string{"process_memory_map"}
	memoryMap.OutputFields = []string{"target_pid", "base", "size", "protect", "type", "mapped", "shown", "limit", "status"}
	memoryMap.AnalysisSignatures = []AnalysisSignature{{ID: "process_memory_map", Name: "Process memory-map inventory", Summary: "Open one process and enumerate bounded committed regions with protection and mapped-image context.", Steps: []AnalysisStep{{Action: "open selected process", APIs: []string{"OpenProcess"}}, {Action: "query virtual-memory regions", APIs: []string{"VirtualQueryEx"}}, {Action: "resolve mapped images", APIs: []string{"GetMappedFileNameA", "GetMappedFileNameW"}}}, Effects: []string{"reads process memory metadata"}, Requirements: []string{"an exact target PID", "process query and VM-read access"}}}
	memoryMap.ProofCases = []ProofCase{{ID: "target-map", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}, Expect: ProofExpectation{Tag: "process-memory-map", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["process-memory-map"] = memoryMap
	threadStarts := byID["thread-start-inventory"]
	threadStarts.Title = "Thread Start Inventory"
	threadStarts.Capabilities = []string{"bounded thread start-address inventory", "thread start region and mapped-image discovery"}
	threadStarts.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "exact process identifier", Required: true}, {Name: "result_limit", Type: "int", Description: "maximum threads (1-512)", Default: "64"}}
	threadStarts.ExpectedAnalysis = []string{"thread_start_inventory"}
	threadStarts.OutputFields = []string{"target_pid", "tid", "start", "state", "protect", "type", "mapped", "shown", "limit", "status"}
	threadStarts.AnalysisSignatures = []AnalysisSignature{{ID: "thread_start_inventory", Name: "Thread start-address inventory", Summary: "Enumerate threads in one process and correlate their start addresses with containing regions and images.", Steps: []AnalysisStep{{Action: "enumerate process threads", APIs: []string{"CreateToolhelp32Snapshot", "Thread32First"}}, {Action: "query thread start address", APIs: []string{"NtQueryInformationThread"}}, {Action: "query containing memory region", APIs: []string{"VirtualQueryEx"}}}, Effects: []string{"reads thread and process memory metadata"}, Requirements: []string{"an exact target PID", "thread and process query access"}}}
	threadStarts.ProofCases = []ProofCase{{ID: "target-starts", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}, Expect: ProofExpectation{Tag: "thread-start-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["thread-start-inventory"] = threadStarts
	processImages := byID["process-image-inventory"]
	processImages.Title = "Process Image Inventory"
	processImages.Capabilities = []string{"bounded loaded-image inventory for one selected process", "module base, size, and path discovery"}
	processImages.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "process identifier", Required: true}, {Name: "module_filter", Type: "string", Description: "case-insensitive module-name substring; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum images (1-512)", Default: "64"}}
	processImages.ExpectedAnalysis = []string{"process_image_inventory"}
	processImages.OutputFields = []string{"target_pid", "base", "size", "module", "path", "shown", "limit", "filter", "status", "error"}
	processImages.AnalysisSignatures = []AnalysisSignature{{ID: "process_image_inventory", Name: "Process image inventory", Summary: "Enumerate modules loaded in one selected process and report base addresses, sizes, and paths.", Steps: []AnalysisStep{{Action: "open selected process module snapshot", APIs: []string{"CreateToolhelp32Snapshot"}}, {Action: "enumerate loaded images", APIs: []string{"Module32FirstW", "Module32NextW"}}}, RequiredStrings: []string{"[process-image-inventory]"}, Effects: []string{"reads process image metadata"}, Requirements: []string{"a process identifier", "module snapshot access"}}}
	processImages.ProofCases = []ProofCase{{ID: "target-images", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID", "module_filter": "", "result_limit": "16"}, Expect: ProofExpectation{Tag: "process-image-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["process-image-inventory"] = processImages
	threadStates := byID["thread-state-inventory"]
	threadStates.Title = "Thread State Inventory"
	threadStates.Capabilities = []string{"bounded thread scheduling-state inventory", "thread priority and execution-time discovery"}
	threadStates.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "process identifier", Required: true}, {Name: "result_limit", Type: "int", Description: "maximum threads (1-512)", Default: "64"}}
	threadStates.ExpectedAnalysis = []string{"thread_state_inventory"}
	threadStates.OutputFields = []string{"target_pid", "tid", "state", "priority", "base_priority", "created", "kernel", "user", "shown", "limit", "status", "error"}
	threadStates.AnalysisSignatures = []AnalysisSignature{{ID: "thread_state_inventory", Name: "Thread state inventory", Summary: "Enumerate threads for one selected process and inspect queryability, priority, and execution-time state.", Steps: []AnalysisStep{{Action: "enumerate selected process threads", APIs: []string{"CreateToolhelp32Snapshot", "Thread32First"}}, {Action: "inspect thread scheduling state", APIs: []string{"OpenThread", "GetThreadPriority", "GetThreadTimes"}}}, RequiredStrings: []string{"[thread-state-inventory]"}, Effects: []string{"reads thread scheduling metadata"}, Requirements: []string{"a process identifier", "thread query access"}}}
	threadStates.ProofCases = []ProofCase{{ID: "target-thread-state", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID", "result_limit": "16"}, Expect: ProofExpectation{Tag: "thread-state-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["thread-state-inventory"] = threadStates
	processJobs := byID["process-job-inventory"]
	processJobs.Title = "Process Job Inventory"
	processJobs.Capabilities = []string{"process job-object membership discovery"}
	processJobs.Arguments = []Argument{{Name: "target_pid", Type: "int", Description: "process identifier", Required: true}}
	processJobs.ExpectedAnalysis = []string{"process_job_inventory"}
	processJobs.OutputFields = []string{"target_pid", "in_job", "status", "error"}
	processJobs.AnalysisSignatures = []AnalysisSignature{{ID: "process_job_inventory", Name: "Process job membership", Summary: "Open one selected process and report whether Windows has assigned it to a job object.", Steps: []AnalysisStep{{Action: "open selected process", APIs: []string{"OpenProcess"}}, {Action: "query job membership", APIs: []string{"IsProcessInJob"}}}, RequiredStrings: []string{"[process-job-inventory]"}, Effects: []string{"reads process job metadata"}, Requirements: []string{"a process identifier", "process query access"}}}
	processJobs.ProofCases = []ProofCase{{ID: "target-job", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_pid": "$TARGET_PID"}, Expect: ProofExpectation{Tag: "process-job-inventory", Fields: map[string]string{"status": "complete", "in_job": "*"}}}}
	byID["process-job-inventory"] = processJobs
	objectNamespace := byID["object-namespace-inventory"]
	objectNamespace.Title = "Object Namespace Inventory"
	objectNamespace.Capabilities = []string{"bounded Windows object-manager namespace inventory"}
	objectNamespace.Arguments = []Argument{{Name: "directory", Type: "wstring", Description: `object-manager directory such as \BaseNamedObjects`, Default: `\BaseNamedObjects`}, {Name: "prefix", Type: "string", Description: "case-insensitive name prefix; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum objects (1-512)", Default: "64"}}
	objectNamespace.ExpectedAnalysis = []string{"object_namespace_inventory"}
	objectNamespace.OutputFields = []string{"name", "type", "shown", "limit", "status", "api", "ntstatus"}
	objectNamespace.AnalysisSignatures = []AnalysisSignature{{ID: "object_namespace_inventory", Name: "Object namespace inventory", Summary: "Open one object-manager directory and enumerate bounded object names and types.", Steps: []AnalysisStep{{Action: "open object-manager directory", APIs: []string{"NtOpenDirectoryObject"}}, {Action: "enumerate namespace entries", APIs: []string{"NtQueryDirectoryObject"}}}, RequiredStrings: []string{"[object-namespace-inventory]"}, Effects: []string{"reads Windows object namespace metadata"}, Requirements: []string{"an object-manager directory path", "directory query access"}}}
	objectNamespace.ProofCases = []ProofCase{{ID: "base-named-objects", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"directory": `\BaseNamedObjects`, "prefix": "", "result_limit": "16"}, Expect: ProofExpectation{Tag: "object-namespace-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["object-namespace-inventory"] = objectNamespace
	pipeInventory := byID["named-pipe-inventory"]
	pipeInventory.Title = "Named Pipe Inventory"
	pipeInventory.Capabilities = []string{"bounded named-pipe discovery"}
	pipeInventory.Arguments = []Argument{{Name: "prefix", Type: "string", Description: "case-insensitive pipe-name prefix; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum rows (1-512)", Default: "64"}}
	pipeInventory.ExpectedAnalysis = []string{"named_pipe_inventory"}
	pipeInventory.OutputFields = []string{"name", "shown", "limit", "prefix", "status"}
	pipeInventory.AnalysisSignatures = []AnalysisSignature{{ID: "named_pipe_inventory", Name: "Named-pipe inventory", Summary: "Enumerate bounded entries from the local named-pipe namespace.", Steps: []AnalysisStep{{Action: "open pipe namespace search", APIs: []string{"FindFirstFileA", "FindFirstFileW"}}, {Action: "enumerate pipe names", APIs: []string{"FindNextFileA", "FindNextFileW"}}}, RequiredStrings: []string{`\\.\pipe\*`}, Effects: []string{"reads named-pipe metadata"}}}
	pipeInventory.ProofCases = []ProofCase{{ID: "bounded", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"prefix": "", "result_limit": "16"}, Expect: ProofExpectation{Tag: "named-pipe-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["named-pipe-inventory"] = pipeInventory
	ldapQuery := byID["ldap-query"]
	ldapQuery.Title = "Bounded LDAP Query"
	ldapQuery.Capabilities = []string{"bounded LDAP directory query", "explicit attribute retrieval"}
	ldapQuery.Network = "domain"
	ldapQuery.Arguments = []Argument{{Name: "server", Type: "string", Description: "domain controller; empty discovers the current domain", Default: ""}, {Name: "base_dn", Type: "string", Description: "LDAP base DN; empty derives the current domain", Default: ""}, {Name: "filter", Type: "string", Description: "LDAP filter", Default: "(objectClass=*)"}, {Name: "attributes", Type: "string", Description: "comma-separated attributes (maximum eight)", Default: "distinguishedName"}, {Name: "result_limit", Type: "int", Description: "maximum directory entries (1-100)", Default: "25"}}
	ldapQuery.ExpectedAnalysis = []string{"ldap_directory_query"}
	ldapQuery.OutputFields = []string{"row", "dn", "attribute", "value", "shown", "limit", "server", "base", "filter", "status"}
	ldapQuery.AnalysisSignatures = []AnalysisSignature{{ID: "ldap_directory_query", Name: "LDAP directory query", Summary: "Discover a domain controller, authenticate with the current context, and issue a bounded LDAP search.", Steps: []AnalysisStep{{Action: "discover domain controller", APIs: []string{"DsGetDcNameA", "DsGetDcNameW"}}, {Action: "connect to LDAP", APIs: []string{"ldap_connect"}}, {Action: "bind current context", APIs: []string{"ldap_bind_sA", "ldap_bind_sW"}}, {Action: "search directory", APIs: []string{"ldap_search_sA", "ldap_search_sW", "ldap_search_ext_sA", "ldap_search_ext_sW"}}}, Effects: []string{"reaches a domain controller", "reads directory data"}, Requirements: []string{"domain connectivity", "directory read access"}}}
	byID["ldap-query"] = ldapQuery
	domainLDAP := func(id, title, summary, capability, filter, attributes string) Document {
		document := baseBuiltin(id, title, summary, []string{"ldap-query"}, []string{"reads directory data", "reaches a domain controller"})
		document.SchemaVersion = 4
		document.Capabilities = []string{capability}
		document.Network = "domain controller"
		document.Arguments = []Argument{
			{Name: "server", Type: "string", Description: "exact domain controller; topology supplies this when omitted", TopologyValue: "domain_controller.computer_name"},
			{Name: "base_dn", Type: "string", Description: "LDAP search base; topology supplies the domain base DN when omitted", TopologyValue: "domain.base_dn"},
			{Name: "filter", Type: "string", Description: "bounded LDAP filter", Default: filter},
			{Name: "attributes", Type: "string", Description: "comma-separated attributes (maximum eight)", Default: attributes},
			{Name: "result_limit", Type: "int", Description: "maximum directory entries (1-100)", Default: "25"},
		}
		document.ExpectedAnalysis = []string{id}
		document.OutputFields = []string{"row", "dn", "attribute", "value", "shown", "limit", "server", "base", "filter", "status"}
		document.AnalysisSignatures = []AnalysisSignature{{ID: id, Name: title, Summary: summary, Steps: []AnalysisStep{{Action: "connect and bind to LDAP", APIs: []string{"ldap_connect", "ldap_bind_sA", "ldap_bind_sW"}}, {Action: "search selected directory objects", APIs: []string{"ldap_search_sA", "ldap_search_sW", "ldap_search_ext_sA", "ldap_search_ext_sW"}}}, RequiredStrings: []string{"[ldap-query]"}, Effects: []string{"reaches a domain controller", "reads directory data"}, Requirements: []string{"domain connectivity", "directory read access"}}}
		document.ProofCases = []ProofCase{{ID: "domain-topology", Via: []string{"lab", "sliver"}, Roles: []string{"execution", "domain_controller"}, Arguments: map[string]string{"filter": filter, "attributes": attributes, "result_limit": "25"}, Expect: ProofExpectation{Tag: "ldap-query", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
		return document
	}
	byID["domain-controller-inventory"] = domainLDAP("domain_controller_inventory", "Domain Controller Inventory", "Enumerate bounded domain-controller computer accounts and operating-system metadata", "bounded domain-controller inventory", "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", "dNSHostName,operatingSystem,operatingSystemVersion")
	byID["domain-controller-inventory"] = func(document Document) Document { document.ID = "domain-controller-inventory"; return document }(byID["domain-controller-inventory"])
	byID["ldap-account-inventory"] = domainLDAP("ldap_account_inventory", "LDAP Account Inventory", "Enumerate bounded domain account identity and control metadata", "bounded LDAP account inventory", "(&(objectCategory=person)(objectClass=user))", "sAMAccountName,userPrincipalName,userAccountControl")
	byID["ldap-account-inventory"] = func(document Document) Document { document.ID = "ldap-account-inventory"; return document }(byID["ldap-account-inventory"])
	byID["ldap-spn-inventory"] = domainLDAP("ldap_spn_inventory", "LDAP SPN Inventory", "Enumerate bounded accounts and their registered service-principal names", "bounded LDAP SPN inventory", "(servicePrincipalName=*)", "sAMAccountName,servicePrincipalName")
	byID["ldap-spn-inventory"] = func(document Document) Document { document.ID = "ldap-spn-inventory"; return document }(byID["ldap-spn-inventory"])
	byID["ldap-delegation-inventory"] = domainLDAP("ldap_delegation_inventory", "LDAP Delegation Inventory", "Enumerate bounded constrained, resource-based, and unconstrained delegation metadata", "bounded LDAP delegation inventory", "(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))", "sAMAccountName,userAccountControl,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity")
	byID["ldap-delegation-inventory"] = func(document Document) Document { document.ID = "ldap-delegation-inventory"; return document }(byID["ldap-delegation-inventory"])
	byID["domain-trust-inventory"] = domainLDAP("domain_trust_inventory", "Domain Trust Inventory", "Enumerate bounded trusted-domain direction, type, and attribute metadata", "bounded domain trust inventory", "(objectClass=trustedDomain)", "name,trustDirection,trustType,trustAttributes")
	byID["domain-trust-inventory"] = func(document Document) Document { document.ID = "domain-trust-inventory"; return document }(byID["domain-trust-inventory"])
	byID["ldap-group-inventory"] = domainLDAP("ldap_group_inventory", "LDAP Group Inventory", "Enumerate bounded domain group identity, scope, and membership metadata", "bounded LDAP group inventory", "(objectCategory=group)", "sAMAccountName,groupType,member")
	byID["ldap-group-inventory"] = func(document Document) Document { document.ID = "ldap-group-inventory"; return document }(byID["ldap-group-inventory"])
	byID["ldap-computer-inventory"] = domainLDAP("ldap_computer_inventory", "LDAP Computer Inventory", "Enumerate bounded domain computer identity, operating-system, and account metadata", "bounded LDAP computer inventory", "(objectCategory=computer)", "dNSHostName,operatingSystem,operatingSystemVersion,userAccountControl")
	byID["ldap-computer-inventory"] = func(document Document) Document { document.ID = "ldap-computer-inventory"; return document }(byID["ldap-computer-inventory"])
	byID["ldap-gpo-inventory"] = domainLDAP("ldap_gpo_inventory", "LDAP GPO Inventory", "Enumerate bounded Group Policy object identity, version, and filesystem location metadata", "bounded LDAP GPO inventory", "(objectClass=groupPolicyContainer)", "displayName,name,versionNumber,gPCFileSysPath")
	byID["ldap-gpo-inventory"] = func(document Document) Document { document.ID = "ldap-gpo-inventory"; return document }(byID["ldap-gpo-inventory"])
	securityPackages := byID["security-package-inventory"]
	securityPackages.Title = "Security Package Inventory"
	securityPackages.Capabilities = []string{"Windows authentication package discovery", "SSPI capability inventory"}
	securityPackages.Arguments = []Argument{{Name: "name_filter", Type: "string", Description: "case-insensitive package-name substring; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum package rows (1-128)", Default: "25"}}
	securityPackages.ExpectedAnalysis = []string{"security_package_inventory"}
	securityPackages.OutputFields = []string{"name", "capabilities", "max_token", "comment", "shown", "total", "limit", "filter", "status"}
	securityPackages.AnalysisSignatures = []AnalysisSignature{{ID: "security_package_inventory", Name: "Windows authentication-package inventory", Summary: "Enumerate installed SSPI authentication and security-support packages with their declared capabilities.", Steps: []AnalysisStep{{Action: "enumerate security packages", APIs: []string{"EnumerateSecurityPackagesW", "EnumerateSecurityPackagesA"}}, {Action: "release package metadata", APIs: []string{"FreeContextBuffer"}}}, Effects: []string{"reads authentication package metadata"}, Requirements: []string{"local SSPI availability", "a result limit"}}}
	securityPackages.ProofCases = []ProofCase{{ID: "bounded", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"name_filter": "", "result_limit": "16"}, Expect: ProofExpectation{Tag: "security-package-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["security-package-inventory"] = securityPackages
	certificates := byID["certificate-store-inventory"]
	certificates.Title = "Certificate Store Inventory"
	certificates.Capabilities = []string{"certificate metadata discovery", "private-key availability discovery"}
	certificates.Arguments = []Argument{{Name: "scope", Type: "string", Description: "current_user or local_machine", Default: "current_user"}, {Name: "store", Type: "wstring", Description: "certificate store name", Default: "MY"}, {Name: "subject_filter", Type: "wstring", Description: "case-insensitive subject substring; empty matches all", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum certificate rows (1-256)", Default: "25"}}
	certificates.ExpectedAnalysis = []string{"certificate_store_inventory"}
	certificates.OutputFields = []string{"thumbprint", "subject", "issuer", "not_before", "not_after", "has_private_key", "shown", "limit", "scope", "status"}
	certificates.AnalysisSignatures = []AnalysisSignature{{ID: "certificate_store_inventory", Name: "Certificate-store inventory", Summary: "Open an explicit Windows certificate store and enumerate bounded identity, validity, thumbprint, and private-key metadata.", Steps: []AnalysisStep{{Action: "open certificate store", APIs: []string{"CertOpenStore", "CertOpenSystemStoreW", "CertOpenSystemStoreA"}}, {Action: "enumerate certificates", APIs: []string{"CertEnumCertificatesInStore"}}, {Action: "inspect certificate properties", APIs: []string{"CertGetCertificateContextProperty", "CertGetNameStringW", "CertGetNameStringA"}}}, Effects: []string{"reads certificate metadata", "reads private-key availability metadata"}, Requirements: []string{"read access to the selected certificate store", "an explicit store scope and name"}}}
	certificates.ProofCases = []ProofCase{{ID: "fixture-certificate", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"scope": "current_user", "store": "$CERT_STORE", "subject_filter": "$CERT_SUBJECT", "result_limit": "10"}, Expect: ProofExpectation{Tag: "certificate-store-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["certificate-store-inventory"] = certificates
	remoteHost := byID["remote-host-info"]
	remoteHost.Title = "Remote Host Information"
	remoteHost.Capabilities = []string{"exact-host workstation identity", "exact-host server role and version discovery"}
	remoteHost.Effects = []string{"reaches a supplied host", "reads host metadata"}
	remoteHost.Network = "explicit host"
	remoteHost.Arguments = []Argument{{Name: "target_host", Type: "wstring", Description: "exact Windows host name", Required: true}}
	remoteHost.ExpectedAnalysis = []string{"remote_host_information"}
	remoteHost.OutputFields = []string{"target", "computer", "workgroup", "platform", "major", "minor", "server_type", "comment", "status"}
	remoteHost.AnalysisSignatures = []AnalysisSignature{{ID: "remote_host_information", Name: "Exact-host workstation and server information", Summary: "Query workstation and server identity for one operator-supplied Windows host.", Steps: []AnalysisStep{{Action: "query workstation identity", APIs: []string{"NetWkstaGetInfo"}}, {Action: "query server role and version", APIs: []string{"NetServerGetInfo"}}}, RequiredStrings: []string{"[remote-host-info]"}, Effects: []string{"reaches a supplied host", "reads host metadata"}, Requirements: []string{"SMB/RPC access to the exact host"}}}
	remoteHost.ProofCases = []ProofCase{{ID: "named-host", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_host": "$LAB_HOST"}, Expect: ProofExpectation{Tag: "remote-host-info", Fields: map[string]string{"status": "complete", "target": "*"}}}}
	byID["remote-host-info"] = remoteHost
	remoteServices := byID["remote-service-inventory"]
	remoteServices.Title = "Remote Service Inventory"
	remoteServices.Capabilities = []string{"bounded exact-host service inventory", "remote service state and process discovery"}
	remoteServices.Effects = []string{"reaches a supplied host", "reads service metadata"}
	remoteServices.Network = "explicit host"
	remoteServices.Arguments = []Argument{{Name: "target_host", Type: "wstring", Description: "exact Windows host name", Required: true}, {Name: "name_filter", Type: "wstring", Description: "case-insensitive service name or display-name substring", Default: ""}, {Name: "state_filter", Type: "string", Description: "all, running, or stopped", Default: "all"}, {Name: "result_limit", Type: "int", Description: "maximum service rows (1-256)", Default: "32"}}
	remoteServices.ExpectedAnalysis = []string{"remote_service_inventory"}
	remoteServices.OutputFields = []string{"target", "name", "display", "state", "type", "pid", "shown", "examined", "pages", "limit", "filter", "status"}
	remoteServices.AnalysisSignatures = []AnalysisSignature{{ID: "remote_service_inventory", Name: "Exact-host service inventory", Summary: "Open the remote Service Control Manager and enumerate bounded service state and process metadata.", Steps: []AnalysisStep{{Action: "open remote service control manager", APIs: []string{"OpenSCManagerW", "OpenSCManagerA"}}, {Action: "enumerate service process state", APIs: []string{"EnumServicesStatusExW", "EnumServicesStatusExA"}}}, RequiredStrings: []string{"[remote-service-inventory]"}, Effects: []string{"reaches a supplied host", "reads service metadata"}, Requirements: []string{"remote SCM enumeration access", "RPC to the exact host"}}}
	remoteServices.ProofCases = []ProofCase{{ID: "target-service", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_host": "$LAB_HOST", "name_filter": "BOFBenchTarget", "state_filter": "running", "result_limit": "8"}, Expect: ProofExpectation{Tag: "remote-service-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["remote-service-inventory"] = remoteServices
	remoteTasks := byID["remote-task-inventory"]
	remoteTasks.Title = "Remote Scheduled Task Inventory"
	remoteTasks.Capabilities = []string{"bounded exact-host scheduled-task inventory", "remote task state and result discovery"}
	remoteTasks.Effects = []string{"reaches a supplied host", "reads scheduled-task metadata"}
	remoteTasks.Network = "explicit host"
	remoteTasks.Arguments = []Argument{{Name: "target_host", Type: "wstring", Description: "exact Windows host name", Required: true}, {Name: "name_filter", Type: "wstring", Description: "case-insensitive task-name substring", Default: ""}, {Name: "result_limit", Type: "int", Description: "maximum task rows (1-256)", Default: "32"}}
	remoteTasks.ExpectedAnalysis = []string{"remote_task_inventory"}
	remoteTasks.OutputFields = []string{"target", "name", "state", "last_result", "shown", "total", "limit", "filter", "status"}
	remoteTasks.AnalysisSignatures = []AnalysisSignature{{ID: "remote_task_inventory", Name: "Exact-host Task Scheduler inventory", Summary: "Connect to Task Scheduler on one supplied host and enumerate bounded task state and last-result metadata.", Steps: []AnalysisStep{{Action: "initialize Task Scheduler COM", APIs: []string{"CoCreateInstance"}}, {Action: "read task metadata", APIs: []string{"SysAllocString", "VariantClear"}}}, RequiredStrings: []string{"[remote-task-inventory]"}, Effects: []string{"reaches a supplied host", "reads scheduled-task metadata"}, Requirements: []string{"Task Scheduler RPC access to the exact host"}}}
	remoteTasks.ProofCases = []ProofCase{{ID: "named-host", Via: []string{"lab", "sliver"}, Arguments: map[string]string{"target_host": "$LAB_HOST", "name_filter": "", "result_limit": "8"}, Expect: ProofExpectation{Tag: "remote-task-inventory", Fields: map[string]string{"status": "complete", "shown": "*"}}}}
	byID["remote-task-inventory"] = remoteTasks
	for id, document := range byID {
		for _, feature := range document.Source.Features {
			if signature, ok := builtinContextSignature(feature); ok && !hasAnalysisSignature(document.AnalysisSignatures, signature.ID) {
				document.AnalysisSignatures = append(document.AnalysisSignatures, signature)
			}
		}
		if len(document.ExpectedAnalysis) > 0 && len(document.AnalysisSignatures) == 0 {
			document.ExpectedAnalysis = builtinExpectedAnalysis(document.Source.Features)
		} else if len(document.ExpectedAnalysis) > 0 && !hasSpecialPackSignature(document) {
			document.ExpectedAnalysis = builtinExpectedAnalysis(document.Source.Features)
		}
		byID[id] = document
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Resolved, 0, len(ids))
	for _, id := range ids {
		document := byID[id]
		item := Resolved{Document: document, Catalog: "builtin", Qualified: "builtin/" + id}
		item.SHA256, _ = fingerprint(item)
		out = append(out, item)
	}
	return out
}

func builtinContextSignature(feature string) (AnalysisSignature, bool) {
	switch feature {
	case "process":
		return AnalysisSignature{ID: "current_process_context", Name: "Current process context", Summary: "Read the current BOF loader process identifier.", Steps: []AnalysisStep{{Action: "read current process identifier", APIs: []string{"GetCurrentProcessId"}}}, Effects: []string{"reads process metadata"}}, true
	case "host":
		return AnalysisSignature{ID: "host_identity", Name: "Host identity", Summary: "Read the local computer name.", Steps: []AnalysisStep{{Action: "read computer name", APIs: []string{"GetComputerNameA", "GetComputerNameW"}}}, Effects: []string{"reads host metadata"}}, true
	case "filesystem":
		return AnalysisSignature{ID: "filesystem_context", Name: "Filesystem context", Summary: "Read the current Windows temporary-directory path.", Steps: []AnalysisStep{{Action: "read temporary path", APIs: []string{"GetTempPathA", "GetTempPathW"}}}, Effects: []string{"reads filesystem metadata"}}, true
	case "lab-run-key":
		return AnalysisSignature{ID: "run_key_persistence", Name: "Current-user Run-key persistence", Summary: "Create or open a current-user registry key and set a Run-key value.", Steps: []AnalysisStep{{Action: "open persistence key", APIs: []string{"RegCreateKeyExA", "RegCreateKeyExW"}}, {Action: "set persistence value", APIs: []string{"RegSetValueExA", "RegSetValueExW"}}}, Effects: []string{"writes registry state", "persists"}, Requirements: []string{"current-user registry write access"}}, true
	default:
		return AnalysisSignature{}, false
	}
}

func hasAnalysisSignature(signatures []AnalysisSignature, id string) bool {
	for _, signature := range signatures {
		if signature.ID == id {
			return true
		}
	}
	return false
}

func hasSpecialPackSignature(document Document) bool {
	for _, signature := range document.AnalysisSignatures {
		if signature.ID != "current_process_context" && signature.ID != "host_identity" && signature.ID != "filesystem_context" && signature.ID != "run_key_persistence" {
			return true
		}
	}
	return false
}

func builtinExpectedAnalysis(features []string) []string {
	mapping := map[string]string{
		"process": "current_process_context", "host": "host_identity", "identity": "identity_account_sid", "filesystem": "filesystem_context",
		"network": "network_tcp", "registry": "registry_read", "process-list": "process_inventory", "process-search": "process_inventory",
		"token-context": "token_context", "service-list": "service_inventory", "tcp-connections": "network_tcp", "domain-context": "domain_context",
		"lab-file-write": "file_write", "lab-registry-write": "registry_write", "lab-run-key": "run_key_persistence", "lab-process-launch": "process_launch", "lab-cleanup": "file_write",
	}
	var result []string
	for _, feature := range features {
		if expected := mapping[feature]; expected != "" && !contains(result, expected) {
			result = append(result, expected)
		}
	}
	return result
}

func baseBuiltin(id, title, summary string, features, effects []string) Document {
	return Document{
		Schema: Schema, SchemaVersion: SchemaVersion, ID: id, Version: "1.0.0", Title: title, Summary: summary, Tier: "public",
		Capabilities: append([]string(nil), features...), Effects: unique(effects), Platforms: []string{"windows"}, Architecture: []string{"x64", "x86"},
		Privilege: "user", Network: "none", Source: Source{Features: append([]string(nil), features...)},
		ExpectedAnalysis: append([]string(nil), features...), TargetSupport: []string{"native", "lab", "sliver", "cobaltstrike"},
	}
}

func effectForFeature(name string) []string {
	switch name {
	case "lab-file-write", "lab-registry-write", "lab-cleanup":
		return []string{"writes state"}
	case "lab-run-key":
		return []string{"writes state", "persists"}
	case "lab-process-launch":
		return []string{"starts execution", "writes state"}
	case "network", "tcp-connections", "domain-context":
		return []string{"reads data", "reaches network"}
	default:
		return []string{"reads data"}
	}
}

func effectsForImpact(impact string) []string {
	if impact == "read_only" {
		return []string{"reads data"}
	}
	return []string{"writes state"}
}

func validate(document Document, root string) error {
	var problems []string
	if document.Schema != Schema || document.SchemaVersion < MinimumSchemaVersion || document.SchemaVersion > SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema must be %s version %d or %d", Schema, MinimumSchemaVersion, SchemaVersion))
	}
	if document.SchemaVersion == 1 && (len(document.AnalysisSignatures) > 0 || len(document.ProofCases) > 0) {
		problems = append(problems, "analysis_signatures and proof_cases require schema version 2")
	}
	usesV3 := len(document.SensitiveOutputFields) > 0 || len(document.CleanupArguments) > 0
	usesV4 := false
	for _, argument := range document.Arguments {
		usesV3 = usesV3 || argument.Sensitive
		usesV4 = usesV4 || argument.TopologyValue != ""
	}
	for _, proof := range document.ProofCases {
		usesV3 = usesV3 || proof.Expect.Payload != nil || len(proof.StateChecks) > 0 || len(proof.CleanupSteps) > 0
		usesV4 = usesV4 || len(proof.Roles) > 0 || len(proof.Captures) > 0
		for _, check := range proof.StateChecks {
			usesV4 = usesV4 || check.Role != ""
		}
	}
	if document.SchemaVersion < 3 && usesV3 {
		problems = append(problems, "sensitive fields, cleanup mappings, payload expectations, state checks, and cleanup steps require schema version 3")
	}
	if document.SchemaVersion < 4 && usesV4 {
		problems = append(problems, "topology defaults, proof roles, captures, and role-specific state checks require schema version 4")
	}
	if !idPattern.MatchString(document.ID) {
		problems = append(problems, "id must contain lowercase letters, numbers, dot, underscore, or hyphen")
	}
	if strings.TrimSpace(document.Version) == "" || strings.TrimSpace(document.Title) == "" || strings.TrimSpace(document.Summary) == "" {
		problems = append(problems, "version, title, and summary are required")
	}
	if document.Tier != "public" && document.Tier != "internal" {
		problems = append(problems, "tier must be public or internal")
	}
	if len(document.Capabilities) == 0 || len(document.Effects) == 0 || len(document.Platforms) == 0 || len(document.Architecture) == 0 || len(document.TargetSupport) == 0 {
		problems = append(problems, "capabilities, effects, platforms, architecture, and target_support must not be empty")
	}
	if len(document.Source.Features) == 0 && len(document.Source.HeaderFragments) == 0 {
		problems = append(problems, "source must declare features or header_fragments")
	}
	seenArgs := map[string]bool{}
	for _, argument := range document.Arguments {
		if !idPattern.MatchString(argument.Name) {
			problems = append(problems, fmt.Sprintf("invalid argument name %q", argument.Name))
		}
		if seenArgs[argument.Name] {
			problems = append(problems, fmt.Sprintf("duplicate argument %q", argument.Name))
		}
		seenArgs[argument.Name] = true
		if !contains([]string{"string", "wstring", "int", "short", "bytes", "file"}, argument.Type) {
			problems = append(problems, fmt.Sprintf("argument %s has unsupported type %q", argument.Name, argument.Type))
		}
		if argument.TopologyValue != "" && !contains([]string{
			"execution.computer_name", "target.computer_name", "domain_controller.computer_name", "domain.name", "domain.base_dn",
		}, argument.TopologyValue) {
			problems = append(problems, fmt.Sprintf("argument %s has unsupported topology_value %q", argument.Name, argument.TopologyValue))
		}
	}
	for _, relative := range document.Source.HeaderFragments {
		if _, err := safeSourcePath(root, relative); err != nil {
			problems = append(problems, err.Error())
		}
	}
	outputFields := map[string]bool{}
	for _, field := range document.OutputFields {
		outputFields[field] = true
	}
	for _, field := range document.SensitiveOutputFields {
		if !outputFields[field] {
			problems = append(problems, fmt.Sprintf("sensitive output field %q is not declared in output_fields", field))
		}
	}
	if len(document.CleanupArguments) > 0 && document.CleanupPack == "" {
		problems = append(problems, "cleanup_arguments requires cleanup_pack")
	}
	for target, expression := range document.CleanupArguments {
		if !idPattern.MatchString(target) {
			problems = append(problems, fmt.Sprintf("invalid cleanup argument %q", target))
			continue
		}
		if !strings.HasPrefix(expression, "$arg.") || !seenArgs[strings.TrimPrefix(expression, "$arg.")] {
			problems = append(problems, fmt.Sprintf("cleanup argument %s must reference a declared argument as $arg.<name>", target))
		}
	}
	seenSignatures := map[string]bool{}
	for _, signature := range document.AnalysisSignatures {
		if !idPattern.MatchString(signature.ID) {
			problems = append(problems, fmt.Sprintf("invalid analysis signature id %q", signature.ID))
		}
		if seenSignatures[signature.ID] {
			problems = append(problems, fmt.Sprintf("duplicate analysis signature %q", signature.ID))
		}
		seenSignatures[signature.ID] = true
		if strings.TrimSpace(signature.Name) == "" || strings.TrimSpace(signature.Summary) == "" || len(signature.Steps) == 0 || len(signature.Effects) == 0 {
			problems = append(problems, fmt.Sprintf("analysis signature %s requires name, summary, steps, and effects", signature.ID))
		}
		for _, step := range signature.Steps {
			if strings.TrimSpace(step.Action) == "" || len(step.APIs) == 0 {
				problems = append(problems, fmt.Sprintf("analysis signature %s has an incomplete step", signature.ID))
			}
		}
	}
	allowedPlaceholders := map[string]bool{
		"$TARGET_PID": true, "$TARGET_TID": true, "$TARGET_HANDLE": true,
		"$MEMORY_ADDRESS": true, "$MEMORY_SIZE": true, "$MEMORY_SHA256": true, "$CANARY_PATH": true, "$CANARY_SHA256": true,
		"$MEMORY_WRITE_ADDRESS": true, "$MEMORY_WRITE_SIZE": true, "$MEMORY_WRITE_SHA256": true,
		"$MEMORY_PROTECTION_ADDRESS": true, "$MEMORY_PROTECTION_SIZE": true, "$MEMORY_PROTECTION": true,
		"$CREDENTIAL_TARGET": true, "$CREDENTIAL_SHA256": true, "$CREDENTIAL_SIZE": true,
		"$DPAPI_USER_PATH": true, "$DPAPI_USER_SHA256": true, "$DPAPI_MACHINE_PATH": true, "$DPAPI_MACHINE_SHA256": true,
		"$VAULT_GUID": true, "$VAULT_RESOURCE": true, "$VAULT_IDENTITY": true, "$VAULT_SHA256": true, "$VAULT_SIZE": true,
		"$CERT_THUMBPRINT": true, "$CERT_STORE": true, "$CERT_SUBJECT": true,
		"$LAB_HOST": true, "$SERVICE_BINARY": true, "$WMI_MARKER_PATH": true, "$TEMP": true, "$RUN_ID": true, "$PROOF_SECRET": true,
		"$PROOF_SECRET_SHA256": true, "$PROOF_SECRET_CRLF_SHA256": true, "$PROOF_SECRET_PATH": true,
		"$REMOTE_REGISTRY_HIVE": true, "$REMOTE_REGISTRY_PATH": true, "$REMOTE_REGISTRY_NAME": true, "$REMOTE_REGISTRY_SHA256": true, "$REMOTE_REGISTRY_SIZE": true,
		"$REMOTE_STAGE_SHARE": true, "$REMOTE_STAGE_RELATIVE_ROOT": true, "$REMOTE_STAGE_LOCAL_ROOT": true,
		"$REMOTE_STAGE_RELATIVE": true, "$REMOTE_STAGE_LOCAL_PATH": true, "$REMOTE_TASK_NAME": true, "$REMOTE_TASK_MARKER_PATH": true,
		"$PAYLOAD_RET_PATH": true,
	}
	seenProofs := map[string]bool{}
	for _, proof := range document.ProofCases {
		if !idPattern.MatchString(proof.ID) || seenProofs[proof.ID] {
			problems = append(problems, fmt.Sprintf("invalid or duplicate proof case id %q", proof.ID))
		}
		seenProofs[proof.ID] = true
		proofPlaceholders := make(map[string]bool, len(allowedPlaceholders)+len(proof.Captures))
		for key, value := range allowedPlaceholders {
			proofPlaceholders[key] = value
		}
		seenRoles := map[string]bool{}
		for _, role := range proof.Roles {
			if !contains([]string{"execution", "target", "domain_controller"}, role) || seenRoles[role] {
				problems = append(problems, fmt.Sprintf("proof case %s has invalid or duplicate role %q", proof.ID, role))
			}
			seenRoles[role] = true
		}
		for placeholder, capture := range proof.Captures {
			if !placeholderPattern.MatchString(placeholder) || placeholderPattern.FindString(placeholder) != placeholder || !strings.HasPrefix(placeholder, "$") {
				problems = append(problems, fmt.Sprintf("proof case %s has invalid capture placeholder %q", proof.ID, placeholder))
				continue
			}
			if proofPlaceholders[placeholder] {
				problems = append(problems, fmt.Sprintf("proof case %s capture %q conflicts with a built-in placeholder", proof.ID, placeholder))
			}
			if !idPattern.MatchString(capture.Tag) || !idPattern.MatchString(capture.Field) {
				problems = append(problems, fmt.Sprintf("proof case %s capture %s requires a valid tag and field", proof.ID, placeholder))
			}
			proofPlaceholders[placeholder] = true
		}
		validateProofPlaceholders := func(value string) {
			for _, placeholder := range placeholderPattern.FindAllString(value, -1) {
				if !proofPlaceholders[placeholder] {
					problems = append(problems, fmt.Sprintf("proof case %s uses unsupported placeholder %q", proof.ID, placeholder))
				}
			}
		}
		if len(proof.Via) == 0 || !idPattern.MatchString(proof.Expect.Tag) {
			problems = append(problems, fmt.Sprintf("proof case %s requires via and a valid expected tag", proof.ID))
		}
		for _, via := range proof.Via {
			if !contains([]string{"native", "lab", "sliver", "cobaltstrike"}, via) {
				problems = append(problems, fmt.Sprintf("proof case %s has unsupported runtime %q", proof.ID, via))
			}
		}
		for name, value := range proof.Arguments {
			if !seenArgs[name] {
				problems = append(problems, fmt.Sprintf("proof case %s uses unknown argument %q", proof.ID, name))
			}
			validateProofPlaceholders(value)
		}
		if proof.Cleanup && document.CleanupPack == "" {
			problems = append(problems, fmt.Sprintf("proof case %s requests cleanup but the pack has no cleanup companion", proof.ID))
		}
		if proof.Cleanup && len(proof.CleanupSteps) > 0 {
			problems = append(problems, fmt.Sprintf("proof case %s cannot use cleanup and cleanup_steps together", proof.ID))
		}
		if payload := proof.Expect.Payload; payload != nil {
			if !idPattern.MatchString(payload.Tag) || !idPattern.MatchString(payload.Field) || !contains([]string{"hex", "base64"}, payload.Encoding) || strings.TrimSpace(payload.SHA256) == "" {
				problems = append(problems, fmt.Sprintf("proof case %s has an invalid payload expectation", proof.ID))
			}
			validateProofPlaceholders(payload.SHA256)
		}
		for _, step := range proof.CleanupSteps {
			if strings.TrimSpace(step.Pack) == "" {
				problems = append(problems, fmt.Sprintf("proof case %s cleanup step requires pack", proof.ID))
			}
			for _, value := range step.Arguments {
				validateProofPlaceholders(value)
			}
		}
		stateParameters := map[string][]string{
			"file": {"path"}, "startup_file": {"name"}, "registry_value": {"hive", "path", "name"}, "service": {"name"},
			"scheduled_task": {"name"}, "credential": {"target"}, "certificate": {"scope", "store", "thumbprint"},
			"dpapi_file": {"path", "sha256"}, "pfx": {"path", "password", "thumbprint"},
			"process_memory": {"pid", "address", "size", "sha256"}, "process_protection": {"pid", "address", "protection"},
			"process": {"pid", "image", "marker"},
		}
		for _, check := range proof.StateChecks {
			required, ok := stateParameters[check.Kind]
			if !contains([]string{"after_run", "after_cleanup"}, check.Phase) || !ok || !contains([]string{"present", "absent", "matches"}, check.Expect) {
				problems = append(problems, fmt.Sprintf("proof case %s has an invalid state check", proof.ID))
				continue
			}
			if check.Role != "" && !contains([]string{"execution", "target", "domain_controller"}, check.Role) {
				problems = append(problems, fmt.Sprintf("proof case %s state check has invalid role %q", proof.ID, check.Role))
			}
			for _, key := range required {
				if strings.TrimSpace(check.Parameters[key]) == "" {
					problems = append(problems, fmt.Sprintf("proof case %s state check %s requires %s", proof.ID, check.Kind, key))
				}
			}
			for _, value := range check.Parameters {
				validateProofPlaceholders(value)
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func decodeDocument(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return document, nil
}

func (item Resolved) sourceDeclaration() (string, error) {
	var fragments []string
	for _, relative := range item.Document.Source.HeaderFragments {
		path, err := safeSourcePath(item.Root, relative)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read pack source %s: %w", path, err)
		}
		fragments = append(fragments, string(data))
	}
	return strings.Join(fragments, "\n"), nil
}

func safeSourcePath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("pack source path must be relative: %q", relative)
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("pack source path escapes its catalog: %q", relative)
	}
	path := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("pack source path escapes its catalog: %q", relative)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("pack source %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("pack source is not a regular file: %q", relative)
	}
	return path, nil
}

func fingerprint(item Resolved) (string, error) {
	hash := sha256.New()
	data, err := json.Marshal(item.Document)
	if err != nil {
		return "", err
	}
	hash.Write(data)
	for _, relative := range item.Document.Source.HeaderFragments {
		path, pathErr := safeSourcePath(item.Root, relative)
		if pathErr != nil {
			return "", pathErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", readErr
		}
		hash.Write([]byte(relative))
		hash.Write(data)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *Registry) recipeRecord(project string) (string, LockRecord, error) {
	document, path, err := recipe.LoadFor(project)
	if os.IsNotExist(err) {
		return "", LockRecord{}, nil
	}
	if err != nil {
		return "", LockRecord{}, err
	}
	item, err := r.Resolve(document.Name)
	if err != nil {
		return "", LockRecord{}, fmt.Errorf("migrate %s: %w", path, err)
	}
	return path, lockRecord(item), nil
}

func lockRecord(item Resolved) LockRecord {
	return LockRecord{ID: item.Document.ID, Qualified: item.Qualified, Catalog: item.Catalog, CatalogRoot: item.CatalogRoot, Version: item.Document.Version, SHA256: item.SHA256, Arguments: append([]Argument(nil), item.Document.Arguments...), Cleanup: item.Document.CleanupPack, CleanupArguments: cloneStringMap(item.Document.CleanupArguments), SensitiveOutputFields: append([]string(nil), item.Document.SensitiveOutputFields...)}
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func loadLock(root string) (Lock, error) {
	lock := Lock{Schema: LockSchema, SchemaVersion: LockSchemaVersion, Packs: []LockRecord{}}
	path := filepath.Join(root, LockName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return lock, nil
	}
	if err != nil {
		return Lock{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if lock.Schema != LockSchema || lock.SchemaVersion != LockSchemaVersion {
		return Lock{}, fmt.Errorf("unsupported pack lock in %s", path)
	}
	return lock, nil
}

func saveCatalogConfig(config CatalogConfig) error {
	path, err := catalogConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeJSON(path, config)
}

func catalogConfigPath() (string, error) {
	if root := strings.TrimSpace(os.Getenv("BOFBENCH_CONFIG_HOME")); root != "" {
		return filepath.Join(root, "catalogs.json"), nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "bofbench", "catalogs.json"), nil
}

func catalogCacheDir() (string, error) {
	if root := strings.TrimSpace(os.Getenv("BOFBENCH_CACHE_HOME")); root != "" {
		return filepath.Join(root, "catalogs"), nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "bofbench", "catalogs"), nil
}

func catalogName(source string) string {
	value := strings.TrimSuffix(strings.TrimSuffix(source, "/"), ".git")
	value = filepath.Base(value)
	value = strings.ToLower(strings.NewReplacer(" ", "-", "_", "-").Replace(value))
	if value == "." || value == "" {
		return "catalog"
	}
	return value
}

func isGitSource(source string) bool {
	lower := strings.ToLower(source)
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "ssh://") || strings.HasPrefix(lower, "git@") || strings.HasSuffix(lower, ".git")
}

func projectDir(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return filepath.Dir(path)
	}
	return path
}

func splitNames(values []string) []string {
	var out []string
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func appendUnique(values []string, value string) []string {
	if contains(values, value) {
		return values
	}
	return append(values, value)
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
