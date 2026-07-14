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
	Schema            = "bofbench.pack"
	SchemaVersion     = 1
	LockSchema        = "bofbench.pack-lock"
	LockSchemaVersion = 1
	LockName          = "bofbench.lock.json"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type Argument struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Default     string `json:"default,omitempty"`
}

type Source struct {
	Features        []string `json:"features,omitempty"`
	HeaderFragments []string `json:"header_fragments,omitempty"`
	Calls           []string `json:"calls,omitempty"`
}

type Document struct {
	Schema           string     `json:"schema"`
	SchemaVersion    int        `json:"schema_version"`
	ID               string     `json:"id"`
	Version          string     `json:"version"`
	Title            string     `json:"title"`
	Summary          string     `json:"summary"`
	Tier             string     `json:"tier"`
	Capabilities     []string   `json:"capabilities"`
	Effects          []string   `json:"effects"`
	Platforms        []string   `json:"platforms"`
	Architecture     []string   `json:"architecture"`
	Privilege        string     `json:"privilege"`
	Network          string     `json:"network"`
	Arguments        []Argument `json:"arguments,omitempty"`
	Dependencies     []string   `json:"dependencies,omitempty"`
	Source           Source     `json:"source"`
	ExpectedAnalysis []string   `json:"expected_analysis,omitempty"`
	OutputFields     []string   `json:"output_fields,omitempty"`
	CleanupPack      string     `json:"cleanup_pack,omitempty"`
	TargetSupport    []string   `json:"target_support"`
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
	ID          string     `json:"id"`
	Qualified   string     `json:"qualified"`
	Catalog     string     `json:"catalog"`
	CatalogRoot string     `json:"catalog_root,omitempty"`
	Version     string     `json:"version"`
	SHA256      string     `json:"sha256"`
	Arguments   []Argument `json:"arguments,omitempty"`
	Cleanup     string     `json:"cleanup_pack,omitempty"`
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
		name := strings.ToLower(filepath.Base(filepath.Clean(path)))
		if err := loadCatalog(path, name); err != nil {
			return nil, err
		}
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
			if err := apply(dependency); err != nil {
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
	systemDiscovery := byID["system-discovery"]
	systemDiscovery.Source.Features = []string{"process-search", "token-context", "service-list"}
	systemDiscovery.Capabilities = []string{"filtered process discovery", "token context discovery", "service discovery"}
	systemDiscovery.Arguments = append([]Argument(nil), processArguments...)
	systemDiscovery.OutputFields = []string{"pid", "image", "elevated", "integrity", "service", "state", "status"}
	systemDiscovery.ExpectedAnalysis = []string{"process enumeration", "token inspection", "service enumeration", "Beacon argument parsing"}
	byID["system-discovery"] = systemDiscovery
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
	if document.Schema != Schema || document.SchemaVersion != SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema must be %s version %d", Schema, SchemaVersion))
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
	}
	for _, relative := range document.Source.HeaderFragments {
		if _, err := safeSourcePath(root, relative); err != nil {
			problems = append(problems, err.Error())
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
	return LockRecord{ID: item.Document.ID, Qualified: item.Qualified, Catalog: item.Catalog, CatalogRoot: item.CatalogRoot, Version: item.Document.Version, SHA256: item.SHA256, Arguments: append([]Argument(nil), item.Document.Arguments...), Cleanup: item.Document.CleanupPack}
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
