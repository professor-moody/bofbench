package arsenal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bofbench/internal/artifact"
	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
)

const LockFileName = "arsenal.lock.json"

const (
	arsenalIndexSchema        = "bofbench.arsenal-index"
	arsenalIndexSchemaVersion = 2
	analyzerCacheVersion      = "behavior-v2"
)

type Inventory struct {
	evidence.Header
	Root            string                    `json:"root"`
	Query           string                    `json:"query,omitempty"`
	Filters         InventoryFilters          `json:"filters,omitempty"`
	RootFingerprint *evidence.TreeFingerprint `json:"root_fingerprint,omitempty"`
	Source          *SourceMetadata           `json:"source,omitempty"`
	GeneratedAt     string                    `json:"generated_at"`
	Status          string                    `json:"status"`
	Summary         InventorySummary          `json:"summary"`
	Entries         []InventoryEntry          `json:"entries"`
	JSONPath        string                    `json:"json_path,omitempty"`
	MarkdownPath    string                    `json:"markdown_path,omitempty"`
	IndexPath       string                    `json:"index_path,omitempty"`
	SignatureSet    string                    `json:"analyzer_signature_set"`
}

type InventorySummary struct {
	Entries         int            `json:"entries"`
	WithSource      int            `json:"with_source"`
	X64Objects      int            `json:"x64_objects"`
	X86Objects      int            `json:"x86_objects"`
	Compatible      int            `json:"compatible"`
	RuntimeLookup   int            `json:"runtime_lookup"`
	Blocked         int            `json:"blocked"`
	AnalysisFailed  int            `json:"analysis_failed"`
	NeedsArguments  int            `json:"needs_arguments"`
	DuplicateGroups int            `json:"duplicate_groups"`
	CacheHits       int            `json:"cache_hits"`
	Refreshed       int            `json:"refreshed"`
	ByCapability    map[string]int `json:"by_capability,omitempty"`
}

// InventoryFilters describe operator-facing behavior filters. Every populated
// field must match, while values inside a field use case-insensitive substring
// matching so "token" can find token inspection and token impersonation.
type InventoryFilters struct {
	Query      string `json:"query,omitempty"`
	Can        string `json:"can,omitempty"`
	API        string `json:"api,omitempty"`
	Chain      string `json:"chain,omitempty"`
	Effect     string `json:"effect,omitempty"`
	WorksWith  string `json:"works_with,omitempty"`
	Requires   string `json:"requires,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Loader     string `json:"loader,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	HasArgs    *bool  `json:"has_args,omitempty"`
}

type InventoryEntry struct {
	Name             string                    `json:"name"`
	Path             string                    `json:"path"`
	HasSource        bool                      `json:"has_source"`
	SourceFiles      []string                  `json:"source_files,omitempty"`
	Objects          []LockedObject            `json:"objects,omitempty"`
	Compatibility    string                    `json:"compatibility,omitempty"`
	Entrypoint       string                    `json:"entrypoint,omitempty"`
	Relocations      int                       `json:"relocations,omitempty"`
	NeedsArgs        bool                      `json:"needs_args,omitempty"`
	ArgumentAPIs     []string                  `json:"argument_apis,omitempty"`
	APIs             []string                  `json:"apis,omitempty"`
	Capabilities     []string                  `json:"capabilities,omitempty"`
	CapabilityIDs    []string                  `json:"capability_ids,omitempty"`
	BehaviorChains   []string                  `json:"behavior_chains,omitempty"`
	Confidences      []string                  `json:"confidences,omitempty"`
	Effects          []string                  `json:"effects,omitempty"`
	Requirements     []string                  `json:"requirements,omitempty"`
	WorksWith        []string                  `json:"works_with,omitempty"`
	Arguments        []artifact.ArgumentHint   `json:"arguments,omitempty"`
	SourceAndVersion artifact.SourceAndVersion `json:"source_and_version"`
	VisibleStrings   []string                  `json:"visible_strings,omitempty"`
	AnalysisError    string                    `json:"analysis_error,omitempty"`
	AnalysisCached   bool                      `json:"analysis_cached,omitempty"`
	Architectures    []ArchitectureInventory   `json:"architectures,omitempty"`
}

type ArchitectureInventory struct {
	Arch           string                  `json:"arch"`
	Path           string                  `json:"path"`
	ObjectSHA256   string                  `json:"object_sha256"`
	Compatibility  string                  `json:"loader_support,omitempty"`
	Entrypoint     string                  `json:"entrypoint,omitempty"`
	Relocations    int                     `json:"relocations,omitempty"`
	NeedsArgs      bool                    `json:"needs_args,omitempty"`
	APIs           []string                `json:"apis,omitempty"`
	Capabilities   []string                `json:"capabilities,omitempty"`
	CapabilityIDs  []string                `json:"capability_ids,omitempty"`
	BehaviorChains []string                `json:"behavior_chains,omitempty"`
	Effects        []string                `json:"effects,omitempty"`
	WorksWith      []string                `json:"works_with,omitempty"`
	Arguments      []artifact.ArgumentHint `json:"arguments,omitempty"`
	AnalysisCached bool                    `json:"analysis_cached,omitempty"`
	AnalysisError  string                  `json:"analysis_error,omitempty"`
}

type arsenalAnalysisIndex struct {
	Schema        string                              `json:"schema"`
	SchemaVersion int                                 `json:"schema_version"`
	Root          string                              `json:"root"`
	UpdatedAt     string                              `json:"updated_at"`
	Entries       map[string]arsenalAnalysisIndexItem `json:"entries"`
}

type arsenalAnalysisIndexItem struct {
	ObjectSHA256 string            `json:"object_sha256"`
	Architecture string            `json:"architecture"`
	ObjectPath   string            `json:"object_path"`
	Source       string            `json:"source_version"`
	SignatureSet string            `json:"analyzer_signature_set"`
	Analysis     artifact.Analysis `json:"analysis"`
}

type ArchitectureMatrix struct {
	Schema        string                    `json:"schema"`
	SchemaVersion int                       `json:"schema_version"`
	Root          string                    `json:"root"`
	GeneratedAt   string                    `json:"generated_at"`
	IndexPath     string                    `json:"index_path"`
	SignatureSet  string                    `json:"analyzer_signature_set"`
	Summary       ArchitectureMatrixSummary `json:"summary"`
	Entries       []ArchitectureMatrixEntry `json:"entries"`
}

type ArchitectureMatrixSummary struct {
	Entries       int `json:"entries"`
	Pairs         int `json:"pairs"`
	Equivalent    int `json:"equivalent"`
	Different     int `json:"different"`
	X64Only       int `json:"x64_only"`
	X86Only       int `json:"x86_only"`
	AnalysisError int `json:"analysis_error"`
	CacheHits     int `json:"cache_hits"`
	Refreshed     int `json:"refreshed"`
}

type ArchitectureMatrixEntry struct {
	Name           string                 `json:"name"`
	Path           string                 `json:"path"`
	SourceFiles    []string               `json:"source_files,omitempty"`
	X64            *ArchitectureInventory `json:"x64,omitempty"`
	X86            *ArchitectureInventory `json:"x86,omitempty"`
	Equivalent     bool                   `json:"equivalent"`
	Differences    []string               `json:"differences,omitempty"`
	CorpusBlockers []string               `json:"corpus_blockers,omitempty"`
}

type Lock struct {
	evidence.Header
	Root              string                   `json:"root"`
	RootFingerprint   evidence.TreeFingerprint `json:"root_fingerprint"`
	SourceFingerprint evidence.TreeFingerprint `json:"source_fingerprint"`
	Source            *SourceMetadata          `json:"source,omitempty"`
	GeneratedAt       string                   `json:"generated_at"`
	Entries           []LockedEntry            `json:"entries"`
}

type LockedEntry struct {
	Name        string         `json:"name"`
	Path        string         `json:"path"`
	HasSource   bool           `json:"has_source"`
	SourceFiles []string       `json:"source_files,omitempty"`
	Objects     []LockedObject `json:"objects,omitempty"`
}

type LockedObject struct {
	Arch   string `json:"arch"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type LockDiff struct {
	evidence.Header
	Baseline      string       `json:"baseline"`
	Current       string       `json:"current"`
	Status        string       `json:"status"`
	SourceChanged bool         `json:"source_changed"`
	Added         []string     `json:"added,omitempty"`
	Removed       []string     `json:"removed,omitempty"`
	Changed       []LockChange `json:"changed,omitempty"`
	GeneratedAt   string       `json:"generated_at"`
	EvidencePath  string       `json:"evidence_path,omitempty"`
	MarkdownPath  string       `json:"markdown_path,omitempty"`
}

type LockChange struct {
	Key            string `json:"key"`
	BaselineSHA256 string `json:"baseline_sha256"`
	CurrentSHA256  string `json:"current_sha256"`
	BaselineSize   int64  `json:"baseline_size"`
	CurrentSize    int64  `json:"current_size"`
}

type RegressionReport struct {
	evidence.Header
	Baseline     string             `json:"baseline"`
	Current      string             `json:"current"`
	EvidenceType string             `json:"evidence_type"`
	Status       string             `json:"status"`
	Summary      RegressionSummary  `json:"summary"`
	Changes      []RegressionChange `json:"changes,omitempty"`
	GeneratedAt  string             `json:"generated_at"`
	EvidencePath string             `json:"evidence_path,omitempty"`
	MarkdownPath string             `json:"markdown_path,omitempty"`
}

type RegressionSummary struct {
	Baseline    int `json:"baseline"`
	Current     int `json:"current"`
	Unchanged   int `json:"unchanged"`
	Added       int `json:"added"`
	Removed     int `json:"removed"`
	Changed     int `json:"changed"`
	Improved    int `json:"improved"`
	Regressions int `json:"regressions"`
}

type RegressionChange struct {
	Key            string `json:"key"`
	Classification string `json:"classification"`
	BeforeStatus   string `json:"before_status,omitempty"`
	AfterStatus    string `json:"after_status,omitempty"`
	BeforeSHA256   string `json:"before_sha256,omitempty"`
	AfterSHA256    string `json:"after_sha256,omitempty"`
	BeforeDetail   string `json:"before_detail,omitempty"`
	AfterDetail    string `json:"after_detail,omitempty"`
}

type regressionItem struct {
	Key    string
	Status string
	SHA256 string
	Detail string
}

func BuildInventory(root, query string) (Inventory, error) {
	return BuildInventoryWithFilters(root, InventoryFilters{Query: query})
}

func BuildInventoryWithFilters(root string, filters InventoryFilters) (Inventory, error) {
	return BuildInventoryWithSignatures(root, filters, nil)
}

func BuildInventoryWithSignatures(root string, filters InventoryFilters, signatures []artifact.DeclarativeSignature) (Inventory, error) {
	entries, err := List(root)
	if err != nil {
		return Inventory{}, err
	}
	signatureSet := analyzerSignatureSet(signatures)
	indexPath, index := loadArsenalAnalysisIndex(root)
	report := Inventory{
		Header: evidence.New(evidence.SchemaArsenalInventory, "", ""), Root: root, Query: strings.TrimSpace(filters.Query), Filters: filters,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), Status: "pass", Summary: InventorySummary{ByCapability: map[string]int{}},
		IndexPath: indexPath, SignatureSet: signatureSet,
	}
	if fingerprint, err := evidence.FingerprintTree(root); err == nil {
		report.RootFingerprint = &fingerprint
	} else {
		return Inventory{}, err
	}
	if source, err := loadSourceMetadata(root); err == nil {
		report.Source = &source
	}
	sourceVersion := arsenalSourceVersion(report.Source, root)
	for _, entry := range entries {
		item := inventoryEntry(root, entry, sourceVersion, signatureSet, signatures, &index)
		if matchesInventoryFilters(item, filters) {
			report.Entries = append(report.Entries, item)
		}
	}
	summarizeInventory(&report)
	if err := writeArsenalAnalysisIndex(indexPath, index); err != nil {
		return Inventory{}, err
	}
	return report, nil
}

func BuildArchitectureMatrix(root string, signatures []artifact.DeclarativeSignature) (ArchitectureMatrix, error) {
	inventory, err := BuildInventoryWithSignatures(root, InventoryFilters{}, signatures)
	if err != nil {
		return ArchitectureMatrix{}, err
	}
	report := ArchitectureMatrix{
		Schema: "bofbench.arsenal-matrix", SchemaVersion: 1, Root: root,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), IndexPath: inventory.IndexPath, SignatureSet: inventory.SignatureSet,
	}
	for _, inventoryEntry := range inventory.Entries {
		entry := ArchitectureMatrixEntry{Name: inventoryEntry.Name, Path: inventoryEntry.Path, SourceFiles: append([]string(nil), inventoryEntry.SourceFiles...)}
		for index := range inventoryEntry.Architectures {
			architecture := inventoryEntry.Architectures[index]
			switch architecture.Arch {
			case "x64":
				entry.X64 = &architecture
			case "x86":
				entry.X86 = &architecture
			}
			if architecture.AnalysisError != "" {
				report.Summary.AnalysisError++
			}
			if architecture.AnalysisCached {
				report.Summary.CacheHits++
			} else if architecture.AnalysisError == "" {
				report.Summary.Refreshed++
			}
			if architecture.Compatibility != "" && architecture.Compatibility != "compatible" && architecture.Compatibility != "compatible_runtime_lookup" {
				entry.CorpusBlockers = append(entry.CorpusBlockers, architecture.Arch+": "+architecture.Compatibility)
			}
		}
		switch {
		case entry.X64 != nil && entry.X86 != nil:
			report.Summary.Pairs++
			entry.Differences = architectureDifferences(*entry.X64, *entry.X86)
			entry.Equivalent = len(entry.Differences) == 0
			if entry.Equivalent {
				report.Summary.Equivalent++
			} else {
				report.Summary.Different++
			}
		case entry.X64 != nil:
			report.Summary.X64Only++
			entry.Differences = []string{"x86 object unavailable"}
		case entry.X86 != nil:
			report.Summary.X86Only++
			entry.Differences = []string{"x64 object unavailable"}
		}
		report.Entries = append(report.Entries, entry)
	}
	report.Summary.Entries = len(report.Entries)
	return report, nil
}

func architectureDifferences(x64, x86 ArchitectureInventory) []string {
	var differences []string
	compare := func(label string, first, second []string) {
		if strings.Join(first, "\x00") != strings.Join(second, "\x00") {
			differences = append(differences, label)
		}
	}
	if x64.Compatibility != x86.Compatibility {
		differences = append(differences, "loader support")
	}
	compare("imports", x64.APIs, x86.APIs)
	compare("capabilities", x64.CapabilityIDs, x86.CapabilityIDs)
	compare("behavior chains", x64.BehaviorChains, x86.BehaviorChains)
	compare("effects", x64.Effects, x86.Effects)
	compare("runtime support", x64.WorksWith, x86.WorksWith)
	compare("arguments", argumentMatrixKeys(x64.Arguments), argumentMatrixKeys(x86.Arguments))
	return differences
}

func argumentMatrixKeys(arguments []artifact.ArgumentHint) []string {
	keys := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		keys = append(keys, argument.Name+":"+argument.Type)
	}
	sort.Strings(keys)
	return keys
}

func PersistInventory(report Inventory) (Inventory, error) {
	runDir, err := runlog.NewDir("arsenal-inventory-" + safeName(filepath.Base(filepath.Clean(report.Root))))
	if err != nil {
		return report, err
	}
	report.Header = evidence.New(evidence.SchemaArsenalInventory, runlog.ID(runDir), "")
	report.JSONPath = filepath.Join(runDir, "inventory.json")
	report.MarkdownPath = filepath.Join(runDir, "inventory.md")
	if err := writeOperationJSON(report.JSONPath, report); err != nil {
		return report, err
	}
	if err := os.WriteFile(report.MarkdownPath, []byte(InventoryMarkdown(report)), 0o644); err != nil {
		return report, err
	}
	return report, nil
}

func CreateLock(root string) (Lock, error) {
	entries, err := List(root)
	if err != nil {
		return Lock{}, err
	}
	lock := Lock{
		Header: evidence.New(evidence.SchemaArsenalLock, "", ""), Root: root,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	lock.SourceFingerprint, err = fingerprintArsenalSource(root)
	if err != nil {
		return Lock{}, err
	}
	if source, err := loadSourceMetadata(root); err == nil {
		lock.Source = &source
	}
	for _, entry := range entries {
		sources := sourceFiles(root, entry.Path)
		item := LockedEntry{Name: entry.Name, Path: relativeSlash(root, entry.Path), HasSource: len(sources) > 0, SourceFiles: sources}
		for _, object := range []struct{ Arch, Path string }{{"x64", entry.X64}, {"x86", entry.X86}} {
			if object.Path == "" {
				continue
			}
			fingerprint, err := evidence.FingerprintFile(object.Path)
			if err != nil {
				return Lock{}, err
			}
			item.Objects = append(item.Objects, LockedObject{Arch: object.Arch, Path: relativeSlash(root, object.Path), Size: fingerprint.Size, SHA256: fingerprint.SHA256})
		}
		lock.Entries = append(lock.Entries, item)
	}
	lock.RootFingerprint = fingerprintLockContent(lock.SourceFingerprint, lock.Entries)
	return lock, nil
}

func WriteLock(root string, lock Lock) (Lock, string, error) {
	path := filepath.Join(root, LockFileName)
	lock.Header = evidence.New(evidence.SchemaArsenalLock, "lock-"+safeName(filepath.Base(filepath.Clean(root)))+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"), "")
	if err := writeOperationJSON(path, lock); err != nil {
		return lock, path, err
	}
	return lock, path, nil
}

func LoadLock(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lock Lock
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, err
	}
	if lock.Schema != evidence.SchemaArsenalLock || lock.SchemaVersion != evidence.ContractVersion {
		return Lock{}, fmt.Errorf("invalid arsenal lock identity %q version %d", lock.Schema, lock.SchemaVersion)
	}
	return lock, nil
}

func CompareLocks(baselinePath, currentPath string, baseline, current Lock) LockDiff {
	report := LockDiff{
		Header: evidence.New(evidence.SchemaArsenalDiff, "", ""), Baseline: baselinePath, Current: currentPath,
		Status: "same", SourceChanged: baseline.SourceFingerprint.SHA256 != current.SourceFingerprint.SHA256,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	baseObjects := lockObjectMap(baseline)
	currentObjects := lockObjectMap(current)
	for key, before := range baseObjects {
		after, ok := currentObjects[key]
		if !ok {
			report.Removed = append(report.Removed, key)
			continue
		}
		if before.SHA256 != after.SHA256 || before.Size != after.Size {
			report.Changed = append(report.Changed, LockChange{Key: key, BaselineSHA256: before.SHA256, CurrentSHA256: after.SHA256, BaselineSize: before.Size, CurrentSize: after.Size})
		}
	}
	for key := range currentObjects {
		if _, ok := baseObjects[key]; !ok {
			report.Added = append(report.Added, key)
		}
	}
	sort.Strings(report.Added)
	sort.Strings(report.Removed)
	sort.Slice(report.Changed, func(i, j int) bool { return report.Changed[i].Key < report.Changed[j].Key })
	if report.SourceChanged || len(report.Added)+len(report.Removed)+len(report.Changed) > 0 {
		report.Status = "changed"
	}
	return report
}

func PersistLockDiff(report LockDiff) (LockDiff, error) {
	runDir, err := runlog.NewDir("arsenal-diff")
	if err != nil {
		return report, err
	}
	report.Header = evidence.New(evidence.SchemaArsenalDiff, runlog.ID(runDir), "")
	report.EvidencePath = filepath.Join(runDir, "arsenal-diff.json")
	report.MarkdownPath = filepath.Join(runDir, "arsenal-diff.md")
	if err := writeOperationJSON(report.EvidencePath, report); err != nil {
		return report, err
	}
	if err := os.WriteFile(report.MarkdownPath, []byte(LockDiffMarkdown(report)), 0o644); err != nil {
		return report, err
	}
	return report, nil
}

func CompareRegressionEvidence(baselinePath, currentPath string) (RegressionReport, error) {
	baselineType, baseline, err := loadRegressionItems(baselinePath)
	if err != nil {
		return RegressionReport{}, err
	}
	currentType, current, err := loadRegressionItems(currentPath)
	if err != nil {
		return RegressionReport{}, err
	}
	if baselineType != currentType {
		return RegressionReport{}, fmt.Errorf("evidence types differ: %s vs %s", baselineType, currentType)
	}
	report := RegressionReport{
		Header: evidence.New(evidence.SchemaArsenalRegression, "", ""), Baseline: baselinePath, Current: currentPath,
		EvidenceType: baselineType, Status: "pass", GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary: RegressionSummary{Baseline: len(baseline), Current: len(current)},
	}
	for key, before := range baseline {
		after, ok := current[key]
		if !ok {
			report.Summary.Removed++
			report.Summary.Regressions++
			report.Changes = append(report.Changes, RegressionChange{Key: key, Classification: "removed", BeforeStatus: before.Status, BeforeSHA256: before.SHA256, BeforeDetail: before.Detail})
			continue
		}
		classification := classifyRegressionChange(before, after)
		switch classification {
		case "unchanged":
			report.Summary.Unchanged++
			continue
		case "regression":
			report.Summary.Regressions++
		case "improved":
			report.Summary.Improved++
		default:
			report.Summary.Changed++
		}
		report.Changes = append(report.Changes, RegressionChange{Key: key, Classification: classification, BeforeStatus: before.Status, AfterStatus: after.Status, BeforeSHA256: before.SHA256, AfterSHA256: after.SHA256, BeforeDetail: before.Detail, AfterDetail: after.Detail})
	}
	for key, after := range current {
		if _, ok := baseline[key]; ok {
			continue
		}
		report.Summary.Added++
		classification := "added"
		if regressionStatusRank(after.Status) == 3 {
			classification = "added_regression"
			report.Summary.Regressions++
		}
		report.Changes = append(report.Changes, RegressionChange{Key: key, Classification: classification, AfterStatus: after.Status, AfterSHA256: after.SHA256, AfterDetail: after.Detail})
	}
	sort.Slice(report.Changes, func(i, j int) bool { return report.Changes[i].Key < report.Changes[j].Key })
	if report.Summary.Regressions > 0 {
		report.Status = "fail"
	} else if len(report.Changes) > 0 {
		report.Status = "pass_with_changes"
	}
	return report, nil
}

func PersistRegression(report RegressionReport) (RegressionReport, error) {
	runDir, err := runlog.NewDir("arsenal-regression")
	if err != nil {
		return report, err
	}
	report.Header = evidence.New(evidence.SchemaArsenalRegression, runlog.ID(runDir), "")
	report.EvidencePath = filepath.Join(runDir, "regression.json")
	report.MarkdownPath = filepath.Join(runDir, "regression.md")
	if err := writeOperationJSON(report.EvidencePath, report); err != nil {
		return report, err
	}
	if err := os.WriteFile(report.MarkdownPath, []byte(RegressionMarkdown(report)), 0o644); err != nil {
		return report, err
	}
	return report, nil
}

func InventoryText(report Inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOF arsenal capabilities\nroot      %s\n", report.Root)
	if report.Query != "" {
		fmt.Fprintf(&b, "query     %s\n", report.Query)
	}
	fmt.Fprintf(&b, "summary   matches=%d x64=%d x86=%d runnable=%d loader-lookup=%d blocked=%d args=%d duplicates=%d cached=%d refreshed=%d\n", report.Summary.Entries, report.Summary.X64Objects, report.Summary.X86Objects, report.Summary.Compatible, report.Summary.RuntimeLookup, report.Summary.Blocked, report.Summary.NeedsArguments, report.Summary.DuplicateGroups, report.Summary.CacheHits, report.Summary.Refreshed)
	groups, groupNames := groupInventoryEntries(report.Entries)
	for _, group := range groupNames {
		fmt.Fprintf(&b, "\nCAPABILITY  %s\n", group)
		for _, entry := range groups[group] {
			fmt.Fprintf(&b, "%s\n", entry.Name)
			fmt.Fprintf(&b, "  confidence  %s\n", previewValues(entry.Confidences, 3))
			fmt.Fprintf(&b, "  arguments   required=%t; %s\n", entry.NeedsArgs, previewArgumentNames(entry.Arguments, entry.ArgumentAPIs))
			fmt.Fprintf(&b, "  can do      %s\n", previewValues(append(append([]string{}, entry.BehaviorChains...), entry.Capabilities...), 6))
			fmt.Fprintf(&b, "  effects     %s\n", previewValues(entry.Effects, 6))
			fmt.Fprintf(&b, "  needs       %s\n", previewValues(entry.Requirements, 5))
			fmt.Fprintf(&b, "  works with  %s\n", previewValues(entry.WorksWith, 5))
			fmt.Fprintf(&b, "  object      %s; loader=%s; cached=%t\n", entry.Path, emptyInventory(entry.Compatibility, "not-analyzed"), entry.AnalysisCached)
		}
	}
	if report.JSONPath != "" {
		fmt.Fprintf(&b, "reports   %s %s\n", report.JSONPath, report.MarkdownPath)
	}
	return b.String()
}

func InventoryMarkdown(report Inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Arsenal Inventory\n\n- Root: `%s`\n- Query: `%s`\n- Entries: `%d`\n- x64/x86: `%d` / `%d`\n- Compatible/runtime lookup/blocked: `%d` / `%d` / `%d`\n\n", report.Root, report.Query, report.Summary.Entries, report.Summary.X64Objects, report.Summary.X86Objects, report.Summary.Compatible, report.Summary.RuntimeLookup, report.Summary.Blocked)
	b.WriteString("| Name | Can do | Confidence | Arguments | Effects | Needs | Works with | Loader |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, entry := range report.Entries {
		canDo := append(append([]string{}, entry.BehaviorChains...), entry.Capabilities...)
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` |\n", entry.Name, strings.Join(canDo, ", "), strings.Join(entry.Confidences, ", "), previewArgumentNames(entry.Arguments, entry.ArgumentAPIs), strings.Join(entry.Effects, ", "), strings.Join(entry.Requirements, ", "), strings.Join(entry.WorksWith, ", "), entry.Compatibility)
	}
	return b.String()
}

func ArchitectureMatrixText(report ArchitectureMatrix) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ARSENAL ARCHITECTURE MATRIX\nroot      %s\nsummary   entries=%d pairs=%d equivalent=%d different=%d x64-only=%d x86-only=%d errors=%d cached=%d refreshed=%d\n",
		report.Root, report.Summary.Entries, report.Summary.Pairs, report.Summary.Equivalent, report.Summary.Different,
		report.Summary.X64Only, report.Summary.X86Only, report.Summary.AnalysisError, report.Summary.CacheHits, report.Summary.Refreshed)
	for _, entry := range report.Entries {
		status := "equivalent"
		if !entry.Equivalent {
			status = strings.Join(entry.Differences, ", ")
		}
		fmt.Fprintf(&b, "%-32s %-12s %s\n", entry.Name, matrixArchitectureLabel(entry), status)
		if len(entry.CorpusBlockers) > 0 {
			fmt.Fprintf(&b, "  blockers  %s\n", strings.Join(entry.CorpusBlockers, "; "))
		}
	}
	fmt.Fprintf(&b, "index     %s\n", report.IndexPath)
	return b.String()
}

func matrixArchitectureLabel(entry ArchitectureMatrixEntry) string {
	switch {
	case entry.X64 != nil && entry.X86 != nil:
		return "x64/x86"
	case entry.X64 != nil:
		return "x64"
	case entry.X86 != nil:
		return "x86"
	default:
		return "-"
	}
}

func groupInventoryEntries(entries []InventoryEntry) (map[string][]InventoryEntry, []string) {
	groups := map[string][]InventoryEntry{}
	for _, entry := range entries {
		name := "Other analyzed behavior"
		if len(entry.BehaviorChains) > 0 {
			name = entry.BehaviorChains[0]
		} else if len(entry.Capabilities) > 0 {
			name = entry.Capabilities[0]
		}
		groups[name] = append(groups[name], entry)
	}
	var names []string
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return groups, names
}

func previewArgumentNames(arguments []artifact.ArgumentHint, detected []string) string {
	var names []string
	for _, argument := range arguments {
		label := argument.Name
		if argument.Type != "" {
			label += ":" + argument.Type
		}
		names = append(names, label)
	}
	if len(names) == 0 {
		names = append(names, detected...)
	}
	return previewValues(names, 6)
}

func LockDiffText(report LockDiff) string {
	return fmt.Sprintf("BOF arsenal diff: %s\nbaseline  %s\ncurrent   %s\nsource    changed=%t\nobjects   added=%d removed=%d changed=%d\nreports   %s %s\n", report.Status, report.Baseline, report.Current, report.SourceChanged, len(report.Added), len(report.Removed), len(report.Changed), report.EvidencePath, report.MarkdownPath)
}

func LockText(lock Lock, path string) string {
	objects := 0
	for _, entry := range lock.Entries {
		objects += len(entry.Objects)
	}
	return fmt.Sprintf("BOF arsenal lock written\npath      %s\nentries   %d\nobjects   %d\ncontent   %s\nsource    %s\n", path, len(lock.Entries), objects, lock.RootFingerprint.SHA256, lock.SourceFingerprint.SHA256)
}

func LockDiffMarkdown(report LockDiff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Arsenal Diff: %s\n\n- Baseline: `%s`\n- Current: `%s`\n- Source fingerprint changed: `%t`\n- Added/removed/changed objects: `%d` / `%d` / `%d`\n", strings.ToUpper(report.Status), report.Baseline, report.Current, report.SourceChanged, len(report.Added), len(report.Removed), len(report.Changed))
	if len(report.Added) > 0 {
		fmt.Fprintf(&b, "\n## Added\n\n- `%s`\n", strings.Join(report.Added, "`\n- `"))
	}
	if len(report.Removed) > 0 {
		fmt.Fprintf(&b, "\n## Removed\n\n- `%s`\n", strings.Join(report.Removed, "`\n- `"))
	}
	if len(report.Changed) > 0 {
		b.WriteString("\n## Changed\n\n| Object | Before | After |\n| --- | --- | --- |\n")
		for _, change := range report.Changed {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", change.Key, change.BaselineSHA256, change.CurrentSHA256)
		}
	}
	return b.String()
}

func RegressionText(report RegressionReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOF arsenal regression: %s\ntype      %s\nbaseline  %s\ncurrent   %s\nsummary   unchanged=%d added=%d removed=%d changed=%d improved=%d regressions=%d\n", report.Status, report.EvidenceType, report.Baseline, report.Current, report.Summary.Unchanged, report.Summary.Added, report.Summary.Removed, report.Summary.Changed, report.Summary.Improved, report.Summary.Regressions)
	for _, change := range report.Changes {
		fmt.Fprintf(&b, "%-12s %-30s %s -> %s\n", change.Classification, change.Key, change.BeforeStatus, change.AfterStatus)
	}
	fmt.Fprintf(&b, "reports   %s %s\n", report.EvidencePath, report.MarkdownPath)
	return b.String()
}

func RegressionMarkdown(report RegressionReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Arsenal Regression: %s\n\n- Evidence: `%s`\n- Baseline: `%s`\n- Current: `%s`\n- Unchanged/added/removed/changed/improved/regressions: `%d` / `%d` / `%d` / `%d` / `%d` / `%d`\n\n", strings.ToUpper(report.Status), report.EvidenceType, report.Baseline, report.Current, report.Summary.Unchanged, report.Summary.Added, report.Summary.Removed, report.Summary.Changed, report.Summary.Improved, report.Summary.Regressions)
	if len(report.Changes) > 0 {
		b.WriteString("| Item | Classification | Before | After | Hash changed |\n| --- | --- | --- | --- | --- |\n")
		for _, change := range report.Changes {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%t` |\n", change.Key, change.Classification, change.BeforeStatus, change.AfterStatus, change.BeforeSHA256 != change.AfterSHA256)
		}
	}
	return b.String()
}

func analyzerSignatureSet(signatures []artifact.DeclarativeSignature) string {
	copyOf := append([]artifact.DeclarativeSignature(nil), signatures...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i].ID < copyOf[j].ID })
	encoded, _ := json.Marshal(copyOf)
	hash := sha256.New()
	_, _ = io.WriteString(hash, analyzerCacheVersion+"\x00")
	_, _ = hash.Write(encoded)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func arsenalAnalysisIndexPath(root string) string {
	absolute, err := filepath.Abs(root)
	if err != nil {
		absolute = filepath.Clean(root)
	}
	rootHash := sha256.Sum256([]byte(absolute))
	cacheRoot, err := os.UserCacheDir()
	if err != nil || cacheRoot == "" {
		cacheRoot = os.TempDir()
	}
	return filepath.Join(cacheRoot, "bofbench", "arsenal", fmt.Sprintf("%x.json", rootHash[:12]))
}

func loadArsenalAnalysisIndex(root string) (string, arsenalAnalysisIndex) {
	path := arsenalAnalysisIndexPath(root)
	absolute, _ := filepath.Abs(root)
	index := arsenalAnalysisIndex{Schema: arsenalIndexSchema, SchemaVersion: arsenalIndexSchemaVersion, Root: absolute, Entries: map[string]arsenalAnalysisIndexItem{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return path, index
	}
	var stored arsenalAnalysisIndex
	if json.Unmarshal(data, &stored) != nil || stored.Schema != arsenalIndexSchema || stored.SchemaVersion != arsenalIndexSchemaVersion || stored.Root != absolute || stored.Entries == nil {
		return path, index
	}
	return path, stored
}

func writeArsenalAnalysisIndex(path string, index arsenalAnalysisIndex) error {
	index.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func arsenalSourceVersion(source *SourceMetadata, root string) string {
	if source != nil {
		return strings.Join([]string{source.URL, source.Ref, source.Adapter}, "\x00")
	}
	absolute, _ := filepath.Abs(root)
	return "local\x00" + absolute
}

func analyzeArsenalObject(path, arch, objectSHA, sourceVersion, signatureSet string, signatures []artifact.DeclarativeSignature, index *arsenalAnalysisIndex) (artifact.Analysis, bool, error) {
	keyHash := sha256.Sum256([]byte(arch + "\x00" + objectSHA + "\x00" + sourceVersion + "\x00" + signatureSet))
	key := fmt.Sprintf("%x", keyHash[:])
	if cached, ok := index.Entries[key]; ok && cached.ObjectSHA256 == objectSHA && cached.Architecture == arch && cached.Source == sourceVersion && cached.SignatureSet == signatureSet {
		analysis := cached.Analysis
		analysis.Path = path
		return analysis, true, nil
	}
	analysis, err := artifact.Analyze(path, "go")
	if err != nil {
		return artifact.Analysis{}, false, err
	}
	artifact.ApplyDeclarativeSignatures(&analysis, signatures)
	index.Entries[key] = arsenalAnalysisIndexItem{
		ObjectSHA256: objectSHA, Architecture: arch, ObjectPath: filepath.ToSlash(path),
		Source: sourceVersion, SignatureSet: signatureSet, Analysis: analysis,
	}
	return analysis, false, nil
}

func inventoryEntry(root string, entry Entry, sourceVersion, signatureSet string, signatures []artifact.DeclarativeSignature, index *arsenalAnalysisIndex) InventoryEntry {
	sources := sourceFiles(root, entry.Path)
	item := InventoryEntry{Name: entry.Name, Path: relativeSlash(root, entry.Path), HasSource: len(sources) > 0, SourceFiles: sources}
	allCached := true
	for _, object := range []struct{ Arch, Path string }{{"x64", entry.X64}, {"x86", entry.X86}} {
		if object.Path == "" {
			continue
		}
		fingerprint, err := evidence.FingerprintFile(object.Path)
		if err != nil {
			item.AnalysisError = strings.TrimSpace(strings.Join([]string{item.AnalysisError, object.Arch + ": " + err.Error()}, "; "))
			allCached = false
			continue
		}
		relativePath := relativeSlash(root, object.Path)
		item.Objects = append(item.Objects, LockedObject{Arch: object.Arch, Path: relativePath, Size: fingerprint.Size, SHA256: fingerprint.SHA256})
		analysis, cached, analyzeErr := analyzeArsenalObject(object.Path, object.Arch, fingerprint.SHA256, sourceVersion, signatureSet, signatures, index)
		if analyzeErr != nil {
			item.Architectures = append(item.Architectures, ArchitectureInventory{Arch: object.Arch, Path: relativePath, ObjectSHA256: fingerprint.SHA256, AnalysisError: analyzeErr.Error()})
			item.AnalysisError = strings.TrimSpace(strings.Join([]string{item.AnalysisError, object.Arch + ": " + analyzeErr.Error()}, "; "))
			allCached = false
			continue
		}
		architecture := architectureInventory(object.Arch, relativePath, fingerprint.SHA256, analysis, cached)
		item.Architectures = append(item.Architectures, architecture)
		allCached = allCached && cached
		if item.Entrypoint == "" || object.Arch == "x64" {
			item.Entrypoint = architecture.Entrypoint
			item.Relocations = architecture.Relocations
			item.SourceAndVersion = analysis.SourceAndVersion
		}
		if item.Compatibility == "" {
			item.Compatibility = architecture.Compatibility
		} else if architecture.Compatibility != "" && item.Compatibility != architecture.Compatibility {
			item.Compatibility = "mixed"
		}
		item.APIs = append(item.APIs, architecture.APIs...)
		item.Capabilities = append(item.Capabilities, architecture.Capabilities...)
		item.CapabilityIDs = append(item.CapabilityIDs, architecture.CapabilityIDs...)
		item.BehaviorChains = append(item.BehaviorChains, architecture.BehaviorChains...)
		item.Effects = append(item.Effects, architecture.Effects...)
		item.WorksWith = append(item.WorksWith, architecture.WorksWith...)
		item.Arguments = append(item.Arguments, architecture.Arguments...)
		item.Requirements = append(item.Requirements, analysis.Requirements.Platform...)
		item.Requirements = append(item.Requirements, analysis.Requirements.Privilege...)
		item.Requirements = append(item.Requirements, analysis.Requirements.Network...)
		item.Requirements = append(item.Requirements, analysis.Requirements.Host...)
		for _, capability := range analysis.Capabilities {
			item.Confidences = append(item.Confidences, capability.Confidence)
		}
		for _, chain := range analysis.BehaviorChains {
			item.Confidences = append(item.Confidences, chain.Confidence)
		}
		for _, api := range architecture.APIs {
			if strings.HasPrefix(api, "BeaconData") {
				item.ArgumentAPIs = append(item.ArgumentAPIs, api)
			}
		}
		for _, visible := range analysis.Strings {
			if len(item.VisibleStrings) == 12 {
				break
			}
			item.VisibleStrings = append(item.VisibleStrings, visible.Value)
		}
	}
	item.AnalysisCached = len(item.Architectures) > 0 && allCached
	item.NeedsArgs = len(item.Arguments) > 0 || len(item.ArgumentAPIs) > 0
	item.APIs = uniqueSorted(item.APIs)
	item.ArgumentAPIs = uniqueSorted(item.ArgumentAPIs)
	item.Capabilities = uniqueSorted(item.Capabilities)
	item.CapabilityIDs = uniqueSorted(item.CapabilityIDs)
	item.BehaviorChains = uniqueSorted(item.BehaviorChains)
	item.Confidences = uniqueSorted(item.Confidences)
	item.Effects = uniqueSorted(item.Effects)
	item.Requirements = uniqueSorted(item.Requirements)
	item.WorksWith = uniqueSorted(item.WorksWith)
	return item
}

func architectureInventory(arch, path, sha string, analysis artifact.Analysis, cached bool) ArchitectureInventory {
	item := ArchitectureInventory{
		Arch: arch, Path: path, ObjectSHA256: sha, Entrypoint: analysis.EntrypointSymbol,
		Relocations: analysis.Relocations, Effects: uniqueSorted(append([]string(nil), analysis.Effects...)),
		WorksWith: uniqueSorted(append([]string(nil), analysis.WorksWith...)),
		Arguments: append([]artifact.ArgumentHint(nil), analysis.Arguments...), AnalysisCached: cached,
	}
	if analysis.LoaderCompatibility != nil {
		item.Compatibility = analysis.LoaderCompatibility.Status
	}
	for _, imp := range analysis.Imports {
		api := imp.API
		if api == "" {
			api = imp.Symbol
		}
		item.APIs = append(item.APIs, api)
		if strings.HasPrefix(api, "BeaconData") {
			item.NeedsArgs = true
		}
	}
	for _, capability := range analysis.Capabilities {
		item.Capabilities = append(item.Capabilities, capability.Name)
		item.CapabilityIDs = append(item.CapabilityIDs, capability.ID)
	}
	for _, chain := range analysis.BehaviorChains {
		item.BehaviorChains = append(item.BehaviorChains, chain.Name)
	}
	item.APIs = uniqueSorted(item.APIs)
	item.Capabilities = uniqueSorted(item.Capabilities)
	item.CapabilityIDs = uniqueSorted(item.CapabilityIDs)
	item.BehaviorChains = uniqueSorted(item.BehaviorChains)
	item.NeedsArgs = item.NeedsArgs || len(item.Arguments) > 0
	return item
}

func summarizeInventory(report *Inventory) {
	report.Summary = InventorySummary{Entries: len(report.Entries), ByCapability: map[string]int{}}
	hashes := map[string]int{}
	for _, entry := range report.Entries {
		if entry.HasSource {
			report.Summary.WithSource++
		}
		for _, object := range entry.Objects {
			if object.Arch == "x86" {
				report.Summary.X86Objects++
			} else {
				report.Summary.X64Objects++
			}
			hashes[object.SHA256]++
		}
		for _, architecture := range entry.Architectures {
			switch architecture.Compatibility {
			case "compatible":
				report.Summary.Compatible++
			case "compatible_runtime_lookup":
				report.Summary.RuntimeLookup++
			case "":
				if architecture.AnalysisError != "" {
					report.Summary.AnalysisFailed++
				}
			default:
				report.Summary.Blocked++
			}
			if architecture.AnalysisCached {
				report.Summary.CacheHits++
			} else if architecture.AnalysisError == "" {
				report.Summary.Refreshed++
			}
		}
		if entry.NeedsArgs {
			report.Summary.NeedsArguments++
		}
		capabilities := entry.CapabilityIDs
		if len(capabilities) == 0 {
			capabilities = entry.Capabilities
		}
		for _, capability := range capabilities {
			report.Summary.ByCapability[capability]++
		}
	}
	for _, count := range hashes {
		if count > 1 {
			report.Summary.DuplicateGroups++
		}
	}
	if report.Summary.AnalysisFailed > 0 {
		report.Status = "fail"
	}
}

func matchesInventoryQuery(entry InventoryEntry, query string) bool {
	return matchesInventoryFilters(entry, InventoryFilters{Query: query})
}

func matchesInventoryFilters(entry InventoryEntry, filters InventoryFilters) bool {
	all := []string{entry.Name, entry.Path, entry.Compatibility, entry.SourceAndVersion.Repository, entry.SourceAndVersion.Ref, entry.SourceAndVersion.Commit}
	all = append(all, entry.APIs...)
	all = append(all, entry.Capabilities...)
	all = append(all, entry.CapabilityIDs...)
	all = append(all, entry.BehaviorChains...)
	all = append(all, entry.Effects...)
	all = append(all, entry.Requirements...)
	all = append(all, entry.WorksWith...)
	all = append(all, entry.Confidences...)
	all = append(all, entry.VisibleStrings...)
	if !containsAllTerms(all, filters.Query) {
		return false
	}
	canDo := append(append(append([]string{}, entry.Capabilities...), entry.CapabilityIDs...), entry.BehaviorChains...)
	if filters.Arch != "" {
		var architectures []string
		for _, object := range entry.Objects {
			architectures = append(architectures, object.Arch)
		}
		if !containsAllTerms(architectures, filters.Arch) {
			return false
		}
	}
	if filters.HasArgs != nil && entry.NeedsArgs != *filters.HasArgs {
		return false
	}
	var loaderSupport []string
	for _, architecture := range entry.Architectures {
		loaderSupport = append(loaderSupport, architecture.Arch+" "+architecture.Compatibility)
	}
	return containsAllTerms(canDo, filters.Can) &&
		containsAllTerms(entry.APIs, filters.API) &&
		containsAllTerms(entry.BehaviorChains, filters.Chain) &&
		containsAllTerms(entry.Effects, filters.Effect) &&
		containsAllTerms(entry.WorksWith, filters.WorksWith) &&
		containsAllTerms(entry.Requirements, filters.Requires) &&
		containsAllTerms(loaderSupport, filters.Loader) &&
		containsAllTerms(entry.Confidences, filters.Confidence)
}

func containsAllTerms(values []string, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	haystack := strings.ToLower(strings.Join(values, "\n"))
	for _, token := range strings.Fields(query) {
		if !strings.Contains(haystack, token) {
			return false
		}
	}
	return true
}

func loadSourceMetadata(root string) (SourceMetadata, error) {
	data, err := os.ReadFile(filepath.Join(root, "source.json"))
	if err != nil {
		return SourceMetadata{}, err
	}
	var source SourceMetadata
	if err := json.Unmarshal(data, &source); err != nil {
		return SourceMetadata{}, err
	}
	return source, nil
}

func sourceFiles(root, dir string) []string {
	var files []string
	seen := map[string]bool{}
	add := func(path string) {
		relative := relativeSlash(root, path)
		if !seen[relative] {
			seen[relative] = true
			files = append(files, relative)
		}
	}
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		base := strings.ToLower(entry.Name())
		if ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".h" || ext == ".hpp" || ext == ".cna" || base == "extension.json" {
			add(path)
		}
		return nil
	})
	rootAbs, _ := filepath.Abs(root)
	for current, _ := filepath.Abs(dir); current != ""; current = filepath.Dir(current) {
		relative, err := filepath.Rel(rootAbs, current)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			break
		}
		entries, _ := os.ReadDir(current)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			base := strings.ToLower(entry.Name())
			if strings.HasSuffix(base, ".cna") || base == "extension.json" {
				add(filepath.Join(current, entry.Name()))
			}
		}
		if current == rootAbs {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	sort.Strings(files)
	return files
}

func fingerprintArsenalSource(root string) (evidence.TreeFingerprint, error) {
	hash := sha256.New()
	result := evidence.TreeFingerprint{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		lower := strings.ToLower(rel)
		if rel == "source.json" || rel == LockFileName || strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".obj") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot fingerprint special source file %s", path)
		}
		if canonicalSourceText(rel) {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
			fmt.Fprintf(hash, "file\x00%s\x00%d\x00", rel, len(data))
			if _, err := hash.Write(data); err != nil {
				return err
			}
			result.Files++
			result.Bytes += int64(len(data))
			return nil
		}
		fmt.Fprintf(hash, "file\x00%s\x00%d\x00", rel, info.Size())
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		result.Files++
		result.Bytes += info.Size()
		return nil
	})
	if err != nil {
		return evidence.TreeFingerprint{}, err
	}
	result.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	return result, nil
}

func canonicalSourceText(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	switch extension {
	case ".c", ".cc", ".cpp", ".h", ".hpp", ".cna", ".go", ".json", ".md", ".ps1", ".sh", ".toml", ".txt", ".yaml", ".yml", ".gitignore":
		return true
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "contributing", "license", "makefile", "readme":
		return true
	default:
		return false
	}
}

func fingerprintLockContent(source evidence.TreeFingerprint, entries []LockedEntry) evidence.TreeFingerprint {
	hash := sha256.New()
	result := evidence.TreeFingerprint{Files: source.Files, Bytes: source.Bytes}
	fmt.Fprintf(hash, "source\x00%d\x00%d\x00%s\x00", source.Files, source.Bytes, source.SHA256)
	type objectIdentity struct {
		key    string
		object LockedObject
	}
	var objects []objectIdentity
	for _, entry := range entries {
		for _, object := range entry.Objects {
			objects = append(objects, objectIdentity{key: entry.Path + "/" + object.Arch, object: object})
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].key < objects[j].key })
	for _, item := range objects {
		fmt.Fprintf(hash, "object\x00%s\x00%s\x00%d\x00%s\x00", item.key, item.object.Path, item.object.Size, item.object.SHA256)
		result.Files++
		result.Bytes += item.object.Size
	}
	result.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	return result
}

func loadRegressionItems(path string) (string, map[string]regressionItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var identity struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &identity); err != nil {
		return "", nil, err
	}
	if identity.SchemaVersion != evidence.ContractVersion {
		return "", nil, fmt.Errorf("unsupported %s schema version %d; expected %d", identity.Schema, identity.SchemaVersion, evidence.ContractVersion)
	}
	items := map[string]regressionItem{}
	switch identity.Schema {
	case evidence.SchemaPreflight:
		var report struct {
			Architecture string `json:"architecture"`
			Results      []struct {
				Name         string `json:"name"`
				Arch         string `json:"arch"`
				Object       string `json:"object"`
				Status       string `json:"status"`
				SHA256       string `json:"sha256"`
				Relocations  int    `json:"relocations"`
				ArgumentNeed string `json:"argument_need"`
				Error        string `json:"error"`
			} `json:"results"`
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return "", nil, err
		}
		for _, result := range report.Results {
			key := result.Name + "/" + regressionArch(result.Arch, result.Object, report.Architecture)
			item := regressionItem{
				Key:    key,
				Status: result.Status,
				SHA256: result.SHA256,
				Detail: fmt.Sprintf("relocs=%d args=%s error=%s", result.Relocations, result.ArgumentNeed, result.Error),
			}
			if err := addRegressionItem(items, item); err != nil {
				return "", nil, err
			}
		}
	case evidence.SchemaArsenalTest:
		var report struct {
			Results []struct {
				Name     string `json:"name"`
				Status   string `json:"status"`
				Phase    string `json:"phase"`
				Error    string `json:"error"`
				Analysis *struct {
					Arch   string `json:"arch"`
					SHA256 string `json:"sha256"`
				} `json:"analysis"`
				Run *struct {
					ExitState string `json:"exit_state"`
				} `json:"run"`
			} `json:"results"`
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return "", nil, err
		}
		for _, result := range report.Results {
			arch, sha, exitState := "x64", "", ""
			if result.Analysis != nil {
				arch = emptyInventory(result.Analysis.Arch, "unknown")
				sha = result.Analysis.SHA256
			}
			if result.Run != nil {
				exitState = result.Run.ExitState
			}
			key := result.Name + "/" + arch
			item := regressionItem{
				Key:    key,
				Status: result.Status,
				SHA256: sha,
				Detail: "phase=" + result.Phase + " exit=" + exitState + " error=" + result.Error,
			}
			if err := addRegressionItem(items, item); err != nil {
				return "", nil, err
			}
		}
	default:
		return "", nil, fmt.Errorf("unsupported regression evidence schema %q", identity.Schema)
	}
	if len(items) == 0 {
		return "", nil, fmt.Errorf("%s contains no regression items", path)
	}
	return identity.Schema, items, nil
}

func addRegressionItem(items map[string]regressionItem, item regressionItem) error {
	if item.Key == "/unknown" || strings.HasPrefix(item.Key, "/") {
		return fmt.Errorf("regression evidence contains an item without a name")
	}
	if _, exists := items[item.Key]; exists {
		return fmt.Errorf("regression evidence contains duplicate item %q", item.Key)
	}
	items[item.Key] = item
	return nil
}

func regressionArch(arch, object, fallback string) string {
	if arch != "" {
		return arch
	}
	lower := strings.ToLower(filepath.Base(object))
	for _, candidate := range []string{"x64", "x86"} {
		if strings.Contains(lower, "."+candidate+".") {
			return candidate
		}
	}
	if fallback == "x64" || fallback == "x86" {
		return fallback
	}
	return "unknown"
}

func classifyRegressionChange(before, after regressionItem) string {
	if before.Status == after.Status && before.SHA256 == after.SHA256 && before.Detail == after.Detail {
		return "unchanged"
	}
	beforeRank := regressionStatusRank(before.Status)
	afterRank := regressionStatusRank(after.Status)
	if afterRank > beforeRank {
		return "regression"
	}
	if afterRank < beforeRank {
		return "improved"
	}
	return "changed"
}

func regressionStatusRank(status string) int {
	switch status {
	case "pass", "compatible":
		return 0
	case "analyze_pass", "compatible_runtime_lookup":
		return 1
	case "not_applicable":
		return 2
	default:
		// All loader blocker categories and test failures are hard failures.
		return 3
	}
}

func relativeSlash(root, path string) string {
	rootAbs, rootErr := filepath.Abs(root)
	pathAbs, pathErr := filepath.Abs(path)
	if rootErr != nil || pathErr != nil {
		return filepath.ToSlash(path)
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func lockObjectMap(lock Lock) map[string]LockedObject {
	out := map[string]LockedObject{}
	for _, entry := range lock.Entries {
		for _, object := range entry.Objects {
			out[entry.Name+"/"+object.Arch] = object
		}
	}
	return out
}
func writeOperationJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
func emptyInventory(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func previewValues(values []string, limit int) string {
	if len(values) == 0 {
		return "-"
	}
	if len(values) <= limit {
		return strings.Join(values, ",")
	}
	return strings.Join(values[:limit], ",") + fmt.Sprintf(",+%d", len(values)-limit)
}
