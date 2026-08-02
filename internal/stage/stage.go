package stage

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/artifact"
	"github.com/professor-moody/bofbench/internal/evidence"
)

const (
	ManifestSchema        = "bofbench.stage"
	ManifestSchemaVersion = 2
)

type Result struct {
	Target       string                `json:"target"`
	Object       string                `json:"object"`
	Output       string                `json:"output"`
	Manifest     string                `json:"manifest,omitempty"`
	Files        []string              `json:"files"`
	Verified     bool                  `json:"verified"`
	Verification []PackageVerification `json:"verification"`
}

type PackageVerification struct {
	Input    string `json:"input"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Warnings int    `json:"warnings"`
}

type Manifest struct {
	evidence.Header
	Name              string                   `json:"name"`
	Target            string                   `json:"target"`
	SourceInput       string                   `json:"source_input,omitempty"`
	Project           string                   `json:"project,omitempty"`
	Profile           string                   `json:"profile,omitempty"`
	Object            string                   `json:"object"`
	StagedObject      string                   `json:"staged_object"`
	ObjectFingerprint evidence.FileFingerprint `json:"object_fingerprint"`
	Entrypoint        string                   `json:"entrypoint"`
	Arguments         []argpack.Item           `json:"arguments,omitempty"`
	ArgumentNames     []string                 `json:"argument_names,omitempty"`
	ArgumentOptional  []bool                   `json:"argument_optional,omitempty"`
	PackedArguments   PackedArguments          `json:"packed_arguments"`
	ArgumentContract  string                   `json:"argument_contract,omitempty"`
	Operations        OperationalContract      `json:"operations"`
	Recipe            string                   `json:"recipe,omitempty"`
	RecipeValidation  string                   `json:"recipe_validation,omitempty"`
	TargetContract    TargetContract           `json:"target_contract"`
	Evidence          []EvidenceReference      `json:"evidence,omitempty"`
	GeneratedAt       string                   `json:"generated_at"`
	Analysis          string                   `json:"analysis,omitempty"`
	AnalysisMD        string                   `json:"analysis_md,omitempty"`
	AnalysisError     string                   `json:"analysis_error,omitempty"`
	LatestReport      []string                 `json:"latest_report,omitempty"`
	Files             []FileRecord             `json:"files"`
}

type FileRecord struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func Stage(object, target, entry string, args []argpack.Item) (Result, error) {
	return StageWithOptions(Options{Object: object, Target: target, Entrypoint: entry, Arguments: args, SourceInput: object})
}

func StageWithOptions(opts Options) (Result, error) {
	object := opts.Object
	target := opts.Target
	entry := opts.Entrypoint
	args := opts.Arguments
	if entry == "" {
		entry = "go"
	}
	switch target {
	case "cobaltstrike", "sliver", "raw":
	default:
		return Result{}, fmt.Errorf("unknown stage target %q", target)
	}
	packedArguments, err := packedArgumentContract(args)
	if err != nil {
		return Result{}, err
	}
	objectFingerprint, err := fingerprintForManifest(object)
	if err != nil {
		return Result{}, err
	}
	name := baseName(object)
	if opts.Project != "" {
		name = filepath.Base(filepath.Clean(opts.Project))
	}
	generatedAt := time.Now().UTC()
	stageRunID := fmt.Sprintf("stage-%s-%s-%s", safeAlias(name), target, generatedAt.Format("20060102T150405.000000000Z"))
	outputRoot := strings.TrimSpace(opts.OutputRoot)
	if outputRoot == "" {
		outputRoot = "stage"
	}
	if filepath.IsAbs(outputRoot) || filepath.Clean(outputRoot) != outputRoot || strings.ContainsAny(outputRoot, `/\\`) || outputRoot == "." || outputRoot == ".." {
		return Result{}, fmt.Errorf("invalid export output root %q", outputRoot)
	}
	root := filepath.Join(outputRoot, fmt.Sprintf("%s-%s", name, target))
	if err := os.RemoveAll(root); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o755); err != nil {
		return Result{}, err
	}
	dstObj := filepath.Join(root, "objects", filepath.Base(object))
	if err := copyFile(object, dstObj); err != nil {
		return Result{}, err
	}
	var files []string
	manifest := Manifest{
		Header:            evidence.New(ManifestSchema, stageRunID, ""),
		Name:              name,
		Target:            target,
		SourceInput:       opts.SourceInput,
		Project:           opts.Project,
		Profile:           opts.Profile,
		Object:            object,
		StagedObject:      filepath.ToSlash(filepath.Join("objects", filepath.Base(object))),
		ObjectFingerprint: objectFingerprint,
		Entrypoint:        entry,
		Arguments:         args,
		ArgumentNames:     append([]string(nil), opts.ArgumentNames...),
		ArgumentOptional:  append([]bool(nil), opts.ArgumentOptional...),
		PackedArguments:   packedArguments,
		Operations:        operationalContract(opts),
		GeneratedAt:       generatedAt.Format(time.RFC3339),
	}
	manifest.SchemaVersion = ManifestSchemaVersion
	manifest.TargetContract = targetContract(target, name, manifest.StagedObject, entry, args, manifest.ArgumentNames, manifest.ArgumentOptional, manifest.Operations)
	add := func(path string) {
		rel, err := filepath.Rel(root, path)
		if err == nil {
			files = append(files, filepath.ToSlash(rel))
		}
	}
	add(dstObj)
	reportFiles, err := writeReports(root, object, entry, name, stageRunID)
	if err != nil {
		return Result{}, err
	}
	for _, file := range reportFiles {
		add(file)
		rel, _ := filepath.Rel(root, file)
		rel = filepath.ToSlash(rel)
		switch filepath.Base(file) {
		case "analysis.json":
			manifest.Analysis = rel
		case "analysis.md":
			manifest.AnalysisMD = rel
		case "analysis-error.txt":
			b, _ := os.ReadFile(file)
			manifest.AnalysisError = strings.TrimSpace(string(b))
		default:
			if strings.HasPrefix(rel, "reports/latest-") {
				manifest.LatestReport = append(manifest.LatestReport, rel)
			}
		}
	}
	supportFiles, err := writeHandoffEvidence(root, manifest, opts)
	if err != nil {
		return Result{}, err
	}
	for _, file := range supportFiles {
		add(file)
	}
	manifest.ArgumentContract = "reports/arguments.json"
	if opts.Recipe != nil {
		manifest.Recipe = "operations/recipe.json"
	}
	if opts.RecipeValidation != nil {
		manifest.RecipeValidation = "operations/recipe-validation.json"
	}
	for _, input := range opts.Evidence {
		manifest.Evidence = append(manifest.Evidence, EvidenceReference{Kind: input.Kind, Path: filepath.ToSlash(input.Destination)})
	}
	switch target {
	case "cobaltstrike":
		p := filepath.Join(root, name+".cna")
		if err := os.WriteFile(p, []byte(cobaltStrike(manifest)), 0o644); err != nil {
			return Result{}, err
		}
		add(p)
	case "sliver":
		sliverObject := filepath.Join(root, filepath.Base(object))
		if err := copyFile(object, sliverObject); err != nil {
			return Result{}, err
		}
		add(sliverObject)
		p := filepath.Join(root, "extension.json")
		if err := writeJSON(p, sliverExtension(manifest, filepath.Base(object))); err != nil {
			return Result{}, err
		}
		add(p)
	case "raw":
		p := filepath.Join(root, "operator-notes.md")
		if err := os.WriteFile(p, []byte(rawNotes(manifest)), 0o644); err != nil {
			return Result{}, err
		}
		add(p)
	}
	readmePath := filepath.Join(root, "README.md")
	if err := os.WriteFile(readmePath, []byte(stageReadme(manifest)), 0o644); err != nil {
		return Result{}, err
	}
	add(readmePath)
	records, err := manifestFileRecords(root, files)
	if err != nil {
		return Result{}, err
	}
	manifest.Files = records
	manifestPath := filepath.Join(root, "manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return Result{}, err
	}
	add(manifestPath)
	zipPath := root + ".zip"
	if err := zipDir(root, zipPath); err != nil {
		return Result{}, err
	}
	files = append(files, filepath.Base(zipPath))
	result := Result{Target: target, Object: object, Output: root, Manifest: filepath.ToSlash(filepath.Join(root, "manifest.json")), Files: files, Verified: true}
	for _, input := range []string{root, zipPath} {
		verification := Verify(input)
		result.Verification = append(result.Verification, PackageVerification{Input: input, Kind: verification.Kind, Status: verification.Status, Warnings: verification.Summary.Warnings})
		if !verification.Passed() {
			result.Verified = false
			return result, fmt.Errorf("generated %s package failed verification: %s: %s", verification.Kind, input, firstVerificationFailure(verification))
		}
	}
	return result, nil
}

func firstVerificationFailure(verification Verification) string {
	for _, check := range verification.Checks {
		if check.Status == "fail" {
			return check.Name + ": " + check.Message
		}
	}
	return "unknown verification failure"
}

func manifestFileRecords(root string, files []string) ([]FileRecord, error) {
	records := make([]FileRecord, 0, len(files))
	seen := map[string]bool{}
	for _, rel := range files {
		rel = filepath.ToSlash(filepath.Clean(rel))
		if seen[rel] {
			continue
		}
		seen[rel] = true
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		hash, err := sha256File(path)
		if err != nil {
			return nil, err
		}
		records = append(records, FileRecord{Path: rel, Size: info.Size(), SHA256: hash})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func cobaltStrike(manifest Manifest) string {
	var b strings.Builder
	command := manifest.TargetContract.CommandName
	description := manifest.Operations.Description
	if description == "" {
		description = "Execute the " + manifest.Name + " Beacon Object File"
	}
	fmt.Fprintf(&b, "# Generated by bofbench from manifest.json\n")
	fmt.Fprintf(&b, "beacon_command_register(\"%s\", \"%s\", \"%s\");\n\n", sleepEscape(command), sleepEscape(description), sleepEscape("Usage: "+manifest.TargetContract.Invoke+"\n\nPrivilege: "+manifest.Operations.Privilege+"; network: "+manifest.Operations.Network+"; impact: "+manifest.Operations.Impact+". See README.md for prerequisites and cleanup."))
	fmt.Fprintf(&b, "alias %s {\n", command)
	locals := "$handle $data $args"
	for index, item := range manifest.Arguments {
		if item.Kind == "b" || item.Kind == "x" {
			locals += fmt.Sprintf(" $arg%d_handle $arg%d_data", index+1, index+1)
		}
	}
	fmt.Fprintf(&b, "\tlocal('%s');\n", locals)
	fmt.Fprintf(&b, "\t$handle = openf(script_resource(\"%s\"));\n", manifest.StagedObject)
	b.WriteString("\t$data = readb($handle, -1);\n\tclosef($handle);\n")
	for index, item := range manifest.Arguments {
		if item.Kind != "b" && item.Kind != "x" {
			continue
		}
		position := index + 2
		fmt.Fprintf(&b, "\t$arg%d_handle = openf($%d);\n", index+1, position)
		fmt.Fprintf(&b, "\t$arg%d_data = readb($arg%d_handle, -1);\n", index+1, index+1)
		fmt.Fprintf(&b, "\tclosef($arg%d_handle);\n", index+1)
	}
	if len(manifest.Arguments) == 0 {
		b.WriteString("\t$args = \"\";\n")
	} else {
		fmt.Fprintf(&b, "\t$args = bof_pack($1, \"%s\"", aggressorFormat(manifest.Arguments))
		for index, item := range manifest.Arguments {
			if item.Kind == "b" || item.Kind == "x" {
				fmt.Fprintf(&b, ", $arg%d_data", index+1)
			} else {
				fmt.Fprintf(&b, ", $%d", index+2)
			}
		}
		b.WriteString(");\n")
	}
	b.WriteString("\tbinput($1, $0);\n")
	fmt.Fprintf(&b, "\tbtask($1, \"Running BOF %s\");\n", sleepEscape(manifest.Name))
	fmt.Fprintf(&b, "\tbeacon_inline_execute($1, $data, \"%s\", $args);\n", sleepEscape(manifest.Entrypoint))
	b.WriteString("}\n")
	return b.String()
}

func sleepEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	return strings.ReplaceAll(value, "\n", `\n`)
}

func aggressorFormat(args []argpack.Item) string {
	var b strings.Builder
	for _, item := range args {
		switch item.Kind {
		case "z":
			b.WriteByte('z')
		case "Z":
			b.WriteByte('Z')
		case "i":
			b.WriteByte('i')
		case "s":
			b.WriteByte('s')
		case "b", "x":
			b.WriteByte('b')
		}
	}
	return b.String()
}

func rawNotes(manifest Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Raw BOF Operator Notes\n\n- Object: `%s`\n- Exported object: `%s`\n- SHA-256: `%s`\n- Entrypoint: `%s`\n- Packed argument bytes: `%d`\n- Packed argument SHA-256: `%s`\n\n## Copy-ready command\n\n```powershell\n%s\n```\n", manifest.Object, manifest.StagedObject, manifest.ObjectFingerprint.SHA256, manifest.Entrypoint, manifest.PackedArguments.ByteLength, manifest.PackedArguments.SHA256, manifest.TargetContract.Invoke)
	b.WriteString("\nVerify the directory or ZIP with `bofbench export verify <path>` before use. Review `README.md` for requirements, effects, artifacts, and cleanup.\n")
	return b.String()
}

func stageReadme(manifest Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOFBench %s export: %s\n\n", manifest.Target, manifest.Name)
	fmt.Fprintf(&b, "- Source input: `%s`\n- Object: `%s`\n- Exported object: `%s`\n- Object SHA-256: `%s`\n- Entrypoint: `%s`\n- Manifest: `manifest.json`\n- Arguments: `reports/arguments.json`\n- Generated: `%s`\n", manifest.SourceInput, manifest.Object, manifest.StagedObject, manifest.ObjectFingerprint.SHA256, manifest.Entrypoint, manifest.GeneratedAt)
	fmt.Fprintf(&b, "\n## Operator command\n\nInstall/load:\n")
	for _, instruction := range manifest.TargetContract.Install {
		fmt.Fprintf(&b, "\n- %s\n", instruction)
	}
	fmt.Fprintf(&b, "\nInvoke:\n\n```text\n%s\n```\n", manifest.TargetContract.Invoke)
	b.WriteString("\n## Arguments\n\n")
	if len(manifest.TargetContract.Arguments) == 0 {
		b.WriteString("This BOF takes no packed arguments.\n")
	} else {
		b.WriteString("| Position | Name | BOF kind | Target type | Example |\n| ---: | --- | --- | --- | --- |\n")
		for _, argument := range manifest.TargetContract.Arguments {
			fmt.Fprintf(&b, "| %d | `%s` | `%s` | `%s` | `%s` |\n", argument.Position, argument.Name, argument.BOFKind, argument.Type, markdownCell(argument.Example))
		}
	}
	fmt.Fprintf(&b, "\nPacked format `%s`; %d bytes; SHA-256 `%s`.\n", manifest.PackedArguments.Format, manifest.PackedArguments.ByteLength, manifest.PackedArguments.SHA256)
	fmt.Fprintf(&b, "\n## Operator requirements (%s)\n\n- Pack set: `%s`\n- Privilege: `%s`\n- Platforms: `%s`\n- Network: `%s`\n- Domain: `%s`\n- Effects: `%s`\n", manifest.Operations.Status, emptyStage(manifest.Operations.Recipe, "none supplied"), manifest.Operations.Privilege, strings.Join(manifest.Operations.Platforms, ", "), manifest.Operations.Network, manifest.Operations.Domain, manifest.Operations.Impact)
	writeStageList(&b, "Prerequisites", manifest.Operations.Prerequisites)
	writeStageList(&b, "State changes", manifest.Operations.StateChanges)
	writeStageList(&b, "Expected artifacts", manifest.Operations.Artifacts)
	writeStageList(&b, "Cleanup", manifest.Operations.Cleanup)
	writeStageList(&b, "Operator notes", manifest.Operations.OperatorNotes)
	b.WriteString("\n## Reports and verification\n\nThe package carries linked static analysis, exact object/argument fingerprints, and any project developer/source/build reports listed in `manifest.json`. Before use:\n\n```sh\nbofbench export verify .\nbofbench export verify ../" + manifest.Name + "-" + manifest.Target + ".zip\n```\n")
	return b.String()
}

func writeStageList(b *strings.Builder, title string, values []string) {
	fmt.Fprintf(b, "\n### %s\n", title)
	for _, value := range values {
		fmt.Fprintf(b, "\n- %s\n", value)
	}
}

func markdownCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", `\|`), "`", "'")
}

func emptyStage(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func legacyCobaltStrike(name, objectFile, entry string, args []argpack.Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by bofbench\n")
	fmt.Fprintf(&b, "alias %s {\n", safeAlias(name))
	b.WriteString("\tlocal('$handle $data $args');\n")
	fmt.Fprintf(&b, "\t$handle = openf(script_resource(\"objects/%s\"));\n", objectFile)
	b.WriteString("\t$data = readb($handle, -1);\n\tclosef($handle);\n")
	if len(args) == 0 {
		b.WriteString("\t$args = \"\";\n")
	} else {
		fmt.Fprintf(&b, "\t$args = bof_pack($1, \"%s\"", aggressorFormat(args))
		for i := range args {
			fmt.Fprintf(&b, ", $%d", i+2)
		}
		b.WriteString(");\n")
	}
	fmt.Fprintf(&b, "\tbtask($1, \"Running BOF %s\");\n", name)
	fmt.Fprintf(&b, "\tbeacon_inline_execute($1, $data, \"%s\", $args);\n", entry)
	b.WriteString("}\n")
	return b.String()
}

func legacyRawNotes(object, entry string, args []argpack.Item) string {
	return fmt.Sprintf("# Raw BOF Stage\n\n- Object: `%s`\n- Entrypoint: `%s`\n- Args: `%v`\n", object, entry, args)
}

func legacyStageReadme(target, object, entry string, args []argpack.Item, generatedAt string) string {
	return fmt.Sprintf("# bofbench %s stage\n\n- Object: `%s`\n- Entrypoint: `%s`\n- Args: `%v`\n- Manifest: `manifest.json`\n- Reports: `reports/`\n\nGenerated at `%s`.\n", target, object, entry, args, generatedAt)
}

func writeHandoffEvidence(root string, manifest Manifest, opts Options) ([]string, error) {
	reportsDir := filepath.Join(root, "reports")
	operationsDir := filepath.Join(root, "operations")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return nil, err
	}
	argumentPath := filepath.Join(reportsDir, "arguments.json")
	if err := writeJSON(argumentPath, ArgumentEvidence{
		Schema: ArgumentSchema, SchemaVersion: evidence.ContractVersion, Entrypoint: manifest.Entrypoint,
		Items: manifest.Arguments, Names: manifest.ArgumentNames, Optional: manifest.ArgumentOptional, Packed: manifest.PackedArguments,
	}); err != nil {
		return nil, err
	}
	files := []string{argumentPath}
	if opts.Recipe != nil || opts.RecipeValidation != nil {
		if err := os.MkdirAll(operationsDir, 0o755); err != nil {
			return nil, err
		}
	}
	if opts.Recipe != nil {
		path := filepath.Join(operationsDir, "recipe.json")
		if err := writeJSON(path, opts.Recipe); err != nil {
			return nil, err
		}
		files = append(files, path)
	}
	if opts.RecipeValidation != nil {
		path := filepath.Join(operationsDir, "recipe-validation.json")
		if err := writeJSON(path, opts.RecipeValidation); err != nil {
			return nil, err
		}
		files = append(files, path)
	}
	seen := map[string]bool{}
	for _, input := range opts.Evidence {
		destination := filepath.ToSlash(filepath.Clean(input.Destination))
		clean, err := cleanPackagePath(destination)
		if err != nil || clean != destination || !strings.HasPrefix(clean, "reports/") {
			return nil, fmt.Errorf("evidence destination must be a safe path under reports/: %s", input.Destination)
		}
		if seen[strings.ToLower(clean)] || clean == "reports/arguments.json" || strings.HasPrefix(clean, "reports/latest-") || clean == "reports/analysis.json" || clean == "reports/analysis.md" || clean == "reports/analysis-error.txt" {
			return nil, fmt.Errorf("duplicate or reserved evidence destination %s", clean)
		}
		seen[strings.ToLower(clean)] = true
		destinationPath := filepath.Join(root, filepath.FromSlash(clean))
		if err := copyFile(input.Path, destinationPath); err != nil {
			return nil, fmt.Errorf("copy %s evidence: %w", input.Kind, err)
		}
		files = append(files, destinationPath)
	}
	return files, nil
}

func writeReports(root, object, entry, name, parentRunID string) ([]string, error) {
	reportsDir := filepath.Join(root, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return nil, err
	}
	var files []string
	a, err := artifact.Analyze(object, entry)
	if err != nil {
		p := filepath.Join(reportsDir, "analysis-error.txt")
		if writeErr := os.WriteFile(p, []byte(err.Error()+"\n"), 0o644); writeErr != nil {
			return nil, writeErr
		}
		files = append(files, p)
	} else {
		a.Header = evidence.New(evidence.SchemaAnalysis, parentRunID+"/analysis", parentRunID)
		jsonPath := filepath.Join(reportsDir, "analysis.json")
		mdPath := filepath.Join(reportsDir, "analysis.md")
		if err := writeJSON(jsonPath, a); err != nil {
			return nil, err
		}
		if err := os.WriteFile(mdPath, []byte(artifact.Markdown(a)), 0o644); err != nil {
			return nil, err
		}
		files = append(files, jsonPath, mdPath)
	}
	latest := latestResultFiles(name)
	for _, src := range latest {
		dst := filepath.Join(reportsDir, "latest-"+filepath.Base(src))
		if err := copyFile(src, dst); err != nil {
			return nil, err
		}
		files = append(files, dst)
	}
	return files, nil
}

func latestResultFiles(name string) []string {
	entries, err := os.ReadDir("runs")
	if err != nil {
		return nil
	}
	candidates := map[string]bool{name: true, safeAlias(name): true}
	var best string
	var bestTime time.Time
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirName := entry.Name()
		if !matchesRunDir(dirName, candidates) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestTime) {
			best = filepath.Join("runs", dirName)
			bestTime = info.ModTime()
		}
	}
	if best == "" {
		return nil
	}
	var out []string
	for _, name := range []string{"result.json", "result.md"} {
		p := filepath.Join(best, name)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func matchesRunDir(dirName string, candidates map[string]bool) bool {
	for name := range candidates {
		if strings.HasSuffix(dirName, "-run-"+name) || strings.HasSuffix(dirName, "-test-"+name) {
			return true
		}
	}
	return false
}

func baseName(object string) string {
	base := filepath.Base(object)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimSuffix(base, ".x64")
	base = strings.TrimSuffix(base, ".x86")
	return base
}

func safeAlias(name string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range name {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_'
		if valid {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	value := strings.Trim(b.String(), "_")
	if value == "" {
		value = "bof"
	}
	if value[0] >= '0' && value[0] <= '9' {
		value = "bof_" + value
	}
	return value
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func zipDir(root, zipPath string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if walkErr != nil {
		_ = zw.Close()
		_ = out.Close()
		return walkErr
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
