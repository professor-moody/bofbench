package stage

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"bofbench/internal/argpack"
	"bofbench/internal/artifact"
)

const (
	VerificationSchema        = "bofbench.stage-verification"
	VerificationSchemaVersion = 1
	maxVerificationFiles      = 10000
	maxVerificationFileBytes  = int64(128 << 20)
	maxVerificationTotalBytes = int64(512 << 20)
	maxManifestBytes          = int64(1 << 20)
	maxMetadataBytes          = int64(16 << 20)
)

type Verification struct {
	Schema        string              `json:"schema"`
	SchemaVersion int                 `json:"schema_version"`
	Input         string              `json:"input"`
	Kind          string              `json:"kind,omitempty"`
	Status        string              `json:"status"`
	Name          string              `json:"name,omitempty"`
	Target        string              `json:"target,omitempty"`
	Object        string              `json:"object,omitempty"`
	StagedObject  string              `json:"staged_object,omitempty"`
	CheckedAt     string              `json:"checked_at"`
	Summary       VerificationSummary `json:"summary"`
	Checks        []VerificationCheck `json:"checks"`
}

type VerificationSummary struct {
	Files    int   `json:"files"`
	Bytes    int64 `json:"bytes"`
	Passed   int   `json:"passed"`
	Warnings int   `json:"warnings"`
	Failed   int   `json:"failed"`
}

type VerificationCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type packagedFile struct {
	name string
	size int64
	open func() (io.ReadCloser, error)
}

type packageView struct {
	kind   string
	files  map[string]packagedFile
	issues []VerificationCheck
	bytes  int64
	close  func() error
}

func Verify(input string) Verification {
	report := Verification{
		Schema:        VerificationSchema,
		SchemaVersion: VerificationSchemaVersion,
		Input:         input,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:        "fail",
		Checks:        []VerificationCheck{},
	}
	view, err := openPackageView(input)
	if err != nil {
		report.add("package.open", "fail", input, err.Error())
		report.finalize()
		return report
	}
	if view.close != nil {
		defer view.close()
	}
	report.Kind = view.kind
	report.Summary.Files = len(view.files)
	report.Summary.Bytes = view.bytes
	for _, issue := range view.issues {
		report.Checks = append(report.Checks, issue)
	}
	if len(view.issues) == 0 {
		report.add("package.inventory", "pass", input, fmt.Sprintf("%d regular files indexed", len(view.files)))
	}

	manifestBytes, err := view.read("manifest.json", maxManifestBytes)
	if err != nil {
		report.add("manifest.present", "fail", "manifest.json", err.Error())
		report.finalize()
		return report
	}
	report.add("manifest.present", "pass", "manifest.json", "manifest is present and readable")
	var manifest Manifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		report.add("manifest.json", "fail", "manifest.json", err.Error())
		report.finalize()
		return report
	}
	report.add("manifest.json", "pass", "manifest.json", "manifest is valid JSON")
	report.Name = manifest.Name
	report.Target = manifest.Target
	report.Object = manifest.Object
	report.StagedObject = manifest.StagedObject

	verifyManifestMetadata(&report, manifest)
	expected, objectHash, objectSize := verifyManifestFiles(&report, view, manifest)
	verifyAnalysisReports(&report, view, manifest, expected, objectHash, objectSize)
	verifyLatestReports(&report, view, manifest, expected)
	verifyTargetFiles(&report, view, manifest, expected)
	report.finalize()
	return report
}

func (v Verification) Passed() bool {
	return v.Summary.Failed == 0
}

func (v Verification) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Stage Package Verification: %s\n\n", strings.ToUpper(v.Status))
	fmt.Fprintf(&b, "Input: %s\n", v.Input)
	if v.Kind != "" {
		fmt.Fprintf(&b, "Kind: %s\n", v.Kind)
	}
	if v.Name != "" {
		fmt.Fprintf(&b, "Name: %s\n", v.Name)
	}
	if v.Target != "" {
		fmt.Fprintf(&b, "Target: %s\n", v.Target)
	}
	fmt.Fprintf(&b, "Files: %d (%d bytes)\n", v.Summary.Files, v.Summary.Bytes)
	fmt.Fprintf(&b, "Checks: %d passed, %d warnings, %d failed\n\n", v.Summary.Passed, v.Summary.Warnings, v.Summary.Failed)
	for _, check := range v.Checks {
		location := ""
		if check.Path != "" {
			location = " [" + check.Path + "]"
		}
		message := strings.ReplaceAll(check.Message, "\n", " ")
		fmt.Fprintf(&b, "%-4s %-28s%s %s\n", strings.ToUpper(check.Status), check.Name, location, message)
	}
	return b.String()
}

func (v *Verification) add(name, status, checkPath, message string) {
	v.Checks = append(v.Checks, VerificationCheck{Name: name, Status: status, Path: checkPath, Message: message})
}

func (v *Verification) finalize() {
	v.Summary.Passed = 0
	v.Summary.Warnings = 0
	v.Summary.Failed = 0
	for _, check := range v.Checks {
		switch check.Status {
		case "pass":
			v.Summary.Passed++
		case "warn":
			v.Summary.Warnings++
		case "fail":
			v.Summary.Failed++
		}
	}
	switch {
	case v.Summary.Failed > 0:
		v.Status = "fail"
	case v.Summary.Warnings > 0:
		v.Status = "pass_with_warnings"
	default:
		v.Status = "pass"
	}
}

func openPackageView(input string) (*packageView, error) {
	info, err := os.Lstat(input)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("package input must not be a symlink")
	}
	if info.IsDir() {
		return openDirectoryView(input)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("package input is not a directory or regular ZIP file")
	}
	return openZipView(input)
}

func openDirectoryView(root string) (*packageView, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	view := &packageView{kind: "directory", files: map[string]packagedFile{}}
	seen := map[string]string{}
	entries := 0
	err = filepath.WalkDir(rootAbs, func(diskPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if diskPath == rootAbs {
			return nil
		}
		entries++
		if entries > maxVerificationFiles {
			view.issue("package.limit", filepath.ToSlash(diskPath), fmt.Sprintf("package exceeds %d entries", maxVerificationFiles))
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(rootAbs, diskPath)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			view.issue("package.entry", name, "symlinks are not allowed")
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if _, err := cleanPackagePath(name); err != nil {
			view.issue("package.entry", name, err.Error())
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			view.issue("package.entry", name, "entry is not a regular file")
			return nil
		}
		if len(view.files) >= maxVerificationFiles {
			view.issue("package.limit", name, fmt.Sprintf("package exceeds %d files", maxVerificationFiles))
			return nil
		}
		if info.Size() > maxVerificationFileBytes || info.Size() > maxVerificationTotalBytes-view.bytes {
			view.issue("package.limit", name, "package exceeds verification size limits")
			return nil
		}
		key := strings.ToLower(name)
		if previous, ok := seen[key]; ok {
			view.issue("package.duplicate", name, fmt.Sprintf("case-collides with %s", previous))
			return nil
		}
		seen[key] = name
		captured := diskPath
		view.files[name] = packagedFile{name: name, size: info.Size(), open: func() (io.ReadCloser, error) { return os.Open(captured) }}
		view.bytes += info.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

func openZipView(zipPath string) (*packageView, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	view := &packageView{kind: "zip", files: map[string]packagedFile{}, close: zr.Close}
	if len(zr.File) > maxVerificationFiles {
		view.issue("package.limit", zipPath, fmt.Sprintf("package contains %d entries; limit is %d", len(zr.File), maxVerificationFiles))
		return view, nil
	}
	seen := map[string]string{}
	for _, file := range zr.File {
		name := strings.TrimSuffix(file.Name, "/")
		if name == "" {
			continue
		}
		clean, err := cleanPackagePath(name)
		if err != nil {
			view.issue("package.entry", file.Name, err.Error())
			continue
		}
		if file.Flags&0x1 != 0 {
			view.issue("package.entry", file.Name, "encrypted ZIP entries are not supported")
			continue
		}
		mode := file.Mode()
		if mode&os.ModeSymlink != 0 {
			view.issue("package.entry", file.Name, "symlinks are not allowed")
			continue
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if !mode.IsRegular() {
			view.issue("package.entry", file.Name, "entry is not a regular file")
			continue
		}
		if len(view.files) >= maxVerificationFiles {
			view.issue("package.limit", clean, fmt.Sprintf("package exceeds %d files", maxVerificationFiles))
			continue
		}
		if file.UncompressedSize64 > uint64(maxVerificationFileBytes) || file.UncompressedSize64 > uint64(maxVerificationTotalBytes-view.bytes) {
			view.issue("package.limit", clean, "package exceeds verification size limits")
			continue
		}
		key := strings.ToLower(clean)
		if previous, ok := seen[key]; ok {
			view.issue("package.duplicate", clean, fmt.Sprintf("case-collides with %s", previous))
			continue
		}
		seen[key] = clean
		captured := file
		view.files[clean] = packagedFile{name: clean, size: int64(file.UncompressedSize64), open: captured.Open}
		view.bytes += int64(file.UncompressedSize64)
	}
	return view, nil
}

func (v *packageView) issue(name, checkPath, message string) {
	v.issues = append(v.issues, VerificationCheck{Name: name, Status: "fail", Path: checkPath, Message: message})
}

func (v *packageView) read(name string, maxBytes int64) ([]byte, error) {
	file, ok := v.files[name]
	if !ok {
		return nil, fmt.Errorf("file is missing")
	}
	if file.size > maxBytes {
		return nil, fmt.Errorf("file is %d bytes; verification limit is %d", file.size, maxBytes)
	}
	in, err := file.open()
	if err != nil {
		return nil, err
	}
	defer in.Close()
	data, err := io.ReadAll(io.LimitReader(in, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d byte verification limit", maxBytes)
	}
	return data, nil
}

func (v *packageView) hash(name string) (string, error) {
	file, ok := v.files[name]
	if !ok {
		return "", fmt.Errorf("file is missing")
	}
	in, err := file.open()
	if err != nil {
		return "", err
	}
	defer in.Close()
	h := sha256.New()
	if _, err := io.Copy(h, in); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func cleanPackagePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) {
		return "", fmt.Errorf("unsafe package path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean != name {
		return "", fmt.Errorf("unsafe package path %q", name)
	}
	first := strings.SplitN(clean, "/", 2)[0]
	if strings.Contains(first, ":") || filepath.VolumeName(filepath.FromSlash(clean)) != "" {
		return "", fmt.Errorf("unsafe package path %q", name)
	}
	return clean, nil
}

func decodeStrictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON contains multiple values")
		}
		return err
	}
	return nil
}

func verifyManifestMetadata(report *Verification, manifest Manifest) {
	if manifest.Schema == ManifestSchema && manifest.SchemaVersion == ManifestSchemaVersion {
		report.add("manifest.schema", "pass", "manifest.json", fmt.Sprintf("%s version %d", manifest.Schema, manifest.SchemaVersion))
	} else {
		report.add("manifest.schema", "fail", "manifest.json", fmt.Sprintf("expected %s version %d, got %q version %d", ManifestSchema, ManifestSchemaVersion, manifest.Schema, manifest.SchemaVersion))
	}
	if validPackageName(manifest.Name) {
		report.add("manifest.name", "pass", "manifest.json", manifest.Name)
	} else {
		report.add("manifest.name", "fail", "manifest.json", "name must be a safe non-empty path component")
	}
	switch manifest.Target {
	case "cobaltstrike", "sliver", "raw":
		report.add("manifest.target", "pass", "manifest.json", manifest.Target)
	default:
		report.add("manifest.target", "fail", "manifest.json", fmt.Sprintf("unsupported target %q", manifest.Target))
	}
	if strings.TrimSpace(manifest.Object) != "" {
		report.add("manifest.object", "pass", "manifest.json", manifest.Object)
	} else {
		report.add("manifest.object", "fail", "manifest.json", "source object path is empty")
	}
	if clean, err := cleanPackagePath(manifest.StagedObject); err == nil && clean == manifest.StagedObject && strings.HasPrefix(clean, "objects/") {
		report.add("manifest.staged_object", "pass", "manifest.json", manifest.StagedObject)
	} else {
		report.add("manifest.staged_object", "fail", "manifest.json", "staged object must be a safe path under objects/")
	}
	if strings.TrimSpace(manifest.Entrypoint) != "" {
		report.add("manifest.entrypoint", "pass", "manifest.json", manifest.Entrypoint)
	} else {
		report.add("manifest.entrypoint", "fail", "manifest.json", "entrypoint is empty")
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err == nil {
		report.add("manifest.generated_at", "pass", "manifest.json", manifest.GeneratedAt)
	} else {
		report.add("manifest.generated_at", "fail", "manifest.json", "generated_at is not RFC3339")
	}
	if _, err := argpack.PackItems(manifest.Arguments); err == nil {
		report.add("manifest.arguments", "pass", "manifest.json", fmt.Sprintf("%d argument definitions", len(manifest.Arguments)))
	} else {
		report.add("manifest.arguments", "fail", "manifest.json", err.Error())
	}
}

func validPackageName(name string) bool {
	if strings.TrimSpace(name) == "" || name == "." || name == ".." || strings.ContainsAny(name, `:/\`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func verifyManifestFiles(report *Verification, view *packageView, manifest Manifest) (map[string]FileRecord, string, int64) {
	expected := map[string]FileRecord{}
	expectedLower := map[string]string{}
	if len(manifest.Files) == 0 {
		report.add("manifest.files", "fail", "manifest.json", "manifest contains no file records")
	} else {
		report.add("manifest.files", "pass", "manifest.json", fmt.Sprintf("%d file records", len(manifest.Files)))
	}
	objectHash := ""
	objectSize := int64(0)
	for _, record := range manifest.Files {
		clean, err := cleanPackagePath(record.Path)
		if err != nil || clean == "manifest.json" {
			report.add("file.record", "fail", record.Path, "file record path is unsafe or reserved")
			continue
		}
		key := strings.ToLower(clean)
		if existing, ok := expectedLower[key]; ok {
			report.add("file.record", "fail", record.Path, fmt.Sprintf("duplicates %s", existing))
			continue
		}
		expectedLower[key] = clean
		expected[clean] = record
		file, ok := view.files[clean]
		if !ok {
			report.add("file.integrity", "fail", clean, "recorded file is missing")
			continue
		}
		if record.Size < 0 || file.size != record.Size {
			report.add("file.integrity", "fail", clean, fmt.Sprintf("size mismatch: manifest=%d package=%d", record.Size, file.size))
			continue
		}
		if len(record.SHA256) != sha256.Size*2 {
			report.add("file.integrity", "fail", clean, "manifest SHA-256 is not 64 hexadecimal characters")
			continue
		}
		if _, err := hex.DecodeString(record.SHA256); err != nil {
			report.add("file.integrity", "fail", clean, "manifest SHA-256 is invalid hexadecimal")
			continue
		}
		actual, err := view.hash(clean)
		if err != nil {
			report.add("file.integrity", "fail", clean, err.Error())
			continue
		}
		if !strings.EqualFold(actual, record.SHA256) {
			report.add("file.integrity", "fail", clean, fmt.Sprintf("SHA-256 mismatch: manifest=%s package=%s", record.SHA256, actual))
			continue
		}
		report.add("file.integrity", "pass", clean, fmt.Sprintf("%d bytes sha256=%s", file.size, actual))
		if clean == manifest.StagedObject {
			objectHash = actual
			objectSize = file.size
		}
	}
	for name := range view.files {
		if name == "manifest.json" {
			continue
		}
		if _, ok := expected[name]; !ok {
			report.add("package.extra_file", "fail", name, "file is not recorded in manifest")
		}
	}
	if _, ok := view.files["manifest.json"]; !ok {
		report.add("package.inventory", "fail", "manifest.json", "manifest is missing from package inventory")
	}
	if _, ok := expected[manifest.StagedObject]; !ok || objectHash == "" {
		report.add("object.integrity", "fail", manifest.StagedObject, "staged object is not a verified manifest file")
	} else if objectSize == 0 {
		report.add("object.integrity", "fail", manifest.StagedObject, "staged object is empty")
	} else {
		report.add("object.integrity", "pass", manifest.StagedObject, fmt.Sprintf("verified object sha256=%s", objectHash))
	}
	return expected, objectHash, objectSize
}

func verifyAnalysisReports(report *Verification, view *packageView, manifest Manifest, expected map[string]FileRecord, objectHash string, objectSize int64) {
	if manifest.AnalysisError != "" {
		if manifest.Analysis != "" || manifest.AnalysisMD != "" {
			report.add("analysis.contract", "fail", "manifest.json", "analysis paths and analysis_error cannot both be set")
		}
		const errorPath = "reports/analysis-error.txt"
		if _, ok := expected[errorPath]; !ok {
			report.add("analysis.contract", "fail", errorPath, "analysis error file is not recorded")
			return
		}
		data, err := view.read(errorPath, maxMetadataBytes)
		if err != nil || strings.TrimSpace(string(data)) != strings.TrimSpace(manifest.AnalysisError) {
			report.add("analysis.contract", "fail", errorPath, "analysis error evidence does not match manifest")
			return
		}
		report.add("analysis.contract", "warn", errorPath, "package is structurally valid but artifact analysis failed: "+manifest.AnalysisError)
		return
	}
	jsonReferenceOK := verifyReference(report, manifest.Analysis, "reports/", expected, "analysis.json")
	markdownReferenceOK := verifyReference(report, manifest.AnalysisMD, "reports/", expected, "analysis.markdown")
	if !jsonReferenceOK || !markdownReferenceOK {
		return
	}
	data, err := view.read(manifest.Analysis, maxMetadataBytes)
	if err != nil {
		report.add("analysis.json", "fail", manifest.Analysis, err.Error())
		return
	}
	var analysis artifact.Analysis
	if err := decodeStrictJSON(data, &analysis); err != nil {
		report.add("analysis.json", "fail", manifest.Analysis, err.Error())
		return
	}
	if analysis.SHA256 != objectHash || analysis.Size != objectSize || analysis.Entrypoint != manifest.Entrypoint || analysis.Path != manifest.Object {
		report.add("analysis.object", "fail", manifest.Analysis, "analysis object hash, size, entrypoint, or source path does not match manifest")
	} else {
		report.add("analysis.object", "pass", manifest.Analysis, "analysis matches the staged object and manifest")
	}
	markdown, err := view.read(manifest.AnalysisMD, maxMetadataBytes)
	if err != nil || strings.TrimSpace(string(markdown)) == "" {
		report.add("analysis.markdown", "fail", manifest.AnalysisMD, "analysis Markdown is missing or empty")
	} else {
		report.add("analysis.markdown", "pass", manifest.AnalysisMD, "analysis Markdown is present")
	}
}

func verifyLatestReports(report *Verification, view *packageView, manifest Manifest, expected map[string]FileRecord) {
	seen := map[string]bool{}
	for _, reportPath := range manifest.LatestReport {
		if seen[reportPath] {
			report.add("latest_report", "fail", reportPath, "duplicate latest report reference")
			continue
		}
		seen[reportPath] = true
		if !verifyReference(report, reportPath, "reports/", expected, "latest_report") {
			continue
		}
		if strings.HasSuffix(strings.ToLower(reportPath), ".json") {
			data, err := view.read(reportPath, maxMetadataBytes)
			if err != nil || !json.Valid(data) {
				report.add("latest_report.json", "fail", reportPath, "latest report is not valid JSON")
			} else {
				report.add("latest_report.json", "pass", reportPath, "latest report JSON is valid")
			}
		}
	}
}

func verifyReference(report *Verification, reference, prefix string, expected map[string]FileRecord, name string) bool {
	clean, err := cleanPackagePath(reference)
	if err != nil || !strings.HasPrefix(clean, prefix) {
		report.add(name, "fail", reference, fmt.Sprintf("reference must be a safe path under %s", prefix))
		return false
	}
	if _, ok := expected[clean]; !ok {
		report.add(name, "fail", reference, "referenced file is not recorded in manifest")
		return false
	}
	report.add(name, "pass", reference, "reference is present in the verified manifest inventory")
	return true
}

func verifyTargetFiles(report *Verification, view *packageView, manifest Manifest, expected map[string]FileRecord) {
	if verifyNonemptyFile(report, view, expected, "README.md", "target.readme") {
		data, _ := view.read("README.md", maxMetadataBytes)
		text := string(data)
		if !strings.Contains(text, manifest.Target) || !strings.Contains(text, manifest.Object) || !strings.Contains(text, manifest.Entrypoint) {
			report.add("target.readme.contract", "fail", "README.md", "README target, object, or entrypoint does not match manifest")
		} else {
			report.add("target.readme.contract", "pass", "README.md", "README matches manifest target, object, and entrypoint")
		}
	}
	switch manifest.Target {
	case "cobaltstrike":
		cna := manifest.Name + ".cna"
		if !verifyNonemptyFile(report, view, expected, cna, "target.cobaltstrike") {
			return
		}
		data, _ := view.read(cna, maxMetadataBytes)
		expectedScript := cobaltStrike(manifest.Name, path.Base(manifest.StagedObject), manifest.Entrypoint, manifest.Arguments)
		if string(data) != expectedScript {
			report.add("target.cobaltstrike.contract", "fail", cna, "Aggressor script does not match manifest-derived canonical content")
		} else {
			report.add("target.cobaltstrike.contract", "pass", cna, "Aggressor script matches manifest-derived canonical content")
		}
	case "sliver":
		const metadataPath = "sliver-extension.json"
		if !verifyNonemptyFile(report, view, expected, metadataPath, "target.sliver") {
			return
		}
		data, _ := view.read(metadataPath, maxMetadataBytes)
		var metadata struct {
			Name        string         `json:"name"`
			Entrypoint  string         `json:"entrypoint"`
			Object      string         `json:"object"`
			Arguments   []argpack.Item `json:"arguments"`
			GeneratedAt string         `json:"generated_at"`
		}
		if err := decodeStrictJSON(data, &metadata); err != nil {
			report.add("target.sliver.contract", "fail", metadataPath, err.Error())
			return
		}
		if metadata.Name != manifest.Name || metadata.Entrypoint != manifest.Entrypoint || metadata.Object != manifest.StagedObject || !reflect.DeepEqual(metadata.Arguments, manifest.Arguments) {
			report.add("target.sliver.contract", "fail", metadataPath, "Sliver metadata does not match manifest")
			return
		}
		if _, err := time.Parse(time.RFC3339, metadata.GeneratedAt); err != nil {
			report.add("target.sliver.contract", "fail", metadataPath, "generated_at is not RFC3339")
			return
		}
		report.add("target.sliver.contract", "pass", metadataPath, "Sliver metadata matches manifest")
	case "raw":
		const notesPath = "operator-notes.md"
		if !verifyNonemptyFile(report, view, expected, notesPath, "target.raw") {
			return
		}
		data, _ := view.read(notesPath, maxMetadataBytes)
		expectedNotes := rawNotes(manifest.Object, manifest.Entrypoint, manifest.Arguments)
		if string(data) != expectedNotes {
			report.add("target.raw.contract", "fail", notesPath, "operator notes do not match manifest-derived canonical content")
		} else {
			report.add("target.raw.contract", "pass", notesPath, "operator notes match manifest-derived canonical content")
		}
	}
}

func verifyNonemptyFile(report *Verification, view *packageView, expected map[string]FileRecord, filePath, name string) bool {
	if _, ok := expected[filePath]; !ok {
		report.add(name, "fail", filePath, "required target file is not recorded in manifest")
		return false
	}
	data, err := view.read(filePath, maxMetadataBytes)
	if err != nil || strings.TrimSpace(string(data)) == "" {
		report.add(name, "fail", filePath, "required target file is missing or empty")
		return false
	}
	report.add(name, "pass", filePath, "required target file is present")
	return true
}
