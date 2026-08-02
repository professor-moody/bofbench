package matrix

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/runlog"
	runtimesvc "github.com/professor-moody/bofbench/internal/runtime"
)

const (
	maxMatrixReportBytes = 64 << 20
	maxMatrixCells       = 64
)

func Replay(path string) (Persisted, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return Persisted{}, fmt.Errorf("matrix replay requires a Windows x64 host")
	}
	source, err := loadReport(path)
	if err != nil {
		return Persisted{}, err
	}
	if err := validateReplayReport(source); err != nil {
		return Persisted{}, err
	}
	packedArgs, _, err := argpack.PackTokens(source.Contract.Args)
	if err != nil {
		return Persisted{}, fmt.Errorf("matrix replay arguments: %w", err)
	}
	runDir, err := runlog.NewDir("matrix-replay-" + safeName(filepath.Base(source.Path)))
	if err != nil {
		return Persisted{}, err
	}
	objectsDir := filepath.Join(runDir, "objects")
	if err := os.MkdirAll(objectsDir, 0o755); err != nil {
		return Persisted{}, err
	}
	report := source
	report.Header = evidence.New(evidence.SchemaCompilerMatrix, runlog.ID(runDir), source.RunID)
	report.ReplayOf = source.RunID
	if fingerprint, fingerprintErr := evidence.FingerprintFile(path); fingerprintErr == nil {
		report.ReplaySource = &fingerprint
	}
	report.Execution = "replay"
	report.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.CompletedAt = ""
	for index := range report.Cells {
		cell := &report.Cells[index]
		if cell.Architecture != "x64" || cell.Artifact == "" || cell.Status == cellSkip || cell.Status == cellFail {
			continue
		}
		cell.Status = cellFail
		cell.Stage = "artifact"
		cell.Classification = "artifact_missing"
		cell.Error = ""
		sourceArtifact, resolveErr := resolveReplayArtifact(path, cell.ID)
		if resolveErr != nil {
			cell.Error = resolveErr.Error()
			continue
		}
		fingerprint, fingerprintErr := evidence.FingerprintFile(sourceArtifact)
		if fingerprintErr != nil {
			cell.Error = fingerprintErr.Error()
			continue
		}
		if cell.ArtifactFingerprint != nil && (cell.ArtifactFingerprint.SHA256 != fingerprint.SHA256 || cell.ArtifactFingerprint.Size != fingerprint.Size) {
			cell.Classification = "artifact_integrity_failed"
			cell.Error = fmt.Sprintf("artifact fingerprint mismatch: expected %s/%d, got %s/%d", cell.ArtifactFingerprint.SHA256, cell.ArtifactFingerprint.Size, fingerprint.SHA256, fingerprint.Size)
			continue
		}
		destination := filepath.Join(objectsDir, cell.ID+".o")
		if copyErr := copyFile(sourceArtifact, destination); copyErr != nil {
			cell.Classification = "artifact_copy_failed"
			cell.Error = copyErr.Error()
			continue
		}
		cell.Artifact = destination
		if copiedFingerprint, copiedErr := evidence.FingerprintFile(destination); copiedErr == nil {
			cell.ArtifactFingerprint = &copiedFingerprint
		}
		cell.RuntimeAttempted = true
		cell.Stage = "runtime"
		run, runErr := runtimesvc.Run(runtimesvc.Request{
			Path:      destination,
			Entry:     report.Entrypoint,
			ArgHex:    argpack.Hex(packedArgs),
			Tokens:    report.Contract.Args,
			TimeoutMS: report.Contract.TimeoutMS,
			Runtime:   report.Runtime,
		})
		run.Header = evidence.New(evidence.SchemaRun, report.RunID+"/"+cell.ID+"/run", report.RunID)
		cell.Run = &run
		if validationErr := validateRunContract(report.Contract, run, runErr); validationErr != nil {
			cell.Classification = "runtime_failed"
			cell.Error = validationErr.Error()
			continue
		}
		cell.Status = cellPass
		cell.Classification = "runtime_pass"
	}
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.Summary = summarize(report.Cells)
	report.Status = "pass"
	if report.Summary.Failed > 0 {
		report.Status = "fail"
	} else if report.Summary.Skipped > 0 {
		report.Status = "pass_with_skips"
	}
	jsonPath := filepath.Join(runDir, "matrix.json")
	mdPath := filepath.Join(runDir, "matrix.md")
	if err := writeJSON(jsonPath, report); err != nil {
		return Persisted{}, err
	}
	if err := os.WriteFile(mdPath, []byte(Markdown(report)), 0o644); err != nil {
		return Persisted{}, err
	}
	persisted := Persisted{Report: report, JSONPath: jsonPath, MDPath: mdPath}
	if report.Summary.Failed > 0 {
		return persisted, fmt.Errorf("matrix replay has %d failed cell(s)", report.Summary.Failed)
	}
	return persisted, nil
}

func loadReport(path string) (Report, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Report{}, fmt.Errorf("stat matrix report %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Report{}, fmt.Errorf("matrix report %s is not a regular file", path)
	}
	if info.Size() > maxMatrixReportBytes {
		return Report{}, fmt.Errorf("matrix report %s exceeds the %d MiB limit", path, maxMatrixReportBytes/(1<<20))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, fmt.Errorf("read matrix report %s: %w", path, err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return Report{}, fmt.Errorf("parse matrix report %s: %w", path, err)
	}
	return report, nil
}

func validateReplayReport(report Report) error {
	if report.Schema != evidence.SchemaCompilerMatrix || report.SchemaVersion != evidence.ContractVersion {
		return fmt.Errorf("matrix replay expected %s version %d, got %q version %d", evidence.SchemaCompilerMatrix, evidence.ContractVersion, report.Schema, report.SchemaVersion)
	}
	if report.Runtime != "windows-coff" {
		return fmt.Errorf("matrix replay requires windows-coff evidence, got %q", report.Runtime)
	}
	if report.RunID == "" || report.Entrypoint == "" {
		return fmt.Errorf("matrix replay evidence is missing run or entrypoint identity")
	}
	if len(report.Cells) == 0 || len(report.Cells) > maxMatrixCells {
		return fmt.Errorf("matrix replay cell count %d is outside the 1..%d limit", len(report.Cells), maxMatrixCells)
	}
	seen := map[string]bool{}
	for _, cell := range report.Cells {
		if cell.Compiler != "mingw" && cell.Compiler != "msvc" {
			return fmt.Errorf("matrix replay cell %q has unsupported compiler %q", cell.ID, cell.Compiler)
		}
		if cell.Optimization != "debug" && cell.Optimization != "size" && cell.Optimization != "speed" {
			return fmt.Errorf("matrix replay cell %q has unsupported optimization %q", cell.ID, cell.Optimization)
		}
		if cell.Architecture != "x64" && cell.Architecture != "x86" {
			return fmt.Errorf("matrix replay cell %q has unsupported architecture %q", cell.ID, cell.Architecture)
		}
		expectedID := strings.Join([]string{cell.Compiler, cell.Optimization, cell.Architecture}, "-")
		if cell.ID != expectedID || seen[cell.ID] {
			return fmt.Errorf("matrix replay cell id %q is invalid or duplicated; expected %q", cell.ID, expectedID)
		}
		seen[cell.ID] = true
		if cell.Artifact == "" {
			continue
		}
		if cell.ArtifactFingerprint == nil || cell.ArtifactFingerprint.Size < 0 || len(cell.ArtifactFingerprint.SHA256) != 64 {
			return fmt.Errorf("matrix replay cell %q has incomplete artifact fingerprint", cell.ID)
		}
		if _, err := hex.DecodeString(cell.ArtifactFingerprint.SHA256); err != nil {
			return fmt.Errorf("matrix replay cell %q has invalid artifact SHA-256", cell.ID)
		}
	}
	return nil
}

func resolveReplayArtifact(reportPath, id string) (string, error) {
	candidate := filepath.Join(filepath.Dir(reportPath), "objects", id+".o")
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		return candidate, nil
	}
	return "", fmt.Errorf("matrix artifact %s is not present beside %s", id, reportPath)
}
