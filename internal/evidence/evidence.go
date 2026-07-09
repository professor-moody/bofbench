package evidence

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const ContractVersion = 1

const (
	SchemaAnalysis       = "bofbench.analysis"
	SchemaAnalysisDiff   = "bofbench.analysis-diff"
	SchemaArsenalTest    = "bofbench.arsenal-test"
	SchemaBuild          = "bofbench.build"
	SchemaCompilerMatrix = "bofbench.compiler-matrix"
	SchemaDoctor         = "bofbench.doctor"
	SchemaLabSmoke       = "bofbench.lab-smoke"
	SchemaPreflight      = "bofbench.preflight"
	SchemaRun            = "bofbench.run"
	SchemaSource         = "bofbench.arsenal-source"
	SchemaVersionInfo    = "bofbench.version"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = ""
)

type Header struct {
	Schema        string   `json:"schema"`
	SchemaVersion int      `json:"schema_version"`
	RunID         string   `json:"run_id,omitempty"`
	ParentRunID   string   `json:"parent_run_id,omitempty"`
	Tool          ToolInfo `json:"tool"`
	Host          HostInfo `json:"host"`
}

type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time,omitempty"`
}

type HostInfo struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
}

type FileFingerprint struct {
	Path   string `json:"path,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type TreeFingerprint struct {
	Files  int    `json:"files"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func New(schema, runID, parentRunID string) Header {
	return Header{
		Schema:        schema,
		SchemaVersion: ContractVersion,
		RunID:         runID,
		ParentRunID:   parentRunID,
		Tool:          CurrentTool(),
		Host:          CurrentHost(),
	}
}

func CurrentTool() ToolInfo {
	return ToolInfo{Name: "bofbench", Version: Version, Commit: Commit, BuildTime: BuildTime}
}

func CurrentHost() HostInfo {
	return HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version()}
}

func FingerprintFile(path string) (FileFingerprint, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileFingerprint{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return FileFingerprint{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileFingerprint{}, err
	}
	return FileFingerprint{Path: path, Size: info.Size(), SHA256: fmt.Sprintf("%x", h.Sum(nil))}, nil
}

func FingerprintTree(root string) (TreeFingerprint, error) {
	h := sha256.New()
	result := TreeFingerprint{}
	err := filepath.WalkDir(root, func(diskPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if diskPath == root {
			return nil
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == ".DS_Store" || strings.HasPrefix(entry.Name(), "._") {
			return nil
		}
		rel, err := filepath.Rel(root, diskPath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "source.json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(diskPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "symlink\x00%s\x00%d\x00%s\x00", rel, len(target), target)
			result.Files++
			result.Bytes += int64(len(target))
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot fingerprint special file %s", diskPath)
		}
		fmt.Fprintf(h, "file\x00%s\x00%d\x00", rel, info.Size())
		f, err := os.Open(diskPath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
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
		return TreeFingerprint{}, err
	}
	result.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
	return result, nil
}
