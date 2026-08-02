package arsenal

import (
	"archive/zip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/bofbench/internal/evidence"
)

func TestFetchRawURLWritesSourceMetadata(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("object"))
	}))
	defer srv.Close()
	meta, err := FetchWithOptions(FetchOptions{Source: srv.URL + "/payload.x64.o?token=ignored", Name: "raw-demo", Type: "raw", Adapter: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Type != "raw" || meta.Adapter != "generic" {
		t.Fatalf("metadata = %+v", meta)
	}
	if _, err := os.Stat(filepath.Join("arsenal", "raw-demo", "payload.x64.o")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("arsenal", "raw-demo", "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got SourceMetadata
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "raw-demo" {
		t.Fatalf("source metadata = %+v", got)
	}
	if got.Schema != evidence.SchemaSource || got.SchemaVersion != evidence.ContractVersion || got.RunID == "" || got.Tool.Name != "bofbench" || got.Content == nil || got.Content.Files != 1 || got.Content.SHA256 == "" {
		t.Fatalf("source evidence header = %+v", got.Header)
	}
}

func TestFetchZipURL(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(tmp, "payloads.zip")
	if err := makeZip(zipPath); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(tmp)))
	defer srv.Close()
	_, err := FetchWithOptions(FetchOptions{Source: srv.URL + "/payloads.zip", Name: "zip-demo", Type: "zip", Adapter: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("arsenal", "zip-demo", "hello", "hello.x64.o")); err != nil {
		t.Fatal(err)
	}
}

func TestFetchZipRejectsUnsafeEntriesAndPreservesExisting(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipFixture
	}{
		{name: "traversal", entries: []zipFixture{{Name: "root/../../../escaped.txt", Body: "bad"}}},
		{name: "absolute", entries: []zipFixture{{Name: "/root/escaped.txt", Body: "bad"}}},
		{name: "backslash", entries: []zipFixture{{Name: `root\..\escaped.txt`, Body: "bad"}}},
		{name: "drive", entries: []zipFixture{{Name: "C:/escaped.txt", Body: "bad"}}},
		{name: "symlink", entries: []zipFixture{{Name: "root/link", Body: "../escaped.txt", Mode: os.ModeSymlink | 0o777}}},
		{name: "case collision", entries: []zipFixture{{Name: "root/BOF.o", Body: "one"}, {Name: "root/bof.o", Body: "two"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wd, _ := os.Getwd()
			tmp := t.TempDir()
			defer os.Chdir(wd)
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			zipPath := filepath.Join(tmp, "payloads.zip")
			if err := makeZipEntries(zipPath, tc.entries); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join("arsenal", "zip-demo")
			if err := os.MkdirAll(dst, 0o755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dst, "existing.txt")
			if err := os.WriteFile(marker, []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.FileServer(http.Dir(tmp)))
			defer srv.Close()
			_, err := FetchWithOptions(FetchOptions{Source: srv.URL + "/payloads.zip", Name: "zip-demo", Type: "zip", Adapter: "generic"})
			if err == nil {
				t.Fatal("unsafe zip fetch succeeded")
			}
			body, readErr := os.ReadFile(marker)
			if readErr != nil || string(body) != "keep" {
				t.Fatalf("existing arsenal was not preserved: body=%q err=%v", body, readErr)
			}
			if _, statErr := os.Stat(filepath.Join(tmp, "escaped.txt")); !os.IsNotExist(statErr) {
				t.Fatalf("unsafe archive wrote outside destination: %v", statErr)
			}
			leftovers, globErr := filepath.Glob(filepath.Join("arsenal", ".zip-demo-fetch-*"))
			if globErr != nil || len(leftovers) != 0 {
				t.Fatalf("staging directories were not cleaned up: %v %v", leftovers, globErr)
			}
		})
	}
}

func TestDownloadEnforcesStreamingLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()
	path, err := download(srv.URL+"/large.bin", 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("download result path=%q err=%v", path, err)
	}
	if path != "" {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("oversized temporary download remains: %v", statErr)
		}
	}
}

func TestInferTypeUsesURLPath(t *testing.T) {
	if got := inferType("https://example.test/archive.zip?token=value"); got != "zip" {
		t.Fatalf("inferType = %q", got)
	}
}

func TestSafeNameRestrictsWorkspacePath(t *testing.T) {
	if got := safeName("../../ Demo:@Payload "); got != "demo-payload" {
		t.Fatalf("safeName = %q", got)
	}
}

func TestGenericObjectsGroupArchitecturesAndAssociateExtensionMetadata(t *testing.T) {
	root := t.TempDir()
	objectDir := filepath.Join(root, "objects")
	if err := os.MkdirAll(objectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(objectDir, "survey.x64.o"), filepath.Join(objectDir, "survey.x86.o"), filepath.Join(root, "extension.json"), filepath.Join(root, "survey.cna")} {
		if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "survey" || entries[0].X64 == "" || entries[0].X86 == "" {
		t.Fatalf("generic entries = %+v", entries)
	}
	metadata := sourceFiles(root, entries[0].Path)
	joined := strings.Join(metadata, "\n")
	if !strings.Contains(joined, "extension.json") || !strings.Contains(joined, "survey.cna") {
		t.Fatalf("associated metadata = %v", metadata)
	}
}

type zipFixture struct {
	Name string
	Body string
	Mode os.FileMode
}

func makeZip(path string) error {
	return makeZipEntries(path, []zipFixture{{Name: "root/hello/hello.x64.o", Body: "object"}})
}

func makeZipEntries(path string, entries []zipFixture) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.Name, Method: zip.Deflate}
		if entry.Mode != 0 {
			header.SetMode(entry.Mode)
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(entry.Body)); err != nil {
			return err
		}
	}
	return zw.Close()
}
