package arsenal

import (
	"archive/zip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
	meta, err := FetchWithOptions(FetchOptions{Source: srv.URL + "/payload.x64.o", Name: "raw-demo", Type: "raw", Adapter: "generic"})
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

func makeZip(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("root/hello/hello.x64.o")
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("object")); err != nil {
		return err
	}
	return zw.Close()
}
