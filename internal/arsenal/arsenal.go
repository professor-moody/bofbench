package arsenal

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const TrustedSecURL = "https://github.com/trustedsec/CS-Situational-Awareness-BOF.git"
const TrustedSecPath = "arsenal/trustedsec-sa"
const TrustedSecHead = "ee9459cc4f42c6b025797bad22ffe8d9f1cf6487"

type Entry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	X64  string `json:"x64,omitempty"`
	X86  string `json:"x86,omitempty"`
}

type FetchOptions struct {
	Source  string
	Name    string
	Ref     string
	Type    string
	Adapter string
}

type SourceMetadata struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Ref       string `json:"ref,omitempty"`
	Type      string `json:"type"`
	Adapter   string `json:"adapter"`
	FetchedAt string `json:"fetched_at"`
	Path      string `json:"path"`
}

func Fetch(source string) (string, error) {
	meta, err := FetchWithOptions(FetchOptions{Source: source, Type: "auto", Adapter: "auto"})
	if err != nil {
		return "", err
	}
	return meta.Path, nil
}

func FetchWithOptions(opts FetchOptions) (SourceMetadata, error) {
	if opts.Source == "" {
		return SourceMetadata{}, fmt.Errorf("fetch source is required")
	}
	if opts.Type == "" {
		opts.Type = "auto"
	}
	if opts.Adapter == "" {
		opts.Adapter = "auto"
	}
	opts = expandAlias(opts)
	if opts.Name == "" {
		opts.Name = inferName(opts.Source)
	}
	if opts.Adapter == "auto" {
		opts.Adapter = inferAdapter(opts.Name, opts.Source)
	}
	kind := opts.Type
	if kind == "auto" {
		kind = inferType(opts.Source)
	}
	path := filepath.Join("arsenal", safeName(opts.Name))
	if err := os.MkdirAll("arsenal", 0o755); err != nil {
		return SourceMetadata{}, err
	}
	switch kind {
	case "git":
		if err := fetchGit(path, opts.Source, opts.Ref); err != nil {
			return SourceMetadata{}, err
		}
	case "zip":
		if err := fetchZip(path, opts.Source); err != nil {
			return SourceMetadata{}, err
		}
	case "raw":
		if err := fetchRaw(path, opts.Source); err != nil {
			return SourceMetadata{}, err
		}
	default:
		return SourceMetadata{}, fmt.Errorf("unsupported fetch type %q", kind)
	}
	meta := SourceMetadata{
		Name:      opts.Name,
		URL:       opts.Source,
		Ref:       opts.Ref,
		Type:      kind,
		Adapter:   opts.Adapter,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Path:      path,
	}
	if err := writeSource(path, meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func List(root string) ([]Entry, error) {
	var entries []Entry
	saRoot := filepath.Join(root, "SA")
	if info, err := os.Stat(saRoot); err == nil && info.IsDir() {
		root = saRoot
	}
	children, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if !child.IsDir() {
			continue
		}
		dir := filepath.Join(root, child.Name())
		entry := Entry{Name: child.Name(), Path: dir}
		x64 := filepath.Join(dir, child.Name()+".x64.o")
		x86 := filepath.Join(dir, child.Name()+".x86.o")
		if _, err := os.Stat(x64); err == nil {
			entry.X64 = x64
		}
		if _, err := os.Stat(x86); err == nil {
			entry.X86 = x86
		}
		if entry.X64 != "" || entry.X86 != "" || hasSource(dir) {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		generic, err := listGenericObjects(root)
		if err != nil {
			return nil, err
		}
		entries = append(entries, generic...)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func Select(entries []Entry, selectList string) []Entry {
	if strings.TrimSpace(selectList) == "" {
		return entries
	}
	want := map[string]bool{}
	for _, part := range strings.Split(selectList, ",") {
		want[strings.TrimSpace(part)] = true
	}
	var out []Entry
	for _, entry := range entries {
		if want[entry.Name] {
			out = append(out, entry)
		}
	}
	return out
}

func expandAlias(opts FetchOptions) FetchOptions {
	if opts.Source == "trustedsec-sa" {
		opts.Source = TrustedSecURL
		if opts.Name == "" {
			opts.Name = "trustedsec-sa"
		}
		if opts.Ref == "" {
			opts.Ref = TrustedSecHead
		}
		if opts.Adapter == "" || opts.Adapter == "auto" {
			opts.Adapter = "trustedsec-sa"
		}
		if opts.Type == "" || opts.Type == "auto" {
			opts.Type = "git"
		}
	}
	return opts
}

func fetchGit(path, source, ref string) error {
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		cmd := exec.Command("git", "fetch", "--depth", "1", "origin", refOrHead(ref))
		cmd.Dir = path
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git fetch failed: %w: %s", err, out)
		}
		cmd = exec.Command("git", "checkout", refOrHead(ref))
		cmd.Dir = path
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git checkout failed: %w: %s", err, out)
		}
		return nil
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	cmd := exec.Command("git", "clone", "--depth", "1", source, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, out)
	}
	if ref != "" {
		cmd = exec.Command("git", "checkout", ref)
		cmd.Dir = path
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git checkout failed: %w: %s", err, out)
		}
	}
	return nil
}

func fetchZip(path, source string) error {
	tmp, err := download(source)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	zr, err := zip.OpenReader(tmp)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		clean := filepath.Clean(f.Name)
		parts := strings.Split(clean, string(filepath.Separator))
		if len(parts) > 1 {
			clean = filepath.Join(parts[1:]...)
		}
		if clean == "." || clean == "" {
			continue
		}
		dst := filepath.Join(path, clean)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		in, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(dst)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func fetchRaw(path, source string) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	tmp, err := download(source)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	name := filepath.Base(source)
	if name == "." || name == "/" || name == "" {
		name = "artifact.bin"
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, name), b, 0o644)
}

func download(source string) (string, error) {
	client := http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(source)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}
	f, err := os.CreateTemp("", "bofbench-download-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func writeSource(path string, meta SourceMetadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(path, "source.json"), b, 0o644)
}

func listGenericObjects(root string) ([]Entry, error) {
	var entries []Entry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		lower := strings.ToLower(path)
		if !(strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".obj")) {
			return nil
		}
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		entry := Entry{Name: name, Path: filepath.Dir(path)}
		if strings.Contains(lower, ".x86.") {
			entry.X86 = path
		} else {
			entry.X64 = path
		}
		entries = append(entries, entry)
		return nil
	})
	return entries, err
}

func hasSource(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".c") {
			return true
		}
	}
	return false
}

func inferType(source string) string {
	if strings.HasSuffix(source, ".git") || strings.Contains(source, "github.com") && !strings.Contains(source, "/archive/") {
		return "git"
	}
	if strings.HasSuffix(strings.ToLower(source), ".zip") {
		return "zip"
	}
	return "raw"
}

func inferAdapter(name, source string) string {
	if name == "trustedsec-sa" || strings.Contains(source, "CS-Situational-Awareness-BOF") {
		return "trustedsec-sa"
	}
	return "generic"
}

func inferName(source string) string {
	u, err := url.Parse(source)
	if err == nil && u.Host != "" {
		base := filepath.Base(strings.TrimSuffix(u.Path, "/"))
		base = strings.TrimSuffix(base, ".git")
		base = strings.TrimSuffix(base, ".zip")
		if base != "" && base != "." {
			return safeName(base)
		}
		return safeName(u.Host)
	}
	return safeName(source)
}

func safeName(s string) string {
	s = strings.ToLower(filepath.Base(strings.TrimSpace(s)))
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, ".zip")
	s = strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(s)
	if s == "" || s == "/" || s == "." {
		return "arsenal"
	}
	return s
}

func refOrHead(ref string) string {
	if ref == "" {
		return "HEAD"
	}
	return ref
}
