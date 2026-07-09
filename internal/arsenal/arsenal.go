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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bofbench/internal/evidence"
)

const TrustedSecURL = "https://github.com/trustedsec/CS-Situational-Awareness-BOF.git"
const TrustedSecPath = "arsenal/trustedsec-sa"
const TrustedSecHead = "ee9459cc4f42c6b025797bad22ffe8d9f1cf6487"

const (
	maxDownloadBytes = int64(256 << 20)
	maxArchiveBytes  = uint64(512 << 20)
	maxArchiveFiles  = 100000
)

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
	evidence.Header
	Content   *evidence.TreeFingerprint `json:"content_fingerprint,omitempty"`
	Name      string                    `json:"name"`
	URL       string                    `json:"url"`
	Ref       string                    `json:"ref,omitempty"`
	Type      string                    `json:"type"`
	Adapter   string                    `json:"adapter"`
	FetchedAt string                    `json:"fetched_at"`
	Path      string                    `json:"path"`
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
	fetchedAt := time.Now().UTC()
	meta := SourceMetadata{
		Header:    evidence.New(evidence.SchemaSource, "fetch-"+safeName(opts.Name)+"-"+fetchedAt.Format("20060102T150405.000000000Z"), ""),
		Name:      opts.Name,
		URL:       opts.Source,
		Ref:       opts.Ref,
		Type:      kind,
		Adapter:   opts.Adapter,
		FetchedAt: fetchedAt.Format(time.RFC3339),
		Path:      path,
	}
	if fingerprint, err := evidence.FingerprintTree(path); err == nil {
		meta.Content = &fingerprint
	} else {
		return meta, fmt.Errorf("fingerprint fetched arsenal: %w", err)
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
	tmp, err := download(source, maxDownloadBytes)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	staged, err := stagingDir(path)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	if err := extractZip(tmp, staged); err != nil {
		return err
	}
	return replaceDir(staged, path)
}

type archiveEntry struct {
	file *zip.File
	name string
}

func extractZip(zipPath, dstRoot string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > maxArchiveFiles {
		return fmt.Errorf("zip contains %d entries; limit is %d", len(zr.File), maxArchiveFiles)
	}
	var entries []archiveEntry
	var total uint64
	for _, f := range zr.File {
		name, err := cleanArchivePath(f.Name)
		if err != nil {
			return err
		}
		mode := f.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("zip entry %q is a symlink", f.Name)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if !mode.IsRegular() {
			return fmt.Errorf("zip entry %q is not a regular file", f.Name)
		}
		if f.UncompressedSize64 > maxArchiveBytes-total {
			return fmt.Errorf("zip expands beyond %d bytes", maxArchiveBytes)
		}
		total += f.UncompressedSize64
		entries = append(entries, archiveEntry{file: f, name: name})
	}
	if len(entries) == 0 {
		return fmt.Errorf("zip contains no regular files")
	}
	prefix := commonArchiveRoot(entries)
	seen := map[string]string{}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.name, prefix)
		if name == "" {
			return fmt.Errorf("zip entry %q has no path after root normalization", entry.file.Name)
		}
		key := strings.ToLower(name)
		if previous, ok := seen[key]; ok {
			return fmt.Errorf("zip entries %q and %q resolve to the same path", previous, entry.file.Name)
		}
		seen[key] = entry.file.Name
		dst, err := archiveDestination(dstRoot, name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		in, err := entry.file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			in.Close()
			return err
		}
		written, copyErr := io.Copy(out, io.LimitReader(in, int64(entry.file.UncompressedSize64)+1))
		closeErr := out.Close()
		inputCloseErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if inputCloseErr != nil {
			return inputCloseErr
		}
		if uint64(written) != entry.file.UncompressedSize64 {
			return fmt.Errorf("zip entry %q size mismatch: expected %d bytes, wrote %d", entry.file.Name, entry.file.UncompressedSize64, written)
		}
	}
	return nil
}

func cleanArchivePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) {
		return "", fmt.Errorf("zip entry has unsafe path %q", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	clean := path.Clean(trimmed)
	if clean == "." || clean == ".." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean != trimmed {
		return "", fmt.Errorf("zip entry has unsafe path %q", name)
	}
	first := strings.SplitN(clean, "/", 2)[0]
	if strings.Contains(first, ":") || filepath.VolumeName(filepath.FromSlash(clean)) != "" {
		return "", fmt.Errorf("zip entry has unsafe path %q", name)
	}
	return clean, nil
}

func commonArchiveRoot(entries []archiveEntry) string {
	var root string
	for _, entry := range entries {
		parts := strings.Split(entry.name, "/")
		if len(parts) < 2 {
			return ""
		}
		if root == "" {
			root = parts[0]
			continue
		}
		if parts[0] != root {
			return ""
		}
	}
	if root == "" {
		return ""
	}
	return root + "/"
}

func archiveDestination(root, name string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	dst := filepath.Join(rootAbs, filepath.FromSlash(name))
	rel, err := filepath.Rel(rootAbs, dst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("zip entry escapes destination: %q", name)
	}
	return dst, nil
}

func fetchRaw(dstPath, source string) error {
	tmp, err := download(source, maxDownloadBytes)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	staged, err := stagingDir(dstPath)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	name := rawFileName(source)
	if err := copyDownloadedFile(tmp, filepath.Join(staged, name)); err != nil {
		return err
	}
	return replaceDir(staged, dstPath)
}

func download(source string, maxBytes int64) (path string, err error) {
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("download source must be an http or https URL")
	}
	if maxBytes <= 0 {
		return "", fmt.Errorf("download size limit must be positive")
	}
	client := http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(source)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download failed: %s", resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return "", fmt.Errorf("download is %d bytes; limit is %d", resp.ContentLength, maxBytes)
	}
	f, err := os.CreateTemp("", "bofbench-download-*")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !keep || err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	written, err := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxBytes {
		return "", fmt.Errorf("download exceeds %d byte limit", maxBytes)
	}
	keep = true
	return f.Name(), nil
}

func stagingDir(dst string) (string, error) {
	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, "."+filepath.Base(dst)+"-fetch-")
}

func replaceDir(staged, dst string) error {
	backup := ""
	if _, err := os.Lstat(dst); err == nil {
		f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+"-previous-")
		if err != nil {
			return err
		}
		backup = f.Name()
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
		if err := os.Rename(dst, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, dst); err != nil {
		if backup != "" {
			_ = os.Rename(backup, dst)
		}
		return err
	}
	if backup != "" {
		return os.RemoveAll(backup)
	}
	return nil
}

func rawFileName(source string) string {
	u, err := url.Parse(source)
	if err != nil {
		return "artifact.bin"
	}
	base := path.Base(u.EscapedPath())
	if decoded, err := url.PathUnescape(base); err == nil {
		base = decoded
	}
	base = filepath.Base(strings.TrimSpace(base))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "artifact.bin"
	}
	var b strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-.")
	if name == "" {
		return "artifact.bin"
	}
	return name
}

func copyDownloadedFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
	parsed, _ := url.Parse(source)
	if strings.HasSuffix(strings.ToLower(parsed.Path), ".zip") {
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
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	s = strings.Join(strings.FieldsFunc(b.String(), func(r rune) bool { return r == '-' }), "-")
	if s == "" {
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
