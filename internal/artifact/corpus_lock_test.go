package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type corpusLock struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Repositories  []struct {
		Root    string `json:"root"`
		Objects []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"objects"`
	} `json:"repositories"`
}

func TestCorpusLockHashesAvailableObjects(t *testing.T) {
	root := filepath.Join("..", "..")
	body, err := os.ReadFile(filepath.Join(root, "testdata", "corpus-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock corpusLock
	if err := json.Unmarshal(body, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Schema != "bofbench.corpus-lock" || lock.SchemaVersion != 1 {
		t.Fatalf("unexpected corpus lock contract: %s v%d", lock.Schema, lock.SchemaVersion)
	}
	checked := 0
	for _, repository := range lock.Repositories {
		for _, object := range repository.Objects {
			body, err := os.ReadFile(filepath.Join(root, repository.Root, object.Path))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			if actual := hex.EncodeToString(digest[:]); actual != object.SHA256 {
				t.Errorf("%s: sha256=%s, want %s", object.Path, actual, object.SHA256)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Log("corpus objects are not checked out; lock syntax was still validated")
	}
}
