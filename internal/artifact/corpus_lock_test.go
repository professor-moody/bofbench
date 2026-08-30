package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type corpusLock struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Repositories  []struct {
		Name       string `json:"name"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Root       string `json:"root"`
		Objects    []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"objects"`
	} `json:"repositories"`
}

type analyzerCorpus struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	CorpusID      string    `json:"corpus_id"`
	State         string    `json:"state"`
	FrozenAt      time.Time `json:"frozen_at"`
	Provenance    struct {
		Name             string `json:"name"`
		Repository       string `json:"repository"`
		Commit           string `json:"commit"`
		Root             string `json:"root"`
		ObjectLock       string `json:"object_lock"`
		ObjectLockSHA256 string `json:"object_lock_sha256"`
	} `json:"provenance"`
	ReviewPolicy struct {
		Basis          []string `json:"basis"`
		Comparison     string   `json:"comparison"`
		SupportClasses []string `json:"support_classes"`
		LabelFields    []string `json:"label_fields"`
	} `json:"review_policy"`
	Limitations []string `json:"limitations"`
	Cases       []struct {
		ID              string            `json:"id"`
		Objects         map[string]string `json:"objects"`
		ExpectedSupport map[string]string `json:"expected_support"`
		Labels          struct {
			Capabilities                  []string `json:"capabilities"`
			BehaviorChains                []string `json:"behavior_chains"`
			InterproceduralBehaviorChains []string `json:"interprocedural_behavior_chains"`
		} `json:"labels"`
	} `json:"cases"`
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

func TestAnalyzerCorpusFreezesReviewedLabelsBeforeMeasurement(t *testing.T) {
	root := filepath.Join("..", "..")
	lockPath := filepath.Join(root, "testdata", "corpus-lock.json")
	lockBody, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock corpusLock
	if err := json.Unmarshal(lockBody, &lock); err != nil {
		t.Fatal(err)
	}
	if len(lock.Repositories) != 1 {
		t.Fatalf("corpus lock has %d repositories, want 1", len(lock.Repositories))
	}

	corpusBody, err := os.ReadFile(filepath.Join(root, "testdata", "analyzer-corpus-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus analyzerCorpus
	if err := json.Unmarshal(corpusBody, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "bofbench.analyzer-evaluation-corpus" || corpus.SchemaVersion != 1 || corpus.CorpusID == "" || corpus.State != "labels_frozen" || corpus.FrozenAt.IsZero() {
		t.Fatalf("incomplete analyzer corpus identity: %#v", corpus)
	}
	locked := lock.Repositories[0]
	if corpus.Provenance.Name != locked.Name || corpus.Provenance.Repository != locked.Repository || corpus.Provenance.Commit != locked.Commit || corpus.Provenance.Root != locked.Root || corpus.Provenance.ObjectLock != "testdata/corpus-lock.json" {
		t.Fatalf("corpus provenance does not match its object lock: corpus=%#v lock=%#v", corpus.Provenance, locked)
	}
	lockDigest := sha256.Sum256(lockBody)
	if actual := hex.EncodeToString(lockDigest[:]); corpus.Provenance.ObjectLockSHA256 != actual {
		t.Fatalf("object lock digest=%s, corpus records %s", actual, corpus.Provenance.ObjectLockSHA256)
	}
	if len(corpus.ReviewPolicy.Basis) == 0 || corpus.ReviewPolicy.Comparison == "" || len(corpus.ReviewPolicy.LabelFields) != 3 || len(corpus.Limitations) < 4 {
		t.Fatal("corpus omits its review method or declared limitations")
	}

	allowedSupport := map[string]bool{}
	for _, class := range corpus.ReviewPolicy.SupportClasses {
		allowedSupport[class] = true
	}
	lockedObjects := map[string]bool{}
	for _, object := range locked.Objects {
		if object.Path == "" || len(object.SHA256) != 64 || lockedObjects[object.Path] {
			t.Fatalf("invalid or duplicate locked object: %#v", object)
		}
		lockedObjects[object.Path] = true
	}
	seenCases := map[string]bool{}
	selectedObjects := map[string]bool{}
	for _, test := range corpus.Cases {
		if test.ID == "" || seenCases[test.ID] {
			t.Fatalf("empty or duplicate corpus case %q", test.ID)
		}
		seenCases[test.ID] = true
		for _, arch := range []string{"x64", "x86"} {
			object := test.Objects[arch]
			if len(test.Objects) != 2 || !strings.HasSuffix(object, "."+arch+".o") || !lockedObjects[object] || selectedObjects[object] {
				t.Fatalf("case %s has invalid %s object %q", test.ID, arch, object)
			}
			selectedObjects[object] = true
			if len(test.ExpectedSupport) != 2 || !allowedSupport[test.ExpectedSupport[arch]] {
				t.Fatalf("case %s has invalid %s support class %q", test.ID, arch, test.ExpectedSupport[arch])
			}
		}
		for label, values := range map[string][]string{
			"capabilities":                    test.Labels.Capabilities,
			"behavior_chains":                 test.Labels.BehaviorChains,
			"interprocedural_behavior_chains": test.Labels.InterproceduralBehaviorChains,
		} {
			if !slices.IsSorted(values) {
				t.Fatalf("case %s label %s is not sorted: %v", test.ID, label, values)
			}
			for index, value := range values {
				if value == "" || (index > 0 && values[index-1] == value) {
					t.Fatalf("case %s label %s has an empty or duplicate value: %v", test.ID, label, values)
				}
			}
		}
	}
	if len(corpus.Cases) != 16 || len(selectedObjects) != 32 || len(selectedObjects) != len(lockedObjects) {
		t.Fatalf("corpus coverage cases=%d selected=%d locked=%d, want 16/32/32", len(corpus.Cases), len(selectedObjects), len(lockedObjects))
	}
}
