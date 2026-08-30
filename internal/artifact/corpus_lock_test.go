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
		Name          string `json:"name"`
		Repository    string `json:"repository"`
		Commit        string `json:"commit"`
		Root          string `json:"root"`
		ReviewSources []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"review_sources"`
		Objects []struct {
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

type analyzerCorpusV2 struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	CorpusID      string    `json:"corpus_id"`
	State         string    `json:"state"`
	FrozenAt      time.Time `json:"frozen_at"`
	Extends       struct {
		Corpus           string `json:"corpus"`
		CorpusSHA256     string `json:"corpus_sha256"`
		ObjectLock       string `json:"object_lock"`
		ObjectLockSHA256 string `json:"object_lock_sha256"`
	} `json:"extends"`
	Provenance struct {
		ObjectLock       string `json:"object_lock"`
		ObjectLockSHA256 string `json:"object_lock_sha256"`
		Sources          []struct {
			Name       string `json:"name"`
			Repository string `json:"repository"`
			Commit     string `json:"commit"`
			Root       string `json:"root"`
		} `json:"sources"`
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
		Source          string            `json:"source"`
		ReviewNotes     string            `json:"review_notes"`
		Objects         map[string]string `json:"objects"`
		ExpectedSupport map[string]string `json:"expected_support"`
		Labels          struct {
			Capabilities                  []string `json:"capabilities"`
			BehaviorChains                []string `json:"behavior_chains"`
			InterproceduralBehaviorChains []string `json:"interprocedural_behavior_chains"`
		} `json:"labels"`
	} `json:"cases"`
}

type reviewedLabelSet struct {
	Capabilities                  []string `json:"capabilities"`
	BehaviorChains                []string `json:"behavior_chains"`
	InterproceduralBehaviorChains []string `json:"interprocedural_behavior_chains"`
}

type analyzerCorpusV3 struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	CorpusID      string    `json:"corpus_id"`
	State         string    `json:"state"`
	FrozenAt      time.Time `json:"frozen_at"`
	Extends       struct {
		Corpus           string `json:"corpus"`
		CorpusSHA256     string `json:"corpus_sha256"`
		ObjectLock       string `json:"object_lock"`
		ObjectLockSHA256 string `json:"object_lock_sha256"`
	} `json:"extends"`
	Corrections []struct {
		Case   string `json:"case"`
		Reason string `json:"reason"`
		Audit  struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Status string `json:"status"`
		} `json:"audit"`
		From reviewedLabelSet `json:"from"`
		To   reviewedLabelSet `json:"to"`
	} `json:"corrections"`
	Provenance struct {
		ObjectLock       string `json:"object_lock"`
		ObjectLockSHA256 string `json:"object_lock_sha256"`
		Sources          []struct {
			Name       string `json:"name"`
			Repository string `json:"repository"`
			Commit     string `json:"commit"`
			Root       string `json:"root"`
		} `json:"sources"`
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
		Source          string            `json:"source"`
		ReviewNotes     string            `json:"review_notes"`
		Architectures   []string          `json:"architectures"`
		Objects         map[string]string `json:"objects"`
		ExpectedSupport map[string]string `json:"expected_support"`
		Labels          reviewedLabelSet  `json:"labels"`
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

func TestAnalyzerCorpusV2ExtendsFrozenBaseWithMissingClasses(t *testing.T) {
	root := filepath.Join("..", "..")
	corpusPath := filepath.Join(root, "testdata", "analyzer-corpus-v2.json")
	corpusBody, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus analyzerCorpusV2
	if err := json.Unmarshal(corpusBody, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "bofbench.analyzer-evaluation-corpus" || corpus.SchemaVersion != 2 || corpus.CorpusID == "" || corpus.State != "labels_frozen" || corpus.FrozenAt.IsZero() {
		t.Fatalf("incomplete analyzer corpus v2 identity: %#v", corpus)
	}
	if len(corpus.ReviewPolicy.Basis) == 0 || corpus.ReviewPolicy.Comparison == "" || len(corpus.ReviewPolicy.LabelFields) != 3 || len(corpus.Limitations) < 4 {
		t.Fatal("corpus v2 omits its review method or declared limitations")
	}

	baseCorpusBody, err := os.ReadFile(filepath.Join(root, corpus.Extends.Corpus))
	if err != nil {
		t.Fatal(err)
	}
	baseCorpusDigest := sha256.Sum256(baseCorpusBody)
	if actual := hex.EncodeToString(baseCorpusDigest[:]); actual != corpus.Extends.CorpusSHA256 {
		t.Fatalf("base corpus digest=%s, v2 records %s", actual, corpus.Extends.CorpusSHA256)
	}
	var base analyzerCorpus
	if err := json.Unmarshal(baseCorpusBody, &base); err != nil {
		t.Fatal(err)
	}
	baseLockBody, err := os.ReadFile(filepath.Join(root, corpus.Extends.ObjectLock))
	if err != nil {
		t.Fatal(err)
	}
	baseLockDigest := sha256.Sum256(baseLockBody)
	if actual := hex.EncodeToString(baseLockDigest[:]); actual != corpus.Extends.ObjectLockSHA256 {
		t.Fatalf("base object-lock digest=%s, v2 records %s", actual, corpus.Extends.ObjectLockSHA256)
	}

	extensionLockBody, err := os.ReadFile(filepath.Join(root, corpus.Provenance.ObjectLock))
	if err != nil {
		t.Fatal(err)
	}
	extensionLockDigest := sha256.Sum256(extensionLockBody)
	if actual := hex.EncodeToString(extensionLockDigest[:]); actual != corpus.Provenance.ObjectLockSHA256 {
		t.Fatalf("extension object-lock digest=%s, v2 records %s", actual, corpus.Provenance.ObjectLockSHA256)
	}
	var extensionLock corpusLock
	if err := json.Unmarshal(extensionLockBody, &extensionLock); err != nil {
		t.Fatal(err)
	}
	if extensionLock.Schema != "bofbench.corpus-lock" || extensionLock.SchemaVersion != 1 || len(extensionLock.Repositories) != 1 || len(corpus.Provenance.Sources) != 1 {
		t.Fatalf("unexpected v2 extension provenance: lock=%#v sources=%#v", extensionLock, corpus.Provenance.Sources)
	}
	locked := extensionLock.Repositories[0]
	source := corpus.Provenance.Sources[0]
	if source.Name != locked.Name || source.Repository != locked.Repository || source.Commit != locked.Commit || source.Root != locked.Root {
		t.Fatalf("v2 source does not match extension lock: source=%#v lock=%#v", source, locked)
	}
	if len(locked.ReviewSources) != 2 || len(locked.Objects) != 4 {
		t.Fatalf("v2 extension coverage sources=%d objects=%d, want 2/4", len(locked.ReviewSources), len(locked.Objects))
	}
	for _, reviewSource := range locked.ReviewSources {
		body, err := os.ReadFile(filepath.Join(root, locked.Root, reviewSource.Path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if actual := hex.EncodeToString(digest[:]); actual != reviewSource.SHA256 {
			t.Errorf("%s: sha256=%s, want %s", reviewSource.Path, actual, reviewSource.SHA256)
		}
	}

	allowedSupport := map[string]bool{}
	for _, class := range corpus.ReviewPolicy.SupportClasses {
		allowedSupport[class] = true
	}
	lockedObjects := map[string]bool{}
	for _, object := range locked.Objects {
		if object.Path == "" || len(object.SHA256) != 64 || lockedObjects[object.Path] {
			t.Fatalf("invalid or duplicate v2 object: %#v", object)
		}
		lockedObjects[object.Path] = true
	}
	seenCases := map[string]bool{}
	selectedObjects := map[string]bool{}
	hasBlockedCase := false
	hasInterproceduralPositive := false
	for _, test := range corpus.Cases {
		if test.ID == "" || seenCases[test.ID] || test.Source != locked.Name || test.ReviewNotes == "" {
			t.Fatalf("invalid v2 corpus case: %#v", test)
		}
		seenCases[test.ID] = true
		for _, arch := range []string{"x64", "x86"} {
			object := test.Objects[arch]
			if len(test.Objects) != 2 || !strings.HasSuffix(object, "."+arch+".o") || !lockedObjects[object] || selectedObjects[object] {
				t.Fatalf("case %s has invalid %s object %q", test.ID, arch, object)
			}
			selectedObjects[object] = true
			support := test.ExpectedSupport[arch]
			if len(test.ExpectedSupport) != 2 || !allowedSupport[support] {
				t.Fatalf("case %s has invalid %s support class %q", test.ID, arch, support)
			}
			if support != "compatible" && support != "compatible_runtime_lookup" {
				hasBlockedCase = true
			}
		}
		if len(test.Labels.InterproceduralBehaviorChains) > 0 {
			hasInterproceduralPositive = true
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
	if len(base.Cases)+len(corpus.Cases) != 18 || len(corpus.Cases) != 2 || len(selectedObjects) != 4 || len(selectedObjects) != len(lockedObjects) {
		t.Fatalf("combined corpus coverage base=%d extension=%d selected=%d locked=%d, want 16/2/4/4", len(base.Cases), len(corpus.Cases), len(selectedObjects), len(lockedObjects))
	}
	if !hasBlockedCase || !hasInterproceduralPositive {
		t.Fatalf("v2 must add both missing classes: blocked=%t interprocedural=%t", hasBlockedCase, hasInterproceduralPositive)
	}
}

func TestAnalyzerCorpusV3AppliesOnlyAuditedCorrectionAndAddsThirdSource(t *testing.T) {
	root := filepath.Join("..", "..")
	corpusBody, err := os.ReadFile(filepath.Join(root, "testdata", "analyzer-corpus-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus analyzerCorpusV3
	if err := json.Unmarshal(corpusBody, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "bofbench.analyzer-evaluation-corpus" || corpus.SchemaVersion != 3 || corpus.CorpusID == "" || corpus.State != "labels_frozen" || corpus.FrozenAt.IsZero() {
		t.Fatalf("incomplete analyzer corpus v3 identity: %#v", corpus)
	}
	if len(corpus.ReviewPolicy.Basis) == 0 || corpus.ReviewPolicy.Comparison == "" || len(corpus.ReviewPolicy.LabelFields) != 3 || len(corpus.Limitations) < 5 {
		t.Fatal("corpus v3 omits its review method or declared limitations")
	}

	baseBody, err := os.ReadFile(filepath.Join(root, corpus.Extends.Corpus))
	if err != nil {
		t.Fatal(err)
	}
	baseDigest := sha256.Sum256(baseBody)
	if actual := hex.EncodeToString(baseDigest[:]); actual != corpus.Extends.CorpusSHA256 || actual != "18b3de78256e8c842df5b30a2e178593384752dc69d4e2b51dde4079393dc19e" {
		t.Fatalf("v2 corpus changed or v3 binding is stale: actual=%s bound=%s", actual, corpus.Extends.CorpusSHA256)
	}
	baseLockBody, err := os.ReadFile(filepath.Join(root, corpus.Extends.ObjectLock))
	if err != nil {
		t.Fatal(err)
	}
	baseLockDigest := sha256.Sum256(baseLockBody)
	if actual := hex.EncodeToString(baseLockDigest[:]); actual != corpus.Extends.ObjectLockSHA256 || actual != "0d761da8ffc65af1d3f085e6d648e9fd1e92f43728fa2951a525359af2cc4d9b" {
		t.Fatalf("v2 object lock changed or v3 binding is stale: actual=%s bound=%s", actual, corpus.Extends.ObjectLockSHA256)
	}

	if len(corpus.Corrections) != 1 {
		t.Fatalf("v3 corrections=%d, want exactly 1 audited correction", len(corpus.Corrections))
	}
	correction := corpus.Corrections[0]
	if correction.Case != "sc_enum" || correction.Reason == "" || correction.Audit.Status != "confirmed_frozen_label_omission" {
		t.Fatalf("unexpected v3 correction: %#v", correction)
	}
	if !slices.Equal(correction.From.Capabilities, []string{"service_inventory"}) || len(correction.From.BehaviorChains) != 0 || len(correction.From.InterproceduralBehaviorChains) != 0 {
		t.Fatalf("v3 correction does not reproduce frozen sc_enum labels: %#v", correction.From)
	}
	if !slices.Equal(correction.To.Capabilities, []string{"service_inventory"}) || !slices.Equal(correction.To.BehaviorChains, []string{"remote_service_inventory"}) || !slices.Equal(correction.To.InterproceduralBehaviorChains, []string{"remote_service_inventory"}) {
		t.Fatalf("unexpected corrected sc_enum labels: %#v", correction.To)
	}
	auditBody, err := os.ReadFile(filepath.Join(root, correction.Audit.Path))
	if err != nil {
		t.Fatal(err)
	}
	auditDigest := sha256.Sum256(auditBody)
	if actual := hex.EncodeToString(auditDigest[:]); actual != correction.Audit.SHA256 {
		t.Fatalf("correction audit digest=%s, v3 records %s", actual, correction.Audit.SHA256)
	}
	var audit struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Corpus        struct {
			Path          string `json:"path"`
			SHA256        string `json:"sha256"`
			InheritedCase string `json:"inherited_case"`
		} `json:"corpus"`
	}
	if err := json.Unmarshal(auditBody, &audit); err != nil {
		t.Fatal(err)
	}
	if audit.Schema != "bofbench.analyzer-corpus-label-audit" || audit.SchemaVersion != 1 || audit.Status != correction.Audit.Status || audit.Corpus.Path != corpus.Extends.Corpus || audit.Corpus.SHA256 != corpus.Extends.CorpusSHA256 || audit.Corpus.InheritedCase != correction.Case {
		t.Fatalf("audit does not authorize the v3 correction: %#v", audit)
	}

	lockBody, err := os.ReadFile(filepath.Join(root, corpus.Provenance.ObjectLock))
	if err != nil {
		t.Fatal(err)
	}
	lockDigest := sha256.Sum256(lockBody)
	if actual := hex.EncodeToString(lockDigest[:]); actual != corpus.Provenance.ObjectLockSHA256 {
		t.Fatalf("v3 object-lock digest=%s, corpus records %s", actual, corpus.Provenance.ObjectLockSHA256)
	}
	var lock corpusLock
	if err := json.Unmarshal(lockBody, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Schema != "bofbench.corpus-lock" || lock.SchemaVersion != 1 || len(lock.Repositories) != 1 || len(corpus.Provenance.Sources) != 1 {
		t.Fatalf("unexpected v3 extension provenance: lock=%#v sources=%#v", lock, corpus.Provenance.Sources)
	}
	locked := lock.Repositories[0]
	source := corpus.Provenance.Sources[0]
	if source.Name != locked.Name || source.Repository != locked.Repository || source.Commit != locked.Commit || source.Root != locked.Root || source.Commit != "9413caf85fd83272f5866ef42f9e7ed8db9987d6" {
		t.Fatalf("v3 source does not match pinned Adaptix lock: source=%#v lock=%#v", source, locked)
	}
	if len(locked.ReviewSources) != 13 || len(locked.Objects) != 3 {
		t.Fatalf("v3 extension coverage sources=%d objects=%d, want 13/3", len(locked.ReviewSources), len(locked.Objects))
	}
	for _, reviewSource := range locked.ReviewSources {
		body, err := os.ReadFile(filepath.Join(root, locked.Root, reviewSource.Path))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if actual := hex.EncodeToString(digest[:]); actual != reviewSource.SHA256 {
			t.Errorf("%s: sha256=%s, want %s", reviewSource.Path, actual, reviewSource.SHA256)
		}
	}

	allowedSupport := map[string]bool{}
	for _, class := range corpus.ReviewPolicy.SupportClasses {
		allowedSupport[class] = true
	}
	lockedObjects := map[string]bool{}
	for _, object := range locked.Objects {
		if object.Path == "" || len(object.SHA256) != 64 || lockedObjects[object.Path] {
			t.Fatalf("invalid or duplicate v3 object: %#v", object)
		}
		lockedObjects[object.Path] = true
	}
	selectedObjects := map[string]bool{}
	hasPairedBlockedFamily := false
	hasUnpairedInterproceduralFamily := false
	for _, test := range corpus.Cases {
		if test.ID == "" || test.Source != locked.Name || test.ReviewNotes == "" || len(test.Architectures) == 0 {
			t.Fatalf("invalid v3 corpus case: %#v", test)
		}
		if len(test.Objects) != len(test.Architectures) || len(test.ExpectedSupport) != len(test.Architectures) {
			t.Fatalf("case %s architecture maps do not match its declaration", test.ID)
		}
		blocked := true
		for _, arch := range test.Architectures {
			object := test.Objects[arch]
			if !lockedObjects[object] || selectedObjects[object] || !allowedSupport[test.ExpectedSupport[arch]] {
				t.Fatalf("case %s has invalid %s object or support", test.ID, arch)
			}
			selectedObjects[object] = true
			blocked = blocked && test.ExpectedSupport[arch] != "compatible" && test.ExpectedSupport[arch] != "compatible_runtime_lookup"
		}
		if blocked && slices.Equal(test.Architectures, []string{"x64", "x86"}) {
			hasPairedBlockedFamily = true
		}
		if slices.Equal(test.Architectures, []string{"x64"}) && len(test.Labels.InterproceduralBehaviorChains) > 0 {
			hasUnpairedInterproceduralFamily = true
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
	if len(corpus.Cases) != 2 || len(selectedObjects) != 3 || len(selectedObjects) != len(lockedObjects) || !hasPairedBlockedFamily || !hasUnpairedInterproceduralFamily {
		t.Fatalf("v3 must add 2 families/3 objects with paired blocked and explicit x64-only interprocedural coverage: cases=%d selected=%d locked=%d blocked=%t interprocedural=%t", len(corpus.Cases), len(selectedObjects), len(lockedObjects), hasPairedBlockedFamily, hasUnpairedInterproceduralFamily)
	}
}
