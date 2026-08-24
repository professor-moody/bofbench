package app

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/professor-moody/bofbench/internal/coff"
	"github.com/professor-moody/bofbench/internal/stage"
)

func TestCLIWorkspaceBuildInspectStage(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "hello")
	runOK(t, tmp, bin, "build", filepath.Join("bofs", "hello"))
	inspect := runOK(t, tmp, bin, "inspect", filepath.Join("dist", "hello.x64.o"))
	if !strings.Contains(inspect, "entry \"go\": yes") {
		t.Fatalf("inspect did not confirm entrypoint:\n%s", inspect)
	}
	runOK(t, tmp, bin, "stage", filepath.Join("dist", "hello.x64.o"), "--target", "cobaltstrike", "--args", "z:hello", "i:3")
	mustExist(t, filepath.Join(tmp, "stage", "hello-cobaltstrike", "hello.cna"))
	mustExist(t, filepath.Join(tmp, "stage", "hello-cobaltstrike.zip"))
}

func TestCLIExportsRepositoryNeutralEDRBundle(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	loader, err := filepath.Abs(filepath.Join("..", "..", "native", "loader", "bofbench-loader.exe"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_LOADER", loader)
	runOK(t, tmp, bin, "new", "edr-export")
	output := runOK(t, tmp, bin, "export", filepath.Join("bofs", "edr-export"), "--for", "edrlab", "--skip-run")
	bundlePath := filepath.Join(tmp, "export", "edr-export-edrlab", "windows-artifact-bundle.json")
	if !strings.Contains(output, bundlePath) && !strings.Contains(output, filepath.ToSlash(filepath.Join("export", "edr-export-edrlab"))) {
		t.Fatalf("export output did not identify bundle: %s", output)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Schema    string `json:"schema_version"`
		Artifacts []struct {
			ID     string `json:"id"`
			SHA256 string `json:"sha256"`
			Kind   string `json:"kind"`
		} `json:"artifacts"`
		Modes []struct {
			LoaderID string   `json:"loader_id"`
			Command  []string `json:"command"`
		} `json:"execution_modes"`
		Effect struct {
			Contains string `json:"contains"`
		} `json:"effect"`
		Cleanup struct {
			Command      []string `json:"command"`
			VerifyAbsent string   `json:"verify_absent"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Schema != "windows.artifact-bundle/v1" || len(bundle.Artifacts) != 3 || len(bundle.Modes) != 1 || bundle.Modes[0].LoaderID != "loader" || bundle.Effect.Contains != "{{run_id}}" {
		t.Fatalf("bundle = %+v", bundle)
	}
	if len(bundle.Cleanup.Command) != 6 || !strings.Contains(bundle.Cleanup.Command[5], `-LiteralPath '{{run_dir}}\bofbench-effect.json'`) || strings.Contains(bundle.Cleanup.Command[5], "$args") || bundle.Cleanup.VerifyAbsent != `{{run_dir}}\bofbench-effect.json` {
		t.Fatalf("cleanup does not bind and verify the exact effect path: %+v", bundle.Cleanup)
	}
	runner, err := os.ReadFile(filepath.Join(tmp, "export", "edr-export-edrlab", "artifacts", "bofbench-edr-runner.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$lines = @(& $Loader", "$loaderExit = $LASTEXITCODE", "for ($i = $lines.Count - 1", "if ($candidate.protocol_event)", "$result = $candidate"} {
		if !strings.Contains(string(runner), want) {
			t.Fatalf("EDR runner does not select the final non-protocol loader result; missing %q", want)
		}
	}
}

func TestCLIOperationCatalogSurface(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	t.Setenv("BOFBENCH_CONFIG_HOME", filepath.Join(tmp, "config"))
	listed := runOK(t, tmp, bin, "operation", "list")
	if !strings.Contains(listed, "builtin/process-triage") {
		t.Fatalf("builtin operation missing:\n%s", listed)
	}
	shown := runOK(t, tmp, bin, "operation", "show", "process-triage")
	for _, want := range []string{"Process Triage", "target_pid", "process-security-inventory"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("operation show missing %q:\n%s", want, shown)
		}
	}
	validated := runOK(t, tmp, bin, "operation", "validate", "builtin/process-triage")
	if !strings.Contains(validated, "OPERATION VALID") || !strings.Contains(validated, "steps      3") {
		t.Fatalf("unexpected operation validation:\n%s", validated)
	}
}

func TestCLIBuildFailurePrintsAndPersistsEvidence(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	project := filepath.Join(tmp, "broken")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("compiler = \"invalid\"\nunknown = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, tmp, bin, "build", project, "--format", "json")
	if err == nil {
		t.Fatal("expected build command failure")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit error = %v", err)
	}
	for _, want := range []string{`"schema": "bofbench.build"`, `"status": "error"`, `"tool": "config"`, `"evidence_path":`, "2 configuration error"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in build failure output:\n%s", want, out)
		}
	}
	matches, globErr := filepath.Glob(filepath.Join(tmp, "runs", "*-build-broken", "build.json"))
	if globErr != nil || len(matches) != 1 {
		t.Fatalf("persisted build evidence = %v err=%v", matches, globErr)
	}
}

func TestCLICompilerMatrixPersistsClassifiedEvidence(t *testing.T) {
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not available")
	}
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	project := filepath.Join(tmp, "matrix-fixture")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	source := "void BeaconPrintf(int, const char *, ...);\nvoid go(char *args, int len) { (void)args; (void)len; BeaconPrintf(0, \"matrix pass\"); }\n"
	if err := os.WriteFile(filepath.Join(project, "matrix.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("name = \"matrix-fixture\"\nexpect = [\"matrix pass\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := runOK(t, tmp, bin, "matrix", project, "--compiler", "mingw", "--optimization", "debug", "--arch", "x64", "--execute", "never", "--verify-reproducible=false", "--format", "json")
	var result struct {
		Report struct {
			Schema  string `json:"schema"`
			Status  string `json:"status"`
			Summary struct {
				Total  int `json:"total"`
				Passed int `json:"passed"`
			} `json:"summary"`
			Cells []struct {
				Classification string `json:"classification"`
			} `json:"cells"`
		} `json:"report"`
		JSONPath string `json:"json_path"`
		MDPath   string `json:"md_path"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Report.Schema != "bofbench.compiler-matrix" || result.Report.Status != "pass" || result.Report.Summary.Total != 1 || result.Report.Summary.Passed != 1 || len(result.Report.Cells) != 1 || result.Report.Cells[0].Classification != "analysis_pass" {
		t.Fatalf("matrix output = %+v", result)
	}
	mustExist(t, filepath.Join(tmp, result.JSONPath))
	mustExist(t, filepath.Join(tmp, result.MDPath))
}

func TestCLIStageVerifyDirectoryZipAndFailure(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	obj := filepath.Join(tmp, "demo.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	runOK(t, tmp, bin, "stage", obj, "--target", "raw")
	directory := filepath.Join("stage", "demo-raw")
	archive := directory + ".zip"
	var verified struct {
		Schema string `json:"schema"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "stage", "verify", directory, "--format", "json")), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.Schema != "bofbench.stage-verification" || verified.Status != "pass_with_warnings" {
		t.Fatalf("directory verification = %+v", verified)
	}
	zipText := runOK(t, tmp, bin, "stage", "verify", archive)
	if !strings.Contains(zipText, "Export Package Verification: PASS") {
		t.Fatalf("unexpected ZIP verification output:\n%s", zipText)
	}
	if err := os.WriteFile(filepath.Join(tmp, directory, "objects", "demo.x64.o"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, tmp, bin, "stage", "verify", directory, "--format", "json")
	if err == nil || !strings.Contains(out, `"status": "fail"`) || !strings.Contains(out, "export package verification failed") {
		t.Fatalf("tampered verification did not fail: err=%v\n%s", err, out)
	}
}

func TestCLINewTemplates(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "pidcheck", "--template", "winapi")
	body, err := os.ReadFile(filepath.Join(tmp, "bofs", "pidcheck", "pidcheck.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "GetCurrentProcessId") {
		t.Fatalf("winapi template missing API call:\n%s", body)
	}

	runOK(t, tmp, bin, "new", "badlink", "--template", "unresolved")
	cfg, err := os.ReadFile(filepath.Join(tmp, "bofs", "badlink", "bofbench.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `expect_exit = "relocation_error"`) {
		t.Fatalf("unresolved template missing expected exit:\n%s", cfg)
	}

	runOK(t, tmp, bin, "new", "echoer", "--template", "args")
	cfg, err = os.ReadFile(filepath.Join(tmp, "bofs", "echoer", "bofbench.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "[profile.alt]") {
		t.Fatalf("args template missing alternate profile:\n%s", cfg)
	}
}

func TestCLIFeaturesAndDeveloperLoop(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	features := runOK(t, tmp, bin, "feature", "list")
	for _, want := range []string{"BOF CAPABILITY MODULES", "Reusable source modules injected into a BOF project.", "add: bofbench feature add bofs/<project> <capability...>", "READ-ONLY DISCOVERY", "STATE-CHANGING LAB ACTIONS", "CLEANUP"} {
		if !strings.Contains(features, want) {
			t.Fatalf("feature list missing operator guidance %q:\n%s", want, features)
		}
	}
	for _, want := range []string{"process", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context"} {
		if !strings.Contains(features, want) {
			t.Fatalf("feature list missing %q:\n%s", want, features)
		}
	}
	packs := runOK(t, tmp, bin, "feature", "pack", "list")
	for _, want := range []string{"host-discovery", "system-discovery", "network-discovery", "deep-discovery", "active-lab", "offensive-lab", "active-cleanup", "features=11", "features=15", "modifies_state"} {
		if !strings.Contains(packs, want) {
			t.Fatalf("feature pack list missing %q:\n%s", want, packs)
		}
	}
	created := runOK(t, tmp, bin, "new", "operator-demo", "--template", "hello", "--feature", "process,host")
	if !strings.Contains(created, "next: bofbench build "+filepath.Join("bofs", "operator-demo")) || !strings.Contains(created, "then: bofbench analyze "+filepath.Join("bofs", "operator-demo")) {
		t.Fatalf("new command missing next action:\n%s", created)
	}
	if out, err := run(t, tmp, bin, "new", "operator-demo", "--template", "hello"); err == nil || !strings.Contains(out, "already exists") {
		t.Fatalf("new command overwrote an existing workspace: err=%v\n%s", err, out)
	}
	source, err := os.ReadFile(filepath.Join(tmp, "bofs", "operator-demo", "operator-demo.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bofbench_feature_process();", "bofbench_feature_host();"} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("generated source missing %q:\n%s", want, source)
		}
	}
	sourceAnalysis := runOK(t, tmp, bin, "analyze", filepath.Join("bofs", "operator-demo"), "--format", "text")
	for _, want := range []string{"Can do", "No operator capability identified", "Works with", "KERNEL32 GetCurrentProcessId", "Loader and object details", "reports:"} {
		if !strings.Contains(sourceAnalysis, want) {
			t.Fatalf("source analysis missing %q:\n%s", want, sourceAnalysis)
		}
	}
	dev := runOK(t, tmp, bin, "dev", filepath.Join("bofs", "operator-demo"), "--compiler", "auto", "--skip-run")
	for _, want := range []string{"BOF DEV PASS", "source    pass", "analysis  compatible", "imports   review", "matched=4", "runtime   skipped", "next      bofbench dev"} {
		if !strings.Contains(dev, want) {
			t.Fatalf("developer loop missing %q:\n%s", want, dev)
		}
	}
	matches, err := filepath.Glob(filepath.Join(tmp, "runs", "*-dev-operator-demo", "dev.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("dev evidence = %v err=%v", matches, err)
	}
}

func TestCLICapabilityPackWorkflow(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	t.Setenv("BOFBENCH_CONFIG_HOME", filepath.Join(tmp, "config"))
	listed := runOK(t, tmp, bin, "pack", "list")
	for _, want := range []string{"CAPABILITY PACKS", "builtin/host-discovery", "builtin/token-context", "effects=reads data"} {
		if !strings.Contains(listed, want) {
			t.Fatalf("pack list missing %q:\n%s", want, listed)
		}
	}
	shown := runOK(t, tmp, bin, "pack", "show", "active-actions")
	for _, want := range []string{"ACTIVE OFFENSIVE LAB ACTIONS", "can do", "effects", "works with", "cleanup    active-cleanup"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("pack show missing %q:\n%s", want, shown)
		}
	}
	created := runOK(t, tmp, bin, "new", "pack-demo", "--pack", "host-discovery,token-context")
	if !strings.Contains(created, "added packs: builtin/host-discovery, builtin/token-context") {
		t.Fatalf("new pack output:\n%s", created)
	}
	mustExist(t, filepath.Join(tmp, "bofs", "pack-demo", "bofbench.lock.json"))
	added := runOK(t, tmp, bin, "add", filepath.Join("bofs", "pack-demo"), "service-list")
	if !strings.Contains(added, "builtin/service-list") || !strings.Contains(added, "next      bofbench build") {
		t.Fatalf("add output:\n%s", added)
	}
	source, err := os.ReadFile(filepath.Join(tmp, "bofs", "pack-demo", "pack-demo.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bofbench_feature_host();", "bofbench_feature_token_context();", "bofbench_feature_service_list();"} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("pack source missing %q:\n%s", want, source)
		}
	}
	exported := runOK(t, tmp, bin, "export", filepath.Join("bofs", "pack-demo"), "--for", "raw", "--skip-run")
	if !strings.Contains(exported, "BOF EXPORT PASS") || !strings.Contains(exported, "target    raw") || !strings.Contains(exported, "package   export/") || strings.Contains(exported, "BOF STAGE") {
		t.Fatalf("export output:\n%s", exported)
	}
	mustExist(t, filepath.Join(tmp, "export", "pack-demo-raw", "manifest.json"))
}

func TestCLIExportKeepsPackRuntimeArgumentContract(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	t.Setenv("BOFBENCH_CONFIG_HOME", filepath.Join(tmp, "config"))
	runOK(t, tmp, bin, "new", "survey", "--pack", "system-discovery")
	runOK(t, tmp, bin, "export", filepath.Join("bofs", "survey"), "--for", "sliver", "--skip-run")
	data, err := os.ReadFile(filepath.Join(tmp, "export", "survey-sliver", "extension.json"))
	if err != nil {
		t.Fatal(err)
	}
	var extension stage.SliverExtension
	if err := json.Unmarshal(data, &extension); err != nil {
		t.Fatal(err)
	}
	if len(extension.Arguments) != 2 || extension.Arguments[0].Name != "process_filter" || extension.Arguments[0].Type != "string" || !extension.Arguments[0].Optional || extension.Arguments[1].Name != "result_limit" || extension.Arguments[1].Type != "int" || !extension.Arguments[1].Optional {
		t.Fatalf("exported argument contract = %+v", extension.Arguments)
	}
}

func TestCLIFeatureListExplainsCapabilityModules(t *testing.T) {
	bin := buildTestBinary(t)
	out := runOK(t, t.TempDir(), bin, "feature", "list")
	for _, want := range []string{
		"BOF CAPABILITY MODULES",
		"Reusable source modules injected into a BOF project.",
		"add: bofbench feature add bofs/<project> <capability...>",
		"READ-ONLY DISCOVERY",
		"STATE-CHANGING LAB ACTIONS",
		"CLEANUP",
		"process",
		"lab-file-write",
		"lab-cleanup",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("feature list missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "READ-ONLY DISCOVERY") > strings.Index(out, "STATE-CHANGING LAB ACTIONS") || strings.Index(out, "STATE-CHANGING LAB ACTIONS") > strings.Index(out, "CLEANUP") {
		t.Fatalf("feature groups are not in operator workflow order:\n%s", out)
	}
}

func TestCLIRecipeCreatesValidOperationalBOF(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	listed := runOK(t, tmp, bin, "recipe", "list")
	for _, want := range []string{"host-survey", "network-survey", "registry-survey", "full-survey", "deep-survey", "active-actions", "offensive-survey", "active-cleanup", "read_only", "modifies_state"} {
		if !strings.Contains(listed, want) {
			t.Fatalf("recipe list missing %q:\n%s", want, listed)
		}
	}
	created := runOK(t, tmp, bin, "new", "survey", "--recipe", "full-survey")
	if !strings.Contains(created, "applied recipe: full-survey") {
		t.Fatalf("recipe creation output:\n%s", created)
	}
	mustExist(t, filepath.Join(tmp, "bofs", "survey", "bofbench.recipe.json"))
	shown := runOK(t, tmp, bin, "recipe", "show", filepath.Join("bofs", "survey"))
	for _, want := range []string{"Full Local Context Survey", "privilege  user", "effects    read_only", "WSACleanup and RegCloseKey"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("recipe show missing %q:\n%s", want, shown)
		}
	}
	validated := runOK(t, tmp, bin, "recipe", "validate", filepath.Join("bofs", "survey"))
	if !strings.Contains(validated, "BOF recipe validation: pass") || !strings.Contains(validated, "filesystem,host,identity,network,process,registry") {
		t.Fatalf("recipe validation:\n%s", validated)
	}
	dev := runOK(t, tmp, bin, "dev", filepath.Join("bofs", "survey"), "--compiler", "auto", "--skip-run")
	for _, want := range []string{"BOF DEV PASS", "recipe    pass", "full-survey", "privilege=user", "network=local", "effects=read_only"} {
		if !strings.Contains(dev, want) {
			t.Fatalf("recipe dev missing %q:\n%s", want, dev)
		}
	}
	var handoff struct {
		Output       string `json:"output"`
		Manifest     string `json:"manifest"`
		Verified     bool   `json:"verified"`
		Verification []struct {
			Status string `json:"status"`
		} `json:"verification"`
	}
	staged := runOK(t, tmp, bin, "stage", filepath.Join("bofs", "survey"), "--target", "raw", "--skip-run", "--format", "json")
	if err := json.Unmarshal([]byte(staged), &handoff); err != nil {
		t.Fatal(err)
	}
	if !handoff.Verified || len(handoff.Verification) != 2 || handoff.Verification[0].Status != "pass" || handoff.Verification[1].Status != "pass" {
		t.Fatalf("handoff = %+v", handoff)
	}
	mustExist(t, filepath.Join(tmp, handoff.Manifest))
	manifestData, err := os.ReadFile(filepath.Join(tmp, handoff.Manifest))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version": 2`, `"status": "complete"`, `"recipe": "full-survey"`, `"developer_json"`, `"packed_arguments"`, `"target_contract"`} {
		if !strings.Contains(string(manifestData), want) {
			t.Fatalf("handoff manifest missing %q:\n%s", want, manifestData)
		}
	}
}

func TestCLISourceAnalysisBlocksInvalidBOFWithFixes(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	project := filepath.Join(tmp, "broken-source")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#include <windows.h>\nint main(void) { printf(\"pid=%lu\", GetCurrentProcessId()); BeaconUseToken(0); return 0; }\n"
	if err := os.WriteFile(filepath.Join(project, "broken.c"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, tmp, bin, "analyze", project, "--format", "text")
	if err == nil {
		t.Fatal("invalid BOF source analysis unexpectedly passed")
	}
	for _, want := range []string{"BOF source analysis: fail", "missing_entrypoint", "unsupported_beacon_api", "implicit_winapi_import", "crt_dependency", "fix:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("invalid source output missing %q:\n%s", want, out)
		}
	}
	matches, globErr := filepath.Glob(filepath.Join(tmp, "runs", "*-source-broken-source", "source.json"))
	if globErr != nil || len(matches) != 1 {
		t.Fatalf("source evidence = %v err=%v", matches, globErr)
	}
}

func TestCLIAnalyzeBaselineWritesDiff(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	obj := filepath.Join(tmp, "demo.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf", "KERNEL32$VirtualAlloc"}); err != nil {
		t.Fatal(err)
	}
	inspect := runOK(t, tmp, bin, "inspect", obj)
	if !strings.Contains(inspect, "runtime compatibility:") || !strings.Contains(inspect, "windows-coff") {
		t.Fatalf("inspect missing runtime compatibility:\n%s", inspect)
	}
	var first struct {
		Analysis struct {
			Schema        string `json:"schema"`
			SchemaVersion int    `json:"schema_version"`
			RunID         string `json:"run_id"`
		} `json:"analysis"`
		JSONPath string `json:"json_path"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "analyze", obj, "--format", "json")), &first); err != nil {
		t.Fatal(err)
	}
	if first.JSONPath == "" || first.Analysis.Schema != "bofbench.analysis" || first.Analysis.SchemaVersion != 3 || first.Analysis.RunID == "" {
		t.Fatalf("missing versioned baseline analysis evidence: %+v", first)
	}
	var second struct {
		Diff *struct {
			Schema      string `json:"schema"`
			RunID       string `json:"run_id"`
			ParentRunID string `json:"parent_run_id"`
		} `json:"diff"`
		DiffJSON string `json:"diff_json_path"`
		DiffMD   string `json:"diff_md_path"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "analyze", obj, "--baseline", first.JSONPath, "--format", "json")), &second); err != nil {
		t.Fatal(err)
	}
	if second.DiffJSON == "" || second.DiffMD == "" || second.Diff == nil || second.Diff.Schema != "bofbench.analysis-diff" || second.Diff.RunID == "" || second.Diff.ParentRunID == "" {
		t.Fatalf("missing diff paths: %+v", second)
	}
	mustExist(t, filepath.Join(tmp, second.DiffJSON))
	mustExist(t, filepath.Join(tmp, second.DiffMD))
	other := filepath.Join(tmp, "other.x64.o")
	if err := coff.CreateMockObject(other, "x64", "go", []string{"ADVAPI32$OpenProcessToken"}); err != nil {
		t.Fatal(err)
	}
	directCompare := runOK(t, tmp, bin, "analyze", obj, "--compare", other, "--format", "json")
	if !strings.Contains(directCompare, `"diff_json_path"`) || !strings.Contains(directCompare, `"capabilities_removed"`) {
		t.Fatalf("direct object comparison missing capability diff:\n%s", directCompare)
	}
	suppressed := runOK(t, tmp, bin, "analyze", obj, "--suppress", "memory_api", "--format", "json")
	if !strings.Contains(suppressed, `"category": "memory_api"`) || !strings.Contains(suppressed, `"suppressed": true`) || !strings.Contains(suppressed, `"suppression": "memory_api"`) {
		t.Fatalf("CLI suppression did not preserve marked finding:\n%s", suppressed)
	}
}

func TestCLIAnalyzeSummaryNamesCapabilitiesImpactAndInferenceLimit(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	obj := filepath.Join(tmp, "operator-capabilities.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{
		"__imp__BeaconPrintf",
		"ADVAPI32$LookupAccountSidW",
		"ADVAPI32$OpenProcessToken",
		"ADVAPI32$RegSetValueExA",
		"KERNEL32$WriteFile",
		"KERNEL32$VirtualAlloc",
		"KERNEL32$CreateProcessW",
	}); err != nil {
		t.Fatal(err)
	}

	out := runOK(t, tmp, bin, "analyze", obj)
	for _, want := range []string{
		"Can do",
		"identity/account/SID lookup",
		"token inspection",
		"registry write",
		"file write",
		"memory allocation/protection",
		"process launch",
		"Effects",
		"writes state",
		"starts execution",
		"Needs",
		"current user",
		"Works with",
		"Loader",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("analysis summary missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "imports:\n") || strings.Contains(out, "relocations:\n") || strings.Contains(out, "visible strings:\n") {
		t.Fatalf("default analysis summary leaked the full detail dump:\n%s", out)
	}
}

func TestCLIRunRequiresWindowsOnNonWindows(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("non-Windows behavior only")
	}
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "hello")
	runOK(t, tmp, bin, "build", filepath.Join("bofs", "hello"))
	out, err := run(t, tmp, bin, "run", filepath.Join("dist", "hello.x64.o"), "--args", "z:hello", "i:3")
	if err == nil {
		t.Fatalf("run succeeded unexpectedly on non-Windows:\n%s", out)
	}
	if !strings.Contains(out, "requires Windows x64") {
		t.Fatalf("unexpected run output:\n%s", out)
	}
	if !strings.Contains(out, `"schema": "bofbench.run"`) || !strings.Contains(out, `"object_fingerprint"`) || !strings.Contains(out, `"run_id"`) {
		t.Fatalf("run failure missing evidence contract:\n%s", out)
	}
}

func TestCLIListTrustedSecLikeArsenal(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	arsenalDir := filepath.Join(tmp, "arsenal", "trustedsec-sa", "SA", "whoami")
	if err := os.MkdirAll(arsenalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arsenalDir, "whoami.x64.o"), []byte("not-real-for-list"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "list", filepath.Join("arsenal", "trustedsec-sa"))
	if !strings.Contains(out, "whoami") || !strings.Contains(out, "x64") {
		t.Fatalf("unexpected list output:\n%s", out)
	}
}

func TestCLIArsenalInventoryLockVerifyAndRegression(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	root := filepath.Join(tmp, "arsenal", "demo")
	entry := filepath.Join(root, "SA", "whoami")
	object := filepath.Join(entry, "whoami.x64.o")
	if err := os.MkdirAll(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(entry, "whoami.c"), []byte("void go(char *args, int len) {(void)args;(void)len;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(object, "x64", "go", []string{"BeaconPrintf", "KERNEL32$GetComputerNameA"}); err != nil {
		t.Fatal(err)
	}

	var inventory struct {
		Schema  string `json:"schema"`
		Summary struct {
			Entries    int `json:"entries"`
			Compatible int `json:"compatible"`
		} `json:"summary"`
	}
	inventoryJSON := runOK(t, tmp, bin, "arsenal", "inventory", root, "--format", "json")
	if err := json.Unmarshal([]byte(inventoryJSON), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Schema != "bofbench.arsenal-inventory" || inventory.Summary.Entries != 1 || inventory.Summary.Compatible != 1 {
		t.Fatalf("inventory = %+v", inventory)
	}
	search := runOK(t, tmp, bin, "arsenal", "search", root, "GetComputerNameA")
	if !strings.Contains(search, "whoami") || !strings.Contains(search, "GetComputerNameA") {
		t.Fatalf("search output = %s", search)
	}
	lockOutput := runOK(t, tmp, bin, "arsenal", "lock", root)
	if !strings.Contains(lockOutput, "BOF arsenal lock written") || !strings.Contains(lockOutput, "objects   1") {
		t.Fatalf("lock output = %s", lockOutput)
	}
	lockPath := filepath.Join(root, "arsenal.lock.json")
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	baselineLock := filepath.Join(tmp, "baseline.lock.json")
	if err := os.WriteFile(baselineLock, lockData, 0o644); err != nil {
		t.Fatal(err)
	}
	verify := runOK(t, tmp, bin, "arsenal", "verify", root)
	if !strings.Contains(verify, "BOF arsenal diff: same") {
		t.Fatalf("verify output = %s", verify)
	}
	file, err := os.OpenFile(object, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tampered")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	changed, err := run(t, tmp, bin, "arsenal", "diff", baselineLock, root, "--check")
	if err == nil || !strings.Contains(changed, "objects   added=0 removed=0 changed=1") || !strings.Contains(changed, "arsenal diff detected changes") {
		t.Fatalf("changed diff did not fail: err=%v\n%s", err, changed)
	}

	preflightBaseline := filepath.Join(tmp, "preflight-baseline.json")
	preflightCurrent := filepath.Join(tmp, "preflight-current.json")
	baselineEvidence := `{"schema":"bofbench.preflight","schema_version":1,"results":[{"name":"whoami","arch":"x64","status":"compatible","sha256":"one","relocations":1,"argument_need":"none"}]}`
	currentEvidence := `{"schema":"bofbench.preflight","schema_version":1,"results":[{"name":"whoami","arch":"x64","status":"unsupported_beacon_api","sha256":"one","relocations":1,"argument_need":"none"}]}`
	if err := os.WriteFile(preflightBaseline, []byte(baselineEvidence), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(preflightCurrent, []byte(currentEvidence), 0o644); err != nil {
		t.Fatal(err)
	}
	stable := runOK(t, tmp, bin, "arsenal", "regression", preflightBaseline, preflightBaseline)
	if !strings.Contains(stable, "BOF arsenal regression: pass") || !strings.Contains(stable, "regressions=0") {
		t.Fatalf("stable regression output = %s", stable)
	}
	regressed, err := run(t, tmp, bin, "arsenal", "regression", preflightBaseline, preflightCurrent)
	if err == nil || !strings.Contains(regressed, "BOF arsenal regression: fail") || !strings.Contains(regressed, "regressions=1") || !strings.Contains(regressed, "arsenal regression detected") {
		t.Fatalf("regression gate did not fail: err=%v\n%s", err, regressed)
	}
}

func TestCLIArsenalTestWritesReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("report-only arsenal smoke avoids requiring native loader in test tempdir")
	}
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	arsenalDir := filepath.Join(tmp, "arsenal", "trustedsec-sa", "SA", "whoami")
	obj := filepath.Join(arsenalDir, "whoami.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", nil); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "test", filepath.Join("arsenal", "trustedsec-sa"), "--select", "whoami")
	if !strings.Contains(out, "reports:") {
		t.Fatalf("missing report line:\n%s", out)
	}
	matches, err := filepath.Glob(filepath.Join(tmp, "runs", "*test-arsenal-trustedsec-sa", "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one result.json, got %d", len(matches))
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"status": "analyze_pass"`) {
		t.Fatalf("unexpected report:\n%s", b)
	}
	if !strings.Contains(string(b), `"schema": "bofbench.arsenal-test"`) || !strings.Contains(string(b), `"parent_run_id"`) {
		t.Fatalf("arsenal report missing linked report IDs:\n%s", b)
	}
}

func TestCLIPreflightArsenalGateAndReports(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	root := filepath.Join(tmp, "arsenal", "demo")
	if err := coff.CreateMockObject(filepath.Join(root, "supported", "supported.x64.o"), "x64", "go", []string{"__imp__BeaconPrintf", "KERNEL32$VirtualAlloc"}); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(filepath.Join(root, "blocked", "blocked.x64.o"), "x64", "go", []string{"BeaconUseToken"}); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(filepath.Join(root, "supported", "supported.x86.o"), "x86", "_go@8", []string{"__imp__BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(filepath.Join(root, "blocked", "blocked.x86.o"), "x86", "_go@8", nil); err != nil {
		t.Fatal(err)
	}
	var passed struct {
		Report struct {
			Schema  string `json:"schema"`
			Status  string `json:"status"`
			Summary struct {
				Compatible int `json:"compatible"`
				Total      int `json:"total"`
			} `json:"summary"`
		} `json:"report"`
		JSONPath string `json:"json_path"`
		MDPath   string `json:"md_path"`
	}
	jsonOutput := runOK(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported", "--format", "json")
	if err := json.Unmarshal([]byte(jsonOutput), &passed); err != nil {
		t.Fatal(err)
	}
	if passed.Report.Schema != "bofbench.preflight" || passed.Report.Status != "pass" || passed.Report.Summary.Compatible != 1 || passed.Report.Summary.Total != 1 || passed.JSONPath == "" || passed.MDPath == "" {
		t.Fatalf("preflight JSON = %+v", passed)
	}
	mustExist(t, filepath.Join(tmp, passed.JSONPath))
	mustExist(t, filepath.Join(tmp, passed.MDPath))
	passedSummary := runOK(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported")
	for _, want := range []string{"BOF PREFLIGHT PASS", "object    arsenal/demo/supported/supported.x64.o", "target    arch=x64", "entry=go", "loader    compatible  blockers=0  warnings=0", "shape     imports=2", "reports   runs/"} {
		if !strings.Contains(passedSummary, want) {
			t.Fatalf("preflight summary missing %q:\n%s", want, passedSummary)
		}
	}
	for _, oldDump := range []string{"catalog matrix:", "dimensions:", "compatible=1, x64=1"} {
		if strings.Contains(passedSummary, oldDump) {
			t.Fatalf("default preflight summary contains old matrix detail %q:\n%s", oldDump, passedSummary)
		}
	}
	fullText := runOK(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported", "--format", "text")
	if !strings.Contains(fullText, "catalog matrix:") || !strings.Contains(fullText, "dimensions:") || !strings.Contains(fullText, "reports:") {
		t.Fatalf("full preflight text no longer available:\n%s", fullText)
	}

	blocked, err := run(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "blocked")
	if err == nil || !strings.Contains(blocked, "BOF PREFLIGHT REVIEW") || !strings.Contains(blocked, "object    arsenal/demo/blocked/blocked.x64.o") || !strings.Contains(blocked, "loader    blocked") || !strings.Contains(blocked, "shape     imports=1") || !strings.Contains(blocked, "blockers  unsupported_beacon_api") || !strings.Contains(blocked, "loader support blocked execution") || !strings.Contains(blocked, "reports   runs/") {
		t.Fatalf("blocked preflight did not fail with evidence: err=%v\n%s", err, blocked)
	}
	allArchitectures, err := run(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported", "--arch", "all", "--format", "md")
	if err != nil || !strings.Contains(allArchitectures, "Architecture request: `all`") || !strings.Contains(allArchitectures, "By architecture: `x64=1, x86=1`") || !strings.Contains(allArchitectures, "2 compatible") {
		t.Fatalf("all-architecture CLI matrix did not expose x64 and x86 loader support: err=%v\n%s", err, allArchitectures)
	}
	reportOnly := runOK(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported", "--arch", "all", "--report-only")
	if !strings.Contains(reportOnly, "BOF PREFLIGHT PASS") || !strings.Contains(reportOnly, "objects   2") || !strings.Contains(reportOnly, "compatible=2") || !strings.Contains(reportOnly, "arch=x86") || !strings.Contains(reportOnly, "reports   runs/") {
		t.Fatalf("report-only matrix missing x64/x86 compatibility evidence:\n%s", reportOnly)
	}
}

func TestCLIVersionJSON(t *testing.T) {
	bin := buildTestBinary(t)
	out := runOK(t, t.TempDir(), bin, "version", "--format", "json")
	var report struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
		Tool          struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Host struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"host"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != "bofbench.version" || report.SchemaVersion != 1 || report.Tool.Name != "bofbench" || report.Tool.Version == "" || report.Host.OS == "" || report.Host.Arch == "" {
		t.Fatalf("version evidence = %+v", report)
	}
}

func TestCLILabSmokePrint(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	out := runOK(t, tmp, bin, "lab", "smoke", "--print", "--repo-root", `C:\bofbench`, "--select", "whoami,env", "--timeout", "7000", "--skip-fetch")
	for _, want := range []string{"windows-lab-smoke.ps1", "-RepoRoot", `C:\bofbench`, "-Select", "whoami,env", "-TimeoutMS", "7000", "-BofbenchExe", "bofbench-lab.exe", "-SkipFetch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCLIRemoteLabCommandSurface(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	help := runOK(t, tmp, bin, "lab", "--help")
	for _, want := range []string{"status", "sync", "run", "collect", "reset", "smoke", "summary"} {
		if !strings.Contains(help, want) {
			t.Fatalf("lab help missing %q:\n%s", want, help)
		}
	}
	runHelp := runOK(t, tmp, bin, "lab", "run", "--help")
	for _, want := range []string{"--host", "--remote-root", "--compiler", "--runtime", "--profile", "--no-sync", "--transport-timeout"} {
		if !strings.Contains(runHelp, want) {
			t.Fatalf("lab run help missing %q:\n%s", want, runHelp)
		}
	}
}

func TestCLILabSummaryLatest(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "runs", "20260709-180000-lab-smoke")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "generated_at": "2026-07-09T18:00:00Z",
  "repo_root": "C:\\bofbench",
  "selection": "whoami,env",
  "timeout_ms": 5000,
  "status": "pass",
  "steps": [
    {"name": "go test", "status": "pass", "started_at": "2026-07-09T18:00:00Z", "duration_ms": 123, "error": null}
  ]
}`
	if err := os.WriteFile(filepath.Join(runDir, "lab-smoke.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "lab", "summary")
	for _, want := range []string{"Lab Smoke Summary", "Status: `pass`", "`go test`", "`123ms`"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	jsonOut := runOK(t, tmp, bin, "lab", "summary", filepath.Join("runs", "20260709-180000-lab-smoke", "lab-smoke.json"), "--format", "json")
	if !strings.Contains(jsonOut, `"status": "pass"`) || !strings.Contains(jsonOut, `"path":`) {
		t.Fatalf("unexpected json summary:\n%s", jsonOut)
	}
}

func buildTestBinary(t *testing.T) string {
	t.Helper()
	repo := filepath.Clean("../..")
	bin := filepath.Join(t.TempDir(), executableName("bofbench"))
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/bofbench")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func executableName(name string) string {
	if os.PathSeparator == '\\' {
		return name + ".exe"
	}
	return name
}

func requireMinGW(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		if os.PathSeparator == '\\' {
			if _, clErr := exec.LookPath("cl"); clErr == nil {
				return
			}
		}
		t.Skip("x86_64-w64-mingw32-gcc or cl not available")
	}
}

func runOK(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	out, err := run(t, dir, bin, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return out
}

func run(t *testing.T, dir, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s missing: %v", path, err)
	}
}
