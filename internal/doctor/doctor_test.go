package doctor

import "testing"

func TestRunReportHasCoreChecks(t *testing.T) {
	r := Run()
	if r.OS == "" || r.Arch == "" {
		t.Fatalf("missing host info: %+v", r)
	}
	names := map[string]bool{}
	for _, check := range r.Checks {
		names[check.Name] = true
	}
	for _, name := range []string{"Go toolchain", "Git client", "x64 BOF compiler", "Windows COFF loader", "windows-coff runtime", "bofs directory", "arsenal directory"} {
		if !names[name] {
			t.Fatalf("missing check %q in %+v", name, r.Checks)
		}
	}
	if _, err := r.JSON(); err != nil {
		t.Fatal(err)
	}
	if r.Text() == "" {
		t.Fatal("empty text report")
	}
}
