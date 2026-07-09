package capability

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	Schema        = "bofbench.loader-capabilities"
	SchemaVersion = 1
)

//go:embed windows_coff.json
var windowsCOFFJSON []byte

//go:generate go run ../../cmd/capgen -out ../../native/loader/capabilities.generated.h

type Catalog struct {
	Schema                 string       `json:"schema"`
	SchemaVersion          int          `json:"schema_version"`
	CatalogVersion         string       `json:"catalog_version"`
	Runtime                string       `json:"runtime"`
	Format                 string       `json:"format"`
	Machine                Machine      `json:"machine"`
	DefaultEntrypoint      string       `json:"default_entrypoint"`
	SectionFlags           SectionFlags `json:"section_flags"`
	Relocations            []Relocation `json:"relocations"`
	BeaconAPIs             []string     `json:"beacon_apis"`
	ImportPointerPrefixes  []string     `json:"import_pointer_prefixes"`
	DynamicImportSeparator string       `json:"dynamic_import_separator"`
	FallbackLibraries      []string     `json:"fallback_libraries"`
}

type Machine struct {
	Name string `json:"name"`
	Arch string `json:"arch"`
	Code uint16 `json:"code"`
}

type SectionFlags struct {
	UninitializedData uint32 `json:"uninitialized_data"`
}

type Relocation struct {
	Name      string `json:"name"`
	Code      uint16 `json:"code"`
	Supported bool   `json:"supported"`
	Detail    string `json:"detail"`
}

func WindowsCOFF() Catalog {
	var catalog Catalog
	if err := json.Unmarshal(windowsCOFFJSON, &catalog); err != nil {
		panic(fmt.Sprintf("embedded Windows COFF capability catalog: %v", err))
	}
	if err := catalog.Validate(); err != nil {
		panic(fmt.Sprintf("embedded Windows COFF capability catalog: %v", err))
	}
	return catalog
}

func (c Catalog) Validate() error {
	if c.Schema != Schema || c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("expected %s version %d, got %q version %d", Schema, SchemaVersion, c.Schema, c.SchemaVersion)
	}
	if c.CatalogVersion == "" || c.Runtime != "windows-coff" || c.Format != "COFF" {
		return fmt.Errorf("catalog identity is incomplete")
	}
	if c.Machine.Name != "AMD64" || c.Machine.Arch != "x64" || c.Machine.Code != 0x8664 {
		return fmt.Errorf("catalog machine must be AMD64/x64/0x8664")
	}
	if c.SectionFlags.UninitializedData != 0x00000080 {
		return fmt.Errorf("catalog uninitialized-data section flag must be 0x00000080")
	}
	if c.DefaultEntrypoint == "" || len(c.Relocations) == 0 || len(c.BeaconAPIs) == 0 || len(c.FallbackLibraries) == 0 {
		return fmt.Errorf("catalog capability lists are incomplete")
	}
	if c.DynamicImportSeparator != "$" {
		return fmt.Errorf("dynamic import separator must be $")
	}
	identifier := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	seenRelocationNames := map[string]bool{}
	seenRelocationCodes := map[uint16]bool{}
	for _, relocation := range c.Relocations {
		if !identifier.MatchString(relocation.Name) || seenRelocationNames[relocation.Name] || seenRelocationCodes[relocation.Code] || relocation.Detail == "" {
			return fmt.Errorf("invalid or duplicate relocation %q/0x%04x", relocation.Name, relocation.Code)
		}
		seenRelocationNames[relocation.Name] = true
		seenRelocationCodes[relocation.Code] = true
	}
	seenAPIs := map[string]bool{}
	for _, api := range c.BeaconAPIs {
		if !strings.HasPrefix(api, "Beacon") || !identifier.MatchString(api) || seenAPIs[api] {
			return fmt.Errorf("invalid or duplicate Beacon API %q", api)
		}
		seenAPIs[api] = true
	}
	seenPrefixes := map[string]bool{}
	lastLength := int(^uint(0) >> 1)
	for _, prefix := range c.ImportPointerPrefixes {
		if prefix == "" || seenPrefixes[prefix] || len(prefix) > lastLength {
			return fmt.Errorf("import pointer prefixes must be unique and longest-first")
		}
		seenPrefixes[prefix] = true
		lastLength = len(prefix)
	}
	seenLibraries := map[string]bool{}
	for _, library := range c.FallbackLibraries {
		if !identifier.MatchString(library) || library != strings.ToLower(library) || seenLibraries[library] {
			return fmt.Errorf("invalid or duplicate fallback library %q", library)
		}
		seenLibraries[library] = true
	}
	return nil
}

func (c Catalog) RelocationByCode(code uint16) (Relocation, bool) {
	for _, relocation := range c.Relocations {
		if relocation.Code == code {
			return relocation, true
		}
	}
	return Relocation{Name: fmt.Sprintf("AMD64_0x%04x", code), Code: code, Detail: "relocation is not declared in the capability catalog"}, false
}

func (c Catalog) SupportsBeaconAPI(name string) bool {
	name, _ = c.NormalizeImport(name)
	for _, api := range c.BeaconAPIs {
		if name == api {
			return true
		}
	}
	return false
}

func (c Catalog) NormalizeImport(name string) (normalized string, importPointer bool) {
	for _, prefix := range c.ImportPointerPrefixes {
		if strings.HasPrefix(name, prefix) {
			return strings.TrimPrefix(name, prefix), true
		}
	}
	return name, false
}

func (c Catalog) SortedRelocations() []Relocation {
	out := append([]Relocation(nil), c.Relocations...)
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
