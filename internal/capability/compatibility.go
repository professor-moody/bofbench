package capability

import (
	"fmt"
	"sort"
	"strings"
)

type COFFInput struct {
	Arch         string
	Entrypoint   string
	EntrypointOK bool
	Relocations  []RelocationUse
	Unresolved   []string
}

type RelocationUse struct {
	Code    uint16
	Name    string
	Section string
	Symbol  string
}

type Compatibility struct {
	Schema         string  `json:"schema"`
	SchemaVersion  int     `json:"schema_version"`
	CatalogVersion string  `json:"catalog_version"`
	Runtime        string  `json:"runtime"`
	Status         string  `json:"status"`
	Compatible     bool    `json:"compatible"`
	Blockers       []Issue `json:"blockers,omitempty"`
	Warnings       []Issue `json:"warnings,omitempty"`
}

type Issue struct {
	Category   string `json:"category"`
	Detail     string `json:"detail"`
	Symbol     string `json:"symbol,omitempty"`
	Relocation string `json:"relocation,omitempty"`
	Code       uint16 `json:"code,omitempty"`
	Section    string `json:"section,omitempty"`
}

func AssessWindowsCOFF(input COFFInput) Compatibility {
	catalog := WindowsCOFF()
	result := Compatibility{
		Schema:         catalog.Schema,
		SchemaVersion:  catalog.SchemaVersion,
		CatalogVersion: catalog.CatalogVersion,
		Runtime:        catalog.Runtime,
		Status:         "compatible",
		Compatible:     true,
	}
	if input.Arch != catalog.Machine.Arch {
		result.Blockers = append(result.Blockers, Issue{
			Category: "unsupported_arch",
			Detail:   fmt.Sprintf("loader supports %s objects; artifact architecture is %s", catalog.Machine.Arch, emptyAs(input.Arch, "unknown")),
		})
	}
	if !input.EntrypointOK {
		result.Blockers = append(result.Blockers, Issue{
			Category: "missing_entrypoint",
			Detail:   fmt.Sprintf("entrypoint %q is not defined by the object", emptyAs(input.Entrypoint, catalog.DefaultEntrypoint)),
			Symbol:   emptyAs(input.Entrypoint, catalog.DefaultEntrypoint),
		})
	}
	for _, use := range input.Relocations {
		relocation, declared := catalog.RelocationByCode(use.Code)
		if declared && relocation.Supported {
			continue
		}
		detail := relocation.Detail
		if !declared {
			detail = "relocation is not declared in the loader capability catalog"
		}
		result.Blockers = append(result.Blockers, Issue{
			Category:   "unsupported_relocation",
			Detail:     detail,
			Symbol:     use.Symbol,
			Relocation: relocation.Name,
			Code:       use.Code,
			Section:    use.Section,
		})
	}
	for _, symbol := range input.Unresolved {
		normalized, _ := catalog.NormalizeImport(symbol)
		candidate := strings.TrimLeft(normalized, "_")
		if strings.HasPrefix(candidate, "Beacon") {
			if !catalog.supportsBeaconName(candidate) {
				result.Blockers = append(result.Blockers, Issue{
					Category: "unsupported_beacon_api",
					Detail:   "Beacon API is not implemented by the native loader shim",
					Symbol:   symbol,
				})
			}
			continue
		}
		if library, api, dynamic := strings.Cut(normalized, catalog.DynamicImportSeparator); dynamic {
			if library == "" || api == "" {
				result.Blockers = append(result.Blockers, Issue{
					Category: "malformed_dynamic_import",
					Detail:   fmt.Sprintf("dynamic imports must use LIBRARY%sAPI", catalog.DynamicImportSeparator),
					Symbol:   symbol,
				})
			}
			continue
		}
		result.Warnings = append(result.Warnings, Issue{
			Category: "fallback_lookup",
			Detail:   "symbol requires runtime lookup across the loader fallback libraries",
			Symbol:   symbol,
		})
	}
	result.Blockers = uniqueIssues(result.Blockers)
	result.Warnings = uniqueIssues(result.Warnings)
	if len(result.Blockers) > 0 {
		result.Compatible = false
		result.Status = result.Blockers[0].Category
	} else if len(result.Warnings) > 0 {
		result.Status = "compatible_runtime_lookup"
	}
	return result
}

func (c Catalog) supportsBeaconName(name string) bool {
	for _, api := range c.BeaconAPIs {
		if name == api {
			return true
		}
	}
	return false
}

func uniqueIssues(issues []Issue) []Issue {
	seen := map[string]bool{}
	out := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", issue.Category, issue.Symbol, issue.Relocation, issue.Code, issue.Section)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, issue)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return issuePriority(out[i].Category) < issuePriority(out[j].Category)
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Symbol != out[j].Symbol {
			return out[i].Symbol < out[j].Symbol
		}
		return out[i].Section < out[j].Section
	})
	return out
}

func issuePriority(category string) int {
	switch category {
	case "unsupported_arch":
		return 0
	case "missing_entrypoint":
		return 1
	case "unsupported_relocation":
		return 2
	case "unsupported_beacon_api":
		return 3
	case "malformed_dynamic_import":
		return 4
	default:
		return 9
	}
}

func emptyAs(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
