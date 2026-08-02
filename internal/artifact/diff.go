package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/evidence"
)

type DiffReport struct {
	evidence.Header
	GeneratedAt string       `json:"generated_at"`
	Baseline    string       `json:"baseline"`
	Current     string       `json:"current"`
	Summary     DiffSummary  `json:"summary"`
	Changes     []DiffChange `json:"changes,omitempty"`
}

type DiffSummary struct {
	HashChanged             bool  `json:"hash_changed"`
	SizeDelta               int64 `json:"size_delta"`
	RelocationsDelta        int   `json:"relocations_delta"`
	ImportsAdded            int   `json:"imports_added"`
	ImportsRemoved          int   `json:"imports_removed"`
	CapabilitiesAdded       int   `json:"capabilities_added"`
	CapabilitiesRemoved     int   `json:"capabilities_removed"`
	BehaviorChainsAdded     int   `json:"behavior_chains_added"`
	BehaviorChainsRemoved   int   `json:"behavior_chains_removed"`
	FindingsAdded           int   `json:"findings_added"`
	FindingsRemoved         int   `json:"findings_removed"`
	ActiveFindingsDelta     int   `json:"active_findings_delta"`
	SuppressedFindingsDelta int   `json:"suppressed_findings_delta"`
	EntrypointChanged       bool  `json:"entrypoint_changed"`
}

type DiffChange struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Change   string `json:"change"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

func LoadAnalysis(path string) (Analysis, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Analysis{}, err
	}
	var a Analysis
	if err := json.Unmarshal(b, &a); err != nil {
		return Analysis{}, err
	}
	return a, nil
}

func CompareAnalysis(baseline, current Analysis) DiffReport {
	baselineFindings := normalizedFindingSummary(baseline)
	currentFindings := normalizedFindingSummary(current)
	report := DiffReport{
		Header:      evidence.New(evidence.SchemaAnalysisDiff, "", ""),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Baseline:    baseline.Path,
		Current:     current.Path,
		Summary: DiffSummary{
			HashChanged:             baseline.SHA256 != current.SHA256,
			SizeDelta:               current.Size - baseline.Size,
			RelocationsDelta:        current.Relocations - baseline.Relocations,
			EntrypointChanged:       baseline.EntrypointOK != current.EntrypointOK || baseline.EntrypointExecutable != current.EntrypointExecutable || baseline.Entrypoint != current.Entrypoint || baseline.EntrypointSymbol != current.EntrypointSymbol || baseline.EntrypointSection != current.EntrypointSection || baseline.EntrypointOffset != current.EntrypointOffset,
			ActiveFindingsDelta:     currentFindings.Active - baselineFindings.Active,
			SuppressedFindingsDelta: currentFindings.Suppressed - baselineFindings.Suppressed,
		},
	}
	if baseline.Kind != current.Kind {
		report.Changes = append(report.Changes, DiffChange{Category: "artifact", Name: "kind", Change: "changed", Before: string(baseline.Kind), After: string(current.Kind)})
	}
	if baseline.Arch != current.Arch {
		report.Changes = append(report.Changes, DiffChange{Category: "artifact", Name: "arch", Change: "changed", Before: baseline.Arch, After: current.Arch})
	}
	if baseline.EntrypointOK != current.EntrypointOK {
		report.Changes = append(report.Changes, DiffChange{Category: "entrypoint", Name: current.Entrypoint, Change: "changed", Before: fmt.Sprintf("%t", baseline.EntrypointOK), After: fmt.Sprintf("%t", current.EntrypointOK)})
	}
	if baseline.EntrypointExecutable != current.EntrypointExecutable {
		report.Changes = append(report.Changes, DiffChange{Category: "entrypoint", Name: current.Entrypoint, Change: "executable", Before: fmt.Sprintf("%t", baseline.EntrypointExecutable), After: fmt.Sprintf("%t", current.EntrypointExecutable)})
	}
	if baseline.EntrypointSymbol != current.EntrypointSymbol || baseline.EntrypointSection != current.EntrypointSection || baseline.EntrypointOffset != current.EntrypointOffset {
		report.Changes = append(report.Changes, DiffChange{Category: "entrypoint", Name: current.Entrypoint, Change: "location", Before: entrypointSummary(baseline), After: entrypointSummary(current)})
	}
	report.Changes = append(report.Changes, diffSet("import", importKeys(baseline.Imports), importKeys(current.Imports), &report.Summary.ImportsRemoved, &report.Summary.ImportsAdded)...)
	report.Changes = append(report.Changes, diffSet("capability", capabilityKeys(baseline.Capabilities), capabilityKeys(current.Capabilities), &report.Summary.CapabilitiesRemoved, &report.Summary.CapabilitiesAdded)...)
	report.Changes = append(report.Changes, diffSet("behavior", behaviorChainKeys(baseline.BehaviorChains), behaviorChainKeys(current.BehaviorChains), &report.Summary.BehaviorChainsRemoved, &report.Summary.BehaviorChainsAdded)...)
	report.Changes = append(report.Changes, diffSet("finding", findingKeys(baseline.Findings), findingKeys(current.Findings), &report.Summary.FindingsRemoved, &report.Summary.FindingsAdded)...)
	report.Changes = append(report.Changes, diffSet("unresolved", stringSet(baseline.Unresolved), stringSet(current.Unresolved), nil, nil)...)
	report.Changes = append(report.Changes, diffSectionChanges(baseline.Sections, current.Sections)...)
	sort.SliceStable(report.Changes, func(i, j int) bool {
		if report.Changes[i].Category != report.Changes[j].Category {
			return report.Changes[i].Category < report.Changes[j].Category
		}
		if report.Changes[i].Name != report.Changes[j].Name {
			return report.Changes[i].Name < report.Changes[j].Name
		}
		return report.Changes[i].Change < report.Changes[j].Change
	})
	return report
}

func normalizedFindingSummary(analysis Analysis) FindingSummary {
	if analysis.FindingSummary.Total == len(analysis.Findings) {
		return analysis.FindingSummary
	}
	summary := FindingSummary{Total: len(analysis.Findings)}
	for _, finding := range analysis.Findings {
		if finding.Suppressed {
			summary.Suppressed++
		} else {
			summary.Active++
		}
	}
	return summary
}

func entrypointSummary(analysis Analysis) string {
	return fmt.Sprintf("symbol=%s section=%s offset=0x%x executable=%t", analysis.EntrypointSymbol, analysis.EntrypointSection, analysis.EntrypointOffset, analysis.EntrypointExecutable)
}

func DiffMarkdown(report DiffReport) string {
	var b strings.Builder
	b.WriteString("# Analysis Diff\n\n")
	fmt.Fprintf(&b, "- Schema: `%s` version `%d`\n", report.Schema, report.SchemaVersion)
	if report.RunID != "" {
		fmt.Fprintf(&b, "- Run ID: `%s`\n", report.RunID)
	}
	fmt.Fprintf(&b, "- Baseline: `%s`\n", report.Baseline)
	fmt.Fprintf(&b, "- Current: `%s`\n", report.Current)
	fmt.Fprintf(&b, "- Hash changed: `%t`\n", report.Summary.HashChanged)
	fmt.Fprintf(&b, "- Size delta: `%+d`\n", report.Summary.SizeDelta)
	fmt.Fprintf(&b, "- Relocations delta: `%+d`\n", report.Summary.RelocationsDelta)
	fmt.Fprintf(&b, "- Imports: `%+d added`, `%+d removed`\n", report.Summary.ImportsAdded, report.Summary.ImportsRemoved)
	fmt.Fprintf(&b, "- Capabilities: `%+d added`, `%+d removed`\n", report.Summary.CapabilitiesAdded, report.Summary.CapabilitiesRemoved)
	fmt.Fprintf(&b, "- Behavior chains: `%+d added`, `%+d removed`\n", report.Summary.BehaviorChainsAdded, report.Summary.BehaviorChainsRemoved)
	fmt.Fprintf(&b, "- Findings: `%+d added`, `%+d removed`\n\n", report.Summary.FindingsAdded, report.Summary.FindingsRemoved)
	fmt.Fprintf(&b, "- Finding state: `%+d active`, `%+d suppressed`\n\n", report.Summary.ActiveFindingsDelta, report.Summary.SuppressedFindingsDelta)
	if len(report.Changes) == 0 {
		b.WriteString("No structural changes detected in the tracked fields.\n")
		return b.String()
	}
	b.WriteString("| Category | Name | Change | Before | After |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, change := range report.Changes {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` |\n", change.Category, escapeTable(change.Name), change.Change, escapeTable(change.Before), escapeTable(change.After))
	}
	return b.String()
}

func diffSet(category string, before, after map[string]string, removedCount, addedCount *int) []DiffChange {
	var changes []DiffChange
	for key, value := range before {
		afterValue, ok := after[key]
		if !ok {
			changes = append(changes, DiffChange{Category: category, Name: key, Change: "removed", Before: value})
			if removedCount != nil {
				*removedCount = *removedCount + 1
			}
		} else if value != afterValue {
			changes = append(changes, DiffChange{Category: category, Name: key, Change: "changed", Before: value, After: afterValue})
		}
	}
	for key, value := range after {
		if _, ok := before[key]; !ok {
			changes = append(changes, DiffChange{Category: category, Name: key, Change: "added", After: value})
			if addedCount != nil {
				*addedCount = *addedCount + 1
			}
		}
	}
	return changes
}

func diffSectionChanges(before, after []Section) []DiffChange {
	beforeMap := map[string]Section{}
	afterMap := map[string]Section{}
	for _, section := range before {
		beforeMap[section.Name] = section
	}
	for _, section := range after {
		afterMap[section.Name] = section
	}
	var changes []DiffChange
	for name, oldSection := range beforeMap {
		newSection, ok := afterMap[name]
		if !ok {
			changes = append(changes, DiffChange{Category: "section", Name: name, Change: "removed", Before: sectionSummary(oldSection)})
			continue
		}
		if oldSection.Flags != newSection.Flags || oldSection.Size != newSection.Size || oldSection.Relocations != newSection.Relocations || oldSection.Alignment != newSection.Alignment || oldSection.Uninitialized != newSection.Uninitialized {
			changes = append(changes, DiffChange{Category: "section", Name: name, Change: "changed", Before: sectionSummary(oldSection), After: sectionSummary(newSection)})
		}
	}
	for name, section := range afterMap {
		if _, ok := beforeMap[name]; !ok {
			changes = append(changes, DiffChange{Category: "section", Name: name, Change: "added", After: sectionSummary(section)})
		}
	}
	return changes
}

func sectionSummary(section Section) string {
	return fmt.Sprintf("size=%d relocs=%d align=%d zero_fill=%t flags=%s", section.Size, section.Relocations, section.Alignment, section.Uninitialized, section.Flags)
}

func importKeys(imports []Import) map[string]string {
	out := map[string]string{}
	for _, imp := range imports {
		key := strings.Join([]string{imp.Category, imp.Symbol}, ":")
		out[key] = strings.TrimSpace(strings.Join([]string{imp.Library, imp.API}, " "))
	}
	return out
}

func findingKeys(findings []Finding) map[string]string {
	out := map[string]string{}
	for _, finding := range findings {
		key := strings.Join([]string{finding.Severity, finding.Category, finding.Evidence, finding.Detail, fmt.Sprintf("suppressed=%t", finding.Suppressed), finding.Suppression}, ":")
		out[key] = finding.Detail
	}
	return out
}

func capabilityKeys(capabilities []Capability) map[string]string {
	out := map[string]string{}
	for _, capability := range capabilities {
		key := capability.ID
		if key == "" {
			key = capability.Name
		}
		out[key] = fmt.Sprintf("confidence=%s effects=%s", capability.Confidence, strings.Join(capability.Effects, ","))
	}
	return out
}

func behaviorChainKeys(chains []BehaviorChain) map[string]string {
	out := map[string]string{}
	for _, chain := range chains {
		key := chain.ID + "@" + chain.Function
		steps := make([]string, 0, len(chain.Steps))
		for _, step := range chain.Steps {
			steps = append(steps, step.API)
		}
		out[key] = fmt.Sprintf("confidence=%s steps=%s effects=%s", chain.Confidence, strings.Join(steps, "->"), strings.Join(chain.Effects, ","))
	}
	return out
}

func stringSet(values []string) map[string]string {
	out := map[string]string{}
	for _, value := range values {
		out[value] = value
	}
	return out
}
