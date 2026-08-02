package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/professor-moody/bofbench/internal/artifact"
	packsvc "github.com/professor-moody/bofbench/internal/pack"
)

func applyProjectPackMetadata(analysis *artifact.Analysis, project string) error {
	lock, lockPath, err := packsvc.LoadLock(project)
	if err != nil {
		return err
	}
	if len(lock.Packs) == 0 {
		return nil
	}
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		return err
	}
	argumentNames := map[string]bool{}
	capabilityNames := map[string]bool{}
	for _, capability := range analysis.Capabilities {
		capabilityNames[strings.ToLower(capability.ID)] = true
		capabilityNames[strings.ToLower(capability.Name)] = true
	}
	var targetIntersection []string
	var lockedItems []packsvc.Resolved
	for _, record := range lock.Packs {
		for _, argument := range record.Arguments {
			key := strings.ToLower(argument.Name)
			if argumentNames[key] {
				continue
			}
			argumentNames[key] = true
			analysis.Arguments = append(analysis.Arguments, artifact.ArgumentHint{Name: argument.Name, Type: argument.Type, Required: argument.Required && argument.Default == "", Source: fmt.Sprintf("%s:%s", lockPath, record.Qualified)})
		}
		resolved, resolveErr := registry.Resolve(record.Qualified)
		if resolveErr != nil {
			// Legacy recipe lock records remain readable even when they do not
			// correspond to a current pack catalog entry.
			if record.Catalog == "recipe" {
				continue
			}
			return resolveErr
		}
		lockedItems = append(lockedItems, resolved)
		for _, capability := range resolved.Document.Capabilities {
			key := strings.ToLower(capability)
			if capabilityNames[key] {
				continue
			}
			capabilityNames[key] = true
			analysis.Capabilities = append(analysis.Capabilities, artifact.Capability{ID: capabilityID(capability), Name: capability, Summary: "Declared by the resolved capability pack and tied to the locked source hash.", Inference: "pack metadata", Confidence: "possible", Effects: append([]string(nil), resolved.Document.Effects...), Evidence: []string{record.Qualified + "@" + record.Version + " sha256=" + record.SHA256}})
		}
		analysis.Effects = appendUniqueStrings(analysis.Effects, resolved.Document.Effects...)
		if value := strings.TrimSpace(resolved.Document.Privilege); value != "" && value != "user" {
			analysis.Requirements.Privilege = appendUniqueStrings(analysis.Requirements.Privilege, value)
		}
		if value := strings.TrimSpace(resolved.Document.Network); value != "" && value != "none" {
			analysis.Requirements.Network = appendUniqueStrings(analysis.Requirements.Network, value)
		}
		if targetIntersection == nil {
			targetIntersection = append([]string(nil), resolved.Document.TargetSupport...)
		} else {
			targetIntersection = intersectStrings(targetIntersection, resolved.Document.TargetSupport)
		}
	}
	if targetIntersection != nil {
		analysis.WorksWith = intersectStrings(analysis.WorksWith, targetIntersection)
	}
	artifact.ApplyDeclarativeSignatures(analysis, declarativeSignatures(lockedItems))
	return nil
}

func applyConfiguredSignatures(analysis *artifact.Analysis, project string) error {
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		return err
	}
	artifact.ApplyDeclarativeSignatures(analysis, declarativeSignatures(registry.List()))
	return nil
}

func declarativeSignatures(items []packsvc.Resolved) []artifact.DeclarativeSignature {
	type candidate struct {
		item       packsvc.Resolved
		signature  packsvc.AnalysisSignature
		definition string
	}
	var candidates []candidate
	definitions := map[string]map[string]bool{}
	for _, item := range items {
		for _, signature := range item.Document.AnalysisSignatures {
			data, _ := json.Marshal(signature)
			definition := string(data)
			if definitions[signature.ID] == nil {
				definitions[signature.ID] = map[string]bool{}
			}
			definitions[signature.ID][definition] = true
			candidates = append(candidates, candidate{item: item, signature: signature, definition: definition})
		}
	}
	seen := map[string]bool{}
	var result []artifact.DeclarativeSignature
	for _, candidate := range candidates {
		id := candidate.signature.ID
		if len(definitions[id]) > 1 {
			id = candidate.item.Catalog + "/" + id
		}
		key := id + "\x00" + candidate.definition
		if seen[key] {
			continue
		}
		seen[key] = true
		converted := artifact.DeclarativeSignature{
			ID: id, Name: candidate.signature.Name, Summary: candidate.signature.Summary, Catalog: candidate.item.Catalog,
			RequiredStrings: append([]string(nil), candidate.signature.RequiredStrings...),
			Effects:         append([]string(nil), candidate.signature.Effects...), Requirements: append([]string(nil), candidate.signature.Requirements...),
		}
		for _, step := range candidate.signature.Steps {
			converted.Steps = append(converted.Steps, artifact.DeclarativeSignatureStep{Action: step.Action, APIs: append([]string(nil), step.APIs...)})
		}
		result = append(result, converted)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func capabilityID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	lastDash := false
	for _, runeValue := range value {
		if runeValue >= 'a' && runeValue <= 'z' || runeValue >= '0' && runeValue <= '9' {
			out.WriteRune(runeValue)
			lastDash = false
		} else if !lastDash && out.Len() > 0 {
			out.WriteByte('_')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "_")
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value = strings.TrimSpace(value); value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

func intersectStrings(left, right []string) []string {
	rightSet := map[string]bool{}
	for _, value := range right {
		rightSet[value] = true
	}
	var result []string
	for _, value := range left {
		if rightSet[value] {
			result = append(result, value)
		}
	}
	return result
}
