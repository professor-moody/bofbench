package app

import (
	"fmt"
	"strings"

	"bofbench/internal/artifact"
	packsvc "bofbench/internal/pack"
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
	return nil
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
