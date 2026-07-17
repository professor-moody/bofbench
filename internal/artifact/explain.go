package artifact

import (
	"fmt"
	"sort"
	"strings"
)

// Explanation is a focused view over the complete analysis report. The full
// report remains persisted; this view answers one operator capability question
// without forcing the user to read loader and structural sections first.
type Explanation struct {
	Query         string          `json:"query"`
	Capability    *Capability     `json:"capability,omitempty"`
	Chains        []BehaviorChain `json:"behavior_chains,omitempty"`
	ResourceFlows []ResourceFlow  `json:"resource_flows,omitempty"`
	ObjectSHA256  string          `json:"object_sha256"`
	WorksWith     []string        `json:"works_with,omitempty"`
}

func Explain(analysis Analysis, query string) (Explanation, error) {
	normalized := normalizeExplanationID(query)
	explanation := Explanation{Query: query, ObjectSHA256: analysis.SHA256, WorksWith: append([]string(nil), analysis.WorksWith...)}
	for index := range analysis.Capabilities {
		candidate := analysis.Capabilities[index]
		if normalizeExplanationID(candidate.ID) == normalized || normalizeExplanationID(candidate.Name) == normalized {
			explanation.Capability = &candidate
			break
		}
	}
	for _, chain := range analysis.BehaviorChains {
		if normalizeExplanationID(chain.ID) == normalized || normalizeExplanationID(chain.Name) == normalized {
			explanation.Chains = append(explanation.Chains, chain)
		}
	}
	for _, flow := range analysis.ResourceFlows {
		if normalizeExplanationID(flow.ID) == normalized || strings.HasPrefix(normalizeExplanationID(flow.ID), normalized+"_") {
			explanation.ResourceFlows = append(explanation.ResourceFlows, flow)
		}
	}
	if explanation.Capability == nil && len(explanation.Chains) == 0 {
		available := make([]string, 0, len(analysis.Capabilities)+len(analysis.BehaviorChains))
		for _, capability := range analysis.Capabilities {
			available = append(available, capability.ID)
		}
		for _, chain := range analysis.BehaviorChains {
			available = append(available, chain.ID)
		}
		sort.Strings(available)
		return Explanation{}, fmt.Errorf("capability %q was not inferred; available: %s", query, strings.Join(uniqueStrings(available), ", "))
	}
	return explanation, nil
}

func ExplanationText(explanation Explanation) string {
	var body strings.Builder
	fmt.Fprintf(&body, "CAPABILITY EXPLANATION\nquery       %s\nobject      %s\n", explanation.Query, explanation.ObjectSHA256)
	if explanation.Capability != nil {
		fmt.Fprintf(&body, "can do      %s\nconfidence  %s\neffects     %s\n", explanation.Capability.Summary, explanation.Capability.Confidence, strings.Join(explanation.Capability.Effects, ", "))
	}
	for _, chain := range explanation.Chains {
		fmt.Fprintf(&body, "chain       %s (%s)\n", chain.Name, chain.Confidence)
		if chain.Interprocedural {
			fmt.Fprintf(&body, "functions   %s\n", strings.Join(chain.EvidenceFunctions, " -> "))
		} else {
			fmt.Fprintf(&body, "function    %s\n", chain.Function)
		}
		for _, step := range chain.Steps {
			fmt.Fprintf(&body, "  %-25s %s [%s]\n", step.Action, step.API, step.Evidence)
		}
	}
	for _, flow := range explanation.ResourceFlows {
		fmt.Fprintf(&body, "flow        %s: %s -> %s (%s)\n", flow.Resource, flow.ProducerFunction, strings.Join(flow.ConsumerFunctions, ", "), flow.Confidence)
	}
	fmt.Fprintf(&body, "works with  %s\n", strings.Join(explanation.WorksWith, ", "))
	return body.String()
}

func ExplanationMarkdown(explanation Explanation) string {
	var body strings.Builder
	fmt.Fprintf(&body, "# Capability Explanation: %s\n\n- Object SHA-256: `%s`\n- Works with: `%s`\n\n", explanation.Query, explanation.ObjectSHA256, strings.Join(explanation.WorksWith, ", "))
	if explanation.Capability != nil {
		fmt.Fprintf(&body, "## Can do\n\n%s\n\n- Confidence: `%s`\n- Effects: `%s`\n\n", explanation.Capability.Summary, explanation.Capability.Confidence, strings.Join(explanation.Capability.Effects, ", "))
	}
	for _, chain := range explanation.Chains {
		fmt.Fprintf(&body, "## %s\n\n%s\n\n- Confidence: `%s`\n", chain.Name, chain.Summary, chain.Confidence)
		if chain.Interprocedural {
			fmt.Fprintf(&body, "- Evidence functions: `%s`\n", strings.Join(chain.EvidenceFunctions, ", "))
		} else {
			fmt.Fprintf(&body, "- Function: `%s`\n", chain.Function)
		}
		body.WriteString("\n")
		for _, step := range chain.Steps {
			fmt.Fprintf(&body, "1. %s — `%s` (`%s`)\n", step.Action, step.API, step.Evidence)
		}
		body.WriteString("\n")
	}
	return body.String()
}

func normalizeExplanationID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("-", "_", " ", "_", "/", "_").Replace(value)
	return strings.Trim(value, "_")
}
