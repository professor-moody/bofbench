package artifact

import (
	"strings"
	"testing"
)

func TestExplainAcceptsOperatorStyleHyphenatedID(t *testing.T) {
	analysis := Analysis{SHA256: "abc", WorksWith: []string{"lab", "sliver"}, BehaviorChains: []BehaviorChain{{ID: "token_impersonation", Name: "Token impersonation", Confidence: "strong chain", Function: "go", Effects: []string{"changes token context"}, Steps: []BehaviorStep{{Action: "open token", API: "openprocesstoken"}}}}}
	explanation, err := Explain(analysis, "token-impersonation")
	if err != nil || len(explanation.Chains) != 1 {
		t.Fatalf("explanation=%+v err=%v", explanation, err)
	}
	if text := ExplanationText(explanation); !strings.Contains(text, "Token impersonation") || !strings.Contains(text, "openprocesstoken") {
		t.Fatalf("text=%q", text)
	}
}
