package arsenal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type CapabilityGraph struct {
	Schema          string                `json:"schema"`
	SchemaVersion   int                   `json:"schema_version"`
	AnalysisVersion int                   `json:"analysis_version"`
	Root            string                `json:"root"`
	Capability      string                `json:"capability,omitempty"`
	GeneratedAt     string                `json:"generated_at"`
	Nodes           []CapabilityGraphNode `json:"nodes"`
	Edges           []CapabilityGraphEdge `json:"edges"`
}

type CapabilityGraphNode struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Arch   string `json:"arch,omitempty"`
	Path   string `json:"path,omitempty"`
	Loader string `json:"loader,omitempty"`
}

type CapabilityGraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

func BuildCapabilityGraph(inventory Inventory, capability string) CapabilityGraph {
	report := CapabilityGraph{Schema: "bofbench.arsenal-graph", SchemaVersion: 1, AnalysisVersion: 3, Root: inventory.Root, Capability: capability, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	nodes := map[string]CapabilityGraphNode{}
	edges := map[string]CapabilityGraphEdge{}
	needle := strings.ToLower(strings.TrimSpace(capability))
	for _, entry := range inventory.Entries {
		for _, architecture := range entry.Architectures {
			objectID := "object:" + entry.Name + ":" + architecture.Arch
			matchedObject := needle == ""
			for _, value := range append(append([]string{}, architecture.Capabilities...), architecture.BehaviorChains...) {
				if needle != "" && !strings.Contains(strings.ToLower(value), needle) {
					continue
				}
				matchedObject = true
				capabilityID := "capability:" + graphID(value)
				nodes[capabilityID] = CapabilityGraphNode{ID: capabilityID, Kind: "capability", Label: value}
				edge := CapabilityGraphEdge{From: objectID, To: capabilityID, Kind: "can-do"}
				edges[edge.From+"\x00"+edge.To] = edge
			}
			if matchedObject {
				nodes[objectID] = CapabilityGraphNode{ID: objectID, Kind: "object", Label: entry.Name + " (" + architecture.Arch + ")", Arch: architecture.Arch, Path: architecture.Path, Loader: architecture.Compatibility}
			}
		}
	}
	for _, node := range nodes {
		report.Nodes = append(report.Nodes, node)
	}
	for _, edge := range edges {
		if nodes[edge.From].ID != "" && nodes[edge.To].ID != "" {
			report.Edges = append(report.Edges, edge)
		}
	}
	sort.Slice(report.Nodes, func(i, j int) bool { return report.Nodes[i].ID < report.Nodes[j].ID })
	sort.Slice(report.Edges, func(i, j int) bool {
		if report.Edges[i].From != report.Edges[j].From {
			return report.Edges[i].From < report.Edges[j].From
		}
		return report.Edges[i].To < report.Edges[j].To
	})
	return report
}

func CapabilityGraphText(report CapabilityGraph) string {
	var body strings.Builder
	fmt.Fprintf(&body, "ARSENAL CAPABILITY GRAPH\nroot        %s\ncapability  %s\nobjects     %d\nrelations   %d\n", report.Root, report.Capability, countGraphNodes(report.Nodes, "object"), len(report.Edges))
	labels := map[string]string{}
	for _, node := range report.Nodes {
		labels[node.ID] = node.Label
	}
	for _, edge := range report.Edges {
		fmt.Fprintf(&body, "  %s -> %s\n", labels[edge.From], labels[edge.To])
	}
	return body.String()
}

func CapabilityGraphMermaid(report CapabilityGraph) string {
	var body strings.Builder
	body.WriteString("flowchart LR\n")
	ids := map[string]string{}
	for index, node := range report.Nodes {
		id := fmt.Sprintf("n%d", index+1)
		ids[node.ID] = id
		fmt.Fprintf(&body, "  %s[\"%s\"]\n", id, strings.ReplaceAll(node.Label, "\"", "'"))
	}
	for _, edge := range report.Edges {
		fmt.Fprintf(&body, "  %s -->|%s| %s\n", ids[edge.From], edge.Kind, ids[edge.To])
	}
	return body.String()
}

func CapabilityGraphJSON(report CapabilityGraph) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func graphID(value string) string {
	value = strings.ToLower(value)
	var body strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			body.WriteRune(char)
		} else if body.Len() > 0 && !strings.HasSuffix(body.String(), "-") {
			body.WriteByte('-')
		}
	}
	return strings.Trim(body.String(), "-")
}

func countGraphNodes(nodes []CapabilityGraphNode, kind string) int {
	count := 0
	for _, node := range nodes {
		if node.Kind == kind {
			count++
		}
	}
	return count
}
