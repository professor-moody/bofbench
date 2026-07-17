package runtimecomparison

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"bofbench/internal/pack"
)

const (
	Schema        = "bofbench.runtime-comparison"
	SchemaVersion = 1
)

type RuntimeResult struct {
	Runtime        string            `json:"runtime"`
	Status         string            `json:"status"`
	ReceiptPath    string            `json:"receipt_path,omitempty"`
	ObjectSHA256   string            `json:"object_sha256,omitempty"`
	ObjectHashes   map[string]string `json:"object_hashes,omitempty"`
	OutputComplete bool              `json:"output_complete"`
	Output         []string          `json:"-"`
	Error          string            `json:"error,omitempty"`
}

type FieldResult struct {
	Tag        string            `json:"tag"`
	Field      string            `json:"field"`
	Behavior   string            `json:"behavior"`
	Normalizer string            `json:"normalizer,omitempty"`
	Values     map[string]string `json:"values,omitempty"`
	Match      bool              `json:"match"`
	Detail     string            `json:"detail,omitempty"`
}

type Receipt struct {
	Schema          string          `json:"schema"`
	SchemaVersion   int             `json:"schema_version"`
	RunID           string          `json:"run_id"`
	Subject         string          `json:"subject"`
	SubjectKind     string          `json:"subject_kind"`
	Status          string          `json:"status"`
	ObjectSHA256    string          `json:"object_sha256,omitempty"`
	ExactObject     bool            `json:"exact_object"`
	Results         []RuntimeResult `json:"results"`
	Fields          []FieldResult   `json:"fields,omitempty"`
	StartedAt       string          `json:"started_at"`
	CompletedAt     string          `json:"completed_at"`
	ReceiptPath     string          `json:"receipt_path,omitempty"`
	ComparisonNotes []string        `json:"comparison_notes,omitempty"`
}

func Compare(subject, kind, runID string, results []RuntimeResult, contracts []pack.ComparisonContract, started time.Time) Receipt {
	receipt := Receipt{Schema: Schema, SchemaVersion: SchemaVersion, RunID: runID, Subject: subject, SubjectKind: kind, Status: "incomplete", Results: results, StartedAt: started.UTC().Format(time.RFC3339Nano), CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	complete := make([]RuntimeResult, 0, len(results))
	hash := ""
	receipt.ExactObject = true
	for _, result := range results {
		if result.Status != "completed" || !result.OutputComplete {
			continue
		}
		complete = append(complete, result)
		if result.ObjectSHA256 == "" {
			receipt.ExactObject = false
		} else if hash == "" {
			hash = strings.ToLower(result.ObjectSHA256)
		} else if !strings.EqualFold(hash, result.ObjectSHA256) {
			receipt.ExactObject = false
		}
	}
	receipt.ObjectSHA256 = hash
	if len(complete) < 2 {
		receipt.ComparisonNotes = append(receipt.ComparisonNotes, "at least two completed runtime results are required")
		return receipt
	}
	if !receipt.ExactObject {
		receipt.Status = "failed"
		receipt.ComparisonNotes = append(receipt.ComparisonNotes, "completed runtimes did not report the same exact object hash")
		return receipt
	}
	if len(contracts) == 0 {
		contracts = defaultContracts(complete)
		receipt.ComparisonNotes = append(receipt.ComparisonNotes, "no pack comparison contract was declared; compared terminal status fields and tag presence")
	}
	allMatch := true
	for _, contract := range contracts {
		for _, field := range contract.Fields {
			comparison := compareField(complete, contract.Tag, field)
			receipt.Fields = append(receipt.Fields, comparison)
			allMatch = allMatch && comparison.Match
		}
	}
	if allMatch {
		receipt.Status = "pass"
	} else {
		receipt.Status = "different"
	}
	return receipt
}

func defaultContracts(results []RuntimeResult) []pack.ComparisonContract {
	tags := map[string]int{}
	status := map[string]bool{}
	for _, result := range results {
		seen := map[string]bool{}
		for _, line := range result.Output {
			tag, fields := ParseStructuredLine(line)
			if tag == "" {
				continue
			}
			seen[tag] = true
			if fields["status"] != "" {
				status[tag] = true
			}
		}
		for tag := range seen {
			tags[tag]++
		}
	}
	var contracts []pack.ComparisonContract
	for tag, count := range tags {
		if count != len(results) {
			continue
		}
		behavior := "presence"
		if status[tag] {
			behavior = "exact"
		}
		contracts = append(contracts, pack.ComparisonContract{Tag: tag, Fields: []pack.ComparisonField{{Name: "status", Behavior: behavior}}})
	}
	sort.Slice(contracts, func(i, j int) bool { return contracts[i].Tag < contracts[j].Tag })
	return contracts
}

func compareField(results []RuntimeResult, tag string, field pack.ComparisonField) FieldResult {
	comparison := FieldResult{Tag: tag, Field: field.Name, Behavior: field.Behavior, Normalizer: field.Normalizer, Values: map[string]string{}, Match: true}
	canonical := ""
	for _, result := range results {
		value, present := terminalField(result.Output, tag, field.Name)
		if field.Behavior == "ignore" {
			continue
		}
		if field.Behavior == "presence" {
			value = strconv.FormatBool(present)
		} else if !present {
			comparison.Match = false
			value = "<missing>"
		}
		if field.Behavior == "normalized" {
			value = normalize(value, field.Normalizer)
		}
		if field.Behavior == "payload_hash" && present && !looksLikeSHA256(value) {
			sum := sha256.Sum256([]byte(value))
			value = hex.EncodeToString(sum[:])
		}
		comparison.Values[result.Runtime] = value
		if canonical == "" {
			canonical = value
		} else if canonical != value {
			comparison.Match = false
		}
	}
	if field.Behavior == "ignore" {
		comparison.Detail = "volatile field intentionally ignored"
	}
	return comparison
}

func terminalField(lines []string, tag, field string) (string, bool) {
	for index := len(lines) - 1; index >= 0; index-- {
		lineTag, fields := ParseStructuredLine(lines[index])
		if lineTag == tag {
			value, ok := fields[field]
			return value, ok
		}
	}
	return "", false
}

func ParseStructuredLine(line string) (string, map[string]string) {
	line = strings.TrimSpace(line)
	fields := map[string]string{}
	if !strings.HasPrefix(line, "[") {
		return "", fields
	}
	end := strings.IndexByte(line, ']')
	if end < 2 {
		return "", fields
	}
	for _, token := range strings.Fields(line[end+1:]) {
		name, value, ok := strings.Cut(token, "=")
		if ok && name != "" {
			fields[name] = strings.Trim(value, `"`)
		}
	}
	return line[1:end], fields
}

func normalize(value, normalizer string) string {
	value = strings.TrimSpace(value)
	switch normalizer {
	case "lowercase":
		return strings.ToLower(value)
	case "trim":
		return value
	case "path":
		return strings.ToLower(filepath.ToSlash(value))
	case "hostname":
		return strings.TrimSuffix(strings.ToLower(value), ".")
	case "integer":
		parsed, err := strconv.ParseInt(value, 0, 64)
		if err == nil {
			return strconv.FormatInt(parsed, 10)
		}
	case "hex":
		value = strings.TrimPrefix(strings.ToLower(value), "0x")
		value = strings.TrimLeft(value, "0")
		if value == "" {
			return "0"
		}
		return value
	}
	return value
}

func looksLikeSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func Text(receipt Receipt) string {
	var body strings.Builder
	fmt.Fprintf(&body, "RUNTIME COMPARISON %s\nsubject     %s\nkind        %s\nexact hash  %t", strings.ToUpper(receipt.Status), receipt.Subject, receipt.SubjectKind, receipt.ExactObject)
	if receipt.ObjectSHA256 != "" {
		fmt.Fprintf(&body, " (%s)", receipt.ObjectSHA256)
	}
	body.WriteByte('\n')
	for _, result := range receipt.Results {
		fmt.Fprintf(&body, "%-11s %-11s complete=%-5t %s\n", result.Runtime, result.Status, result.OutputComplete, result.Error)
	}
	for _, field := range receipt.Fields {
		state := "different"
		if field.Match {
			state = "match"
		}
		fmt.Fprintf(&body, "%-11s [%s] %s (%s)\n", state, field.Tag, field.Field, field.Behavior)
	}
	for _, note := range receipt.ComparisonNotes {
		fmt.Fprintf(&body, "note        %s\n", note)
	}
	if receipt.ReceiptPath != "" {
		fmt.Fprintf(&body, "receipt     %s\n", receipt.ReceiptPath)
	}
	return body.String()
}
