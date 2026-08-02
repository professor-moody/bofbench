package stage

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/recipe"
)

const ArgumentSchema = "bofbench.stage-arguments"

type Options struct {
	Object           string
	Target           string
	OutputRoot       string
	Entrypoint       string
	Arguments        []argpack.Item
	ArgumentNames    []string
	ArgumentOptional []bool
	SourceInput      string
	Project          string
	Profile          string
	OperatorNotes    []string
	Recipe           *recipe.Document
	RecipeValidation *recipe.Validation
	Evidence         []EvidenceInput
}

type EvidenceInput struct {
	Kind        string
	Path        string
	Destination string
}

type EvidenceReference struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type PackedArguments struct {
	Format     string   `json:"format,omitempty"`
	Tokens     []string `json:"tokens,omitempty"`
	ByteLength int      `json:"byte_length"`
	SHA256     string   `json:"sha256"`
	Hex        string   `json:"hex,omitempty"`
}

type OperationalContract struct {
	Status        string   `json:"status"`
	Recipe        string   `json:"recipe,omitempty"`
	Title         string   `json:"title,omitempty"`
	Description   string   `json:"description,omitempty"`
	Category      string   `json:"category,omitempty"`
	Privilege     string   `json:"privilege"`
	Platforms     []string `json:"platforms"`
	Network       string   `json:"network"`
	Domain        string   `json:"domain"`
	Impact        string   `json:"impact"`
	Prerequisites []string `json:"prerequisites"`
	StateChanges  []string `json:"state_changes"`
	Artifacts     []string `json:"artifacts"`
	Cleanup       []string `json:"cleanup"`
	OperatorNotes []string `json:"operator_notes,omitempty"`
}

type TargetArgument struct {
	Position int    `json:"position"`
	Name     string `json:"name"`
	BOFKind  string `json:"bof_kind"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Example  string `json:"example,omitempty"`
}

type TargetContract struct {
	CommandName  string           `json:"command_name"`
	Install      []string         `json:"install"`
	Invoke       string           `json:"invoke"`
	Dependencies []string         `json:"dependencies,omitempty"`
	Arguments    []TargetArgument `json:"arguments,omitempty"`
}

type ArgumentEvidence struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Entrypoint    string          `json:"entrypoint"`
	Items         []argpack.Item  `json:"items,omitempty"`
	Names         []string        `json:"names,omitempty"`
	Optional      []bool          `json:"optional,omitempty"`
	Packed        PackedArguments `json:"packed"`
}

type SliverExtension struct {
	Name            string           `json:"name"`
	Version         string           `json:"version"`
	CommandName     string           `json:"command_name"`
	ExtensionAuthor string           `json:"extension_author"`
	OriginalAuthor  string           `json:"original_author"`
	RepositoryURL   string           `json:"repo_url"`
	Help            string           `json:"help"`
	LongHelp        string           `json:"long_help"`
	DependsOn       string           `json:"depends_on"`
	Entrypoint      string           `json:"entrypoint"`
	Files           []SliverFile     `json:"files"`
	Arguments       []SliverArgument `json:"arguments,omitempty"`
}

type SliverFile struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Path string `json:"path"`
}

type SliverArgument struct {
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Type     string `json:"type"`
	Optional bool   `json:"optional"`
}

func packedArgumentContract(items []argpack.Item) (PackedArguments, error) {
	packed, err := argpack.PackItems(items)
	if err != nil {
		return PackedArguments{}, err
	}
	hash := sha256.Sum256(packed)
	contract := PackedArguments{
		Format:     aggressorFormat(items),
		ByteLength: len(packed),
		SHA256:     fmt.Sprintf("%x", hash[:]),
		Hex:        argpack.Hex(packed),
	}
	for _, item := range items {
		contract.Tokens = append(contract.Tokens, item.Kind+":"+item.Value)
	}
	return contract, nil
}

func operationalContract(opts Options) OperationalContract {
	contract := OperationalContract{
		Status:        "incomplete",
		Privilege:     "unspecified",
		Platforms:     []string{"windows-x64"},
		Network:       "unspecified",
		Domain:        "unspecified",
		Impact:        "unspecified",
		Prerequisites: []string{"review the BOF source and environment before operator use"},
		StateChanges:  []string{"unspecified"},
		Artifacts:     []string{"BOF output and C2 task telemetry"},
		Cleanup:       []string{"unspecified"},
		OperatorNotes: append([]string(nil), opts.OperatorNotes...),
	}
	if opts.Recipe == nil {
		return contract
	}
	document := opts.Recipe
	contract.Recipe = document.Name
	contract.Title = document.Title
	contract.Description = document.Description
	contract.Category = document.Category
	contract.Privilege = document.Privilege
	contract.Platforms = append([]string(nil), document.Platforms...)
	contract.Network = document.Network
	contract.Domain = document.Domain
	contract.Impact = document.Impact
	contract.Prerequisites = append([]string(nil), document.Prerequisites...)
	contract.StateChanges = append([]string(nil), document.StateChanges...)
	contract.Artifacts = append([]string(nil), document.Artifacts...)
	contract.Cleanup = append([]string(nil), document.Cleanup...)
	contract.OperatorNotes = append(contract.OperatorNotes, document.OperatorNotes...)
	if opts.RecipeValidation != nil && opts.RecipeValidation.Status == "pass" {
		contract.Status = "complete"
	} else {
		contract.Status = "invalid"
	}
	contract.OperatorNotes = uniqueNonempty(contract.OperatorNotes)
	return contract
}

func targetContract(target, name, stagedObject, entrypoint string, items []argpack.Item, names []string, optional []bool, operations OperationalContract) TargetContract {
	command := safeAlias(name)
	contract := TargetContract{CommandName: command, Arguments: targetArguments(items, names, optional)}
	switch target {
	case "cobaltstrike":
		contract.Install = []string{"Cobalt Strike > Script Manager > Load: " + name + ".cna"}
		contract.Invoke = command + targetValues(items)
	case "sliver":
		contract.Install = []string{"armory install coff-loader", "extensions load ."}
		contract.Invoke = command + targetValues(items)
		contract.Dependencies = []string{"coff-loader"}
	case "raw":
		contract.Install = []string{"place bofbench and its Windows COFF loader on the operator host"}
		contract.Invoke = "bofbench run " + stagedObject + " --runtime windows-coff --entry " + commandQuote(entrypoint)
		if len(items) > 0 {
			contract.Invoke += " --args"
			for _, item := range items {
				contract.Invoke += " " + commandQuote(item.Kind+":"+item.Value)
			}
		}
	}
	if operations.Description != "" && target == "raw" {
		contract.Install = append(contract.Install, operations.Description)
	}
	return contract
}

func targetArguments(items []argpack.Item, names []string, optional []bool) []TargetArgument {
	if len(items) == 0 {
		return nil
	}
	result := make([]TargetArgument, 0, len(items))
	for index, item := range items {
		name := fmt.Sprintf("arg%d", index+1)
		if index < len(names) && strings.TrimSpace(names[index]) != "" {
			name = safeAlias(names[index])
		}
		required := true
		if index < len(optional) {
			required = !optional[index]
		}
		result = append(result, TargetArgument{
			Position: index + 1,
			Name:     name,
			BOFKind:  item.Kind,
			Type:     targetArgumentType(item.Kind),
			Required: required,
			Example:  targetArgumentExample(item),
		})
	}
	return result
}

func targetArgumentType(kind string) string {
	switch kind {
	case "z":
		return "string"
	case "Z":
		return "wstring"
	case "i":
		return "int"
	case "s":
		return "short"
	case "b", "x":
		return "file"
	default:
		return "unknown"
	}
}

func targetArgumentExample(item argpack.Item) string {
	if item.Kind == "b" || item.Kind == "x" {
		return "<path-to-binary-data>"
	}
	return item.Value
}

func targetValues(items []argpack.Item) string {
	var b strings.Builder
	for _, item := range items {
		b.WriteByte(' ')
		b.WriteString(commandQuote(targetArgumentExample(item)))
	}
	return b.String()
}

func commandQuote(value string) string {
	if value == "" {
		return `""`
	}
	if !strings.ContainsAny(value, " \t\r\n\"'") {
		return value
	}
	return strconv.Quote(value)
}

func sliverExtension(manifest Manifest, objectFile string) SliverExtension {
	help := manifest.Operations.Description
	if help == "" {
		help = "Execute the " + manifest.Name + " Beacon Object File"
	}
	longHelp := fmt.Sprintf("Entrypoint: %s. Privilege: %s. Network: %s. Effects: %s. See README.md for requirements and cleanup.", manifest.Entrypoint, manifest.Operations.Privilege, manifest.Operations.Network, manifest.Operations.Impact)
	arch := "amd64"
	if strings.Contains(strings.ToLower(filepath.Base(manifest.Object)), ".x86.") {
		arch = "386"
	}
	extension := SliverExtension{
		Name: manifest.Name, Version: "1.0.0", CommandName: manifest.TargetContract.CommandName,
		ExtensionAuthor: "bofbench", OriginalAuthor: "bofbench project", RepositoryURL: "N/A",
		Help: help, LongHelp: longHelp, DependsOn: "coff-loader", Entrypoint: manifest.Entrypoint,
		Files: []SliverFile{{OS: "windows", Arch: arch, Path: objectFile}},
	}
	for _, argument := range manifest.TargetContract.Arguments {
		extension.Arguments = append(extension.Arguments, SliverArgument{
			Name: argument.Name, Desc: fmt.Sprintf("BOF argument %d (%s)", argument.Position, argument.BOFKind), Type: argument.Type, Optional: !argument.Required,
		})
	}
	return extension
}

func uniqueNonempty(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func fingerprintForManifest(path string) (evidence.FileFingerprint, error) {
	fingerprint, err := evidence.FingerprintFile(path)
	if err != nil {
		return evidence.FileFingerprint{}, err
	}
	fingerprint.Path = path
	return fingerprint, nil
}
