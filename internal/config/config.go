package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Project struct {
	Name           string
	Entrypoint     string
	BuildCommand   string
	Compiler       string
	CompilerSet    bool
	CFlags         []string
	Deterministic  bool
	Args           []string
	Expect         []string
	Forbid         []string
	TimeoutMS      int
	ExpectedExit   string
	ExpectedStatus string
	OperatorNotes  []string
	Profiles       map[string]TestProfile
}

type TestProfile struct {
	Entrypoint     string
	Args           []string
	ArgsSet        bool
	Expect         []string
	ExpectSet      bool
	Forbid         []string
	ForbidSet      bool
	TimeoutMS      int
	ExpectedExit   string
	ExpectedStatus string
	OperatorNotes  []string
}

type Diagnostic struct {
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
	Code   string `json:"code"`
	Key    string `json:"key,omitempty"`
	Detail string `json:"detail"`
}

type Error struct {
	Path        string       `json:"path"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func (e *Error) Error() string {
	if e == nil || len(e.Diagnostics) == 0 {
		return "invalid bofbench configuration"
	}
	first := e.Diagnostics[0]
	location := e.Path
	if first.Line > 0 {
		location += fmt.Sprintf(":%d", first.Line)
	}
	return fmt.Sprintf("%s: %s (%s; %d configuration error(s))", location, first.Detail, first.Code, len(e.Diagnostics))
}

func LoadFor(path string) (Project, string, error) {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	cfgPath := filepath.Join(dir, "bofbench.toml")
	cfg := Project{Entrypoint: "go", Compiler: "auto", Deterministic: true, TimeoutMS: 5000, Profiles: map[string]TestProfile{}}
	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, "", nil
		}
		return cfg, cfgPath, err
	}
	defer f.Close()

	var diagnostics []Diagnostic
	seen := map[string]int{}
	currentProfile := ""
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line, stripErr := stripInlineComment(scanner.Text())
		if stripErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "syntax", Detail: stripErr.Error()})
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "section_syntax", Detail: "section header is missing closing ]"})
				currentProfile = "!invalid"
				continue
			}
			section := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			currentProfile = profileName(section)
			if currentProfile == "" {
				diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "unknown_section", Detail: fmt.Sprintf("unsupported section %q; expected [profile.<name>]", section)})
				currentProfile = "!invalid"
				continue
			}
			if _, exists := cfg.Profiles[currentProfile]; exists {
				diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "duplicate_section", Detail: fmt.Sprintf("profile %q is declared more than once", currentProfile)})
			} else {
				cfg.Profiles[currentProfile] = TestProfile{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "assignment", Detail: "expected key = value assignment"})
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "assignment", Key: key, Detail: "configuration key and value must both be present"})
			continue
		}
		if currentProfile == "!invalid" {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "invalid_section_value", Key: key, Detail: "value belongs to an invalid section"})
			continue
		}
		scope := "root"
		canonical := canonicalKey(key)
		if currentProfile != "" {
			scope = "profile." + currentProfile
		}
		seenKey := scope + ":" + canonical
		if previous, duplicate := seen[seenKey]; duplicate {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: "duplicate_key", Key: key, Detail: fmt.Sprintf("key was already set on line %d", previous)})
			continue
		}
		seen[seenKey] = lineNumber
		var applyErr error
		if currentProfile != "" {
			profile := cfg.Profiles[currentProfile]
			applyErr = applyProfileValue(&profile, key, value)
			cfg.Profiles[currentProfile] = profile
		} else {
			applyErr = applyProjectValue(&cfg, key, value)
		}
		if applyErr != nil {
			diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Column: 1, Code: diagnosticCode(applyErr), Key: key, Detail: applyErr.Error()})
		}
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Line: lineNumber, Code: "read", Detail: err.Error()})
	}
	if len(diagnostics) > 0 {
		return cfg, cfgPath, &Error{Path: cfgPath, Diagnostics: diagnostics}
	}
	return cfg, cfgPath, nil
}

func ApplyProfile(cfg Project, name string) (Project, error) {
	if strings.TrimSpace(name) == "" {
		return cfg, nil
	}
	profile, ok := cfg.Profiles[name]
	if !ok {
		return cfg, fmt.Errorf("test profile %q not found", name)
	}
	if profile.Entrypoint != "" {
		cfg.Entrypoint = profile.Entrypoint
	}
	if profile.ArgsSet {
		cfg.Args = profile.Args
	}
	if profile.ExpectSet {
		cfg.Expect = profile.Expect
	}
	if profile.ForbidSet {
		cfg.Forbid = profile.Forbid
	}
	if profile.TimeoutMS > 0 {
		cfg.TimeoutMS = profile.TimeoutMS
	}
	if profile.ExpectedExit != "" {
		cfg.ExpectedExit = profile.ExpectedExit
	}
	if profile.ExpectedStatus != "" {
		cfg.ExpectedStatus = profile.ExpectedStatus
	}
	if len(profile.OperatorNotes) > 0 {
		cfg.OperatorNotes = profile.OperatorNotes
	}
	return cfg, nil
}

func applyProjectValue(cfg *Project, key, value string) error {
	switch canonicalKey(key) {
	case "name":
		parsed, err := parseQuotedString(value)
		if err == nil && !validProjectName(parsed) {
			err = valueError{fmt.Sprintf("name must contain only letters, numbers, dot, underscore, or hyphen and cannot start with a dot; got %q", parsed)}
		}
		cfg.Name = parsed
		return err
	case "entry":
		parsed, err := parseQuotedString(value)
		cfg.Entrypoint = parsed
		return err
	case "build":
		parsed, err := parseQuotedString(value)
		cfg.BuildCommand = parsed
		return err
	case "compiler":
		parsed, err := parseQuotedString(value)
		if err != nil {
			return err
		}
		parsed = strings.ToLower(parsed)
		if parsed != "auto" && parsed != "mingw" && parsed != "msvc" {
			return valueError{fmt.Sprintf("compiler must be auto, mingw, or msvc; got %q", parsed)}
		}
		cfg.Compiler = parsed
		cfg.CompilerSet = true
		return nil
	case "cflags":
		parsed, err := parseStringArray(value)
		cfg.CFlags = parsed
		return err
	case "deterministic":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return valueError{fmt.Sprintf("deterministic must be true or false; got %q", value)}
		}
		cfg.Deterministic = parsed
		return nil
	case "args":
		parsed, err := parseStringArray(value)
		cfg.Args = parsed
		return err
	case "expect":
		parsed, err := parseStringArray(value)
		cfg.Expect = parsed
		return err
	case "forbid":
		parsed, err := parseStringArray(value)
		cfg.Forbid = parsed
		return err
	case "timeout_ms":
		parsed, err := parsePositiveInt(value, "timeout_ms")
		cfg.TimeoutMS = parsed
		return err
	case "expect_exit":
		parsed, err := parseQuotedString(value)
		cfg.ExpectedExit = parsed
		return err
	case "expect_status":
		parsed, err := parseQuotedString(value)
		cfg.ExpectedStatus = parsed
		return err
	case "operator_notes":
		parsed, err := parseStringArray(value)
		cfg.OperatorNotes = parsed
		return err
	default:
		return unknownKeyError{fmt.Sprintf("unknown root configuration key %q", key)}
	}
}

func applyProfileValue(profile *TestProfile, key, value string) error {
	switch canonicalKey(key) {
	case "entry":
		parsed, err := parseQuotedString(value)
		profile.Entrypoint = parsed
		return err
	case "args":
		parsed, err := parseStringArray(value)
		profile.Args = parsed
		profile.ArgsSet = true
		return err
	case "expect":
		parsed, err := parseStringArray(value)
		profile.Expect = parsed
		profile.ExpectSet = true
		return err
	case "forbid":
		parsed, err := parseStringArray(value)
		profile.Forbid = parsed
		profile.ForbidSet = true
		return err
	case "timeout_ms":
		parsed, err := parsePositiveInt(value, "timeout_ms")
		profile.TimeoutMS = parsed
		return err
	case "expect_exit":
		parsed, err := parseQuotedString(value)
		profile.ExpectedExit = parsed
		return err
	case "expect_status":
		parsed, err := parseQuotedString(value)
		profile.ExpectedStatus = parsed
		return err
	case "operator_notes":
		parsed, err := parseStringArray(value)
		profile.OperatorNotes = parsed
		return err
	default:
		return unknownKeyError{fmt.Sprintf("unknown profile configuration key %q", key)}
	}
}

func canonicalKey(key string) string {
	switch strings.TrimSpace(key) {
	case "entry", "entrypoint":
		return "entry"
	case "forbid", "forbidden", "forbid_output":
		return "forbid"
	case "expect_exit", "expected_exit":
		return "expect_exit"
	case "expect_status", "expected_status":
		return "expect_status"
	default:
		return strings.TrimSpace(key)
	}
}

func validProjectName(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func profileName(section string) string {
	for _, prefix := range []string{"profile.", "profiles."} {
		if strings.HasPrefix(section, prefix) {
			name := strings.TrimSpace(strings.TrimPrefix(section, prefix))
			name = strings.Trim(name, `"'`)
			if name != "" && !strings.ContainsAny(name, " []") {
				return name
			}
		}
	}
	return ""
}

type unknownKeyError struct{ message string }

func (e unknownKeyError) Error() string { return e.message }

type valueError struct{ message string }

func (e valueError) Error() string { return e.message }

func diagnosticCode(err error) string {
	switch err.(type) {
	case unknownKeyError:
		return "unknown_key"
	case valueError:
		return "invalid_value"
	default:
		return "invalid_syntax"
	}
}

func parsePositiveInt(value, name string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0, valueError{fmt.Sprintf("%s must be a positive integer; got %q", name, value)}
	}
	return parsed, nil
}

func parseQuotedString(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || (value[0] != '"' && value[0] != '\'') || value[len(value)-1] != value[0] {
		return "", fmt.Errorf("expected quoted string, got %q", value)
	}
	if value[0] == '\'' {
		return value[1 : len(value)-1], nil
	}
	parsed, err := strconv.Unquote(value)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return parsed, nil
}

func parseStringArray(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return nil, fmt.Errorf("expected array of quoted strings, got %q", value)
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return nil, nil
	}
	var result []string
	for index := 0; index < len(inner); {
		for index < len(inner) && (inner[index] == ' ' || inner[index] == '\t') {
			index++
		}
		if index >= len(inner) || (inner[index] != '"' && inner[index] != '\'') {
			return nil, fmt.Errorf("array element at byte %d must be a quoted string", index+1)
		}
		quote := inner[index]
		start := index
		index++
		escaped := false
		for index < len(inner) {
			char := inner[index]
			if quote == '"' && char == '\\' && !escaped {
				escaped = true
				index++
				continue
			}
			if char == quote && !escaped {
				index++
				break
			}
			escaped = false
			index++
		}
		if index > len(inner) || inner[index-1] != quote {
			return nil, fmt.Errorf("unterminated quoted array element")
		}
		parsed, err := parseQuotedString(inner[start:index])
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
		for index < len(inner) && (inner[index] == ' ' || inner[index] == '\t') {
			index++
		}
		if index == len(inner) {
			break
		}
		if inner[index] != ',' {
			return nil, fmt.Errorf("expected comma after array element at byte %d", index+1)
		}
		index++
		if strings.TrimSpace(inner[index:]) == "" {
			return nil, fmt.Errorf("trailing comma is not supported")
		}
	}
	return result, nil
}

func stripInlineComment(line string) (string, error) {
	quote := byte(0)
	escaped := false
	for index := 0; index < len(line); index++ {
		char := line[index]
		if quote != 0 {
			if quote == '"' && char == '\\' && !escaped {
				escaped = true
				continue
			}
			if char == quote && !escaped {
				quote = 0
			}
			escaped = false
			continue
		}
		if char == '"' || char == '\'' {
			quote = char
			continue
		}
		if char == '#' {
			return line[:index], nil
		}
	}
	if quote != 0 {
		return line, fmt.Errorf("unterminated quoted string")
	}
	return line, nil
}
