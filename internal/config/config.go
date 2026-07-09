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

func LoadFor(path string) (Project, string, error) {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	cfgPath := filepath.Join(dir, "bofbench.toml")
	cfg := Project{Entrypoint: "go", TimeoutMS: 5000, Profiles: map[string]TestProfile{}}
	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, "", nil
		}
		return cfg, cfgPath, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	currentProfile := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			currentProfile = profileName(section)
			if currentProfile != "" {
				if cfg.Profiles == nil {
					cfg.Profiles = map[string]TestProfile{}
				}
				if _, ok := cfg.Profiles[currentProfile]; !ok {
					cfg.Profiles[currentProfile] = TestProfile{}
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if currentProfile != "" {
			profile := cfg.Profiles[currentProfile]
			applyProfileValue(&profile, key, value)
			cfg.Profiles[currentProfile] = profile
			continue
		}
		switch key {
		case "name":
			cfg.Name = parseString(value)
		case "entry", "entrypoint":
			cfg.Entrypoint = parseString(value)
		case "build":
			cfg.BuildCommand = parseString(value)
		case "args":
			cfg.Args = parseArray(value)
		case "expect":
			cfg.Expect = parseArray(value)
		case "forbid", "forbidden", "forbid_output":
			cfg.Forbid = parseArray(value)
		case "timeout_ms":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.TimeoutMS = n
			}
		case "expect_exit", "expected_exit":
			cfg.ExpectedExit = parseString(value)
		case "expect_status", "expected_status":
			cfg.ExpectedStatus = parseString(value)
		case "operator_notes":
			cfg.OperatorNotes = parseArray(value)
		}
	}
	return cfg, cfgPath, scanner.Err()
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

func applyProfileValue(profile *TestProfile, key, value string) {
	switch key {
	case "entry", "entrypoint":
		profile.Entrypoint = parseString(value)
	case "args":
		profile.Args = parseArray(value)
		profile.ArgsSet = true
	case "expect":
		profile.Expect = parseArray(value)
		profile.ExpectSet = true
	case "forbid", "forbidden", "forbid_output":
		profile.Forbid = parseArray(value)
		profile.ForbidSet = true
	case "timeout_ms":
		if n, err := strconv.Atoi(value); err == nil {
			profile.TimeoutMS = n
		}
	case "expect_exit", "expected_exit":
		profile.ExpectedExit = parseString(value)
	case "expect_status", "expected_status":
		profile.ExpectedStatus = parseString(value)
	case "operator_notes":
		profile.OperatorNotes = parseArray(value)
	}
}

func profileName(section string) string {
	for _, prefix := range []string{"profile.", "profiles."} {
		if strings.HasPrefix(section, prefix) {
			name := strings.TrimSpace(strings.TrimPrefix(section, prefix))
			return strings.Trim(name, `"'`)
		}
	}
	return ""
}

func parseString(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return value
}

func parseArray(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		out = append(out, parseString(part))
	}
	return out
}
