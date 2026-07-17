package runtimecontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"bofbench/internal/lab"
)

const (
	Schema        = "bofbench.runtime-controls"
	SchemaVersion = 1
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Control describes one runtime control plane without storing credentials.
// Provider authentication is resolved through the referenced preparation file.
type Control struct {
	Runtime      string `json:"runtime"`
	Provider     string `json:"provider"`
	ProxmoxPrep  string `json:"proxmox_preparation"`
	VMID         int    `json:"vmid"`
	TemplateVMID int    `json:"template_vmid,omitempty"`
	CloneMode    string `json:"clone_mode,omitempty"`
	Name         string `json:"guest_name,omitempty"`
}

type Config struct {
	Schema        string             `json:"schema"`
	SchemaVersion int                `json:"schema_version"`
	Active        string             `json:"active,omitempty"`
	Controls      map[string]Control `json:"controls"`
	UpdatedAt     string             `json:"updated_at,omitempty"`
}

func NewConfig() Config {
	return Config{Schema: Schema, SchemaVersion: SchemaVersion, Controls: map[string]Control{}}
}

func Path() string {
	root := strings.TrimSpace(os.Getenv("BOFBENCH_CONFIG_HOME"))
	if root == "" {
		var err error
		root, err = os.UserConfigDir()
		if err != nil || strings.TrimSpace(root) == "" {
			root = "."
		}
		root = filepath.Join(root, "bofbench")
	}
	return filepath.Join(root, "runtime-controls.json")
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		path = Path()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewConfig(), nil
	}
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := Validate(config); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

func Save(path string, config Config) error {
	if strings.TrimSpace(path) == "" {
		path = Path()
	}
	if config.Controls == nil {
		config.Controls = map[string]Control{}
	}
	config.Schema = Schema
	config.SchemaVersion = SchemaVersion
	config.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := Validate(config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runtime-controls-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func Validate(config Config) error {
	if config.Schema != Schema || config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema must be %s version %d", Schema, SchemaVersion)
	}
	if config.Controls == nil {
		return fmt.Errorf("controls must be an object")
	}
	for name, control := range config.Controls {
		if !validName.MatchString(name) {
			return fmt.Errorf("invalid runtime control name %q", name)
		}
		if err := ValidateControl(control); err != nil {
			return fmt.Errorf("control %s: %w", name, err)
		}
	}
	if config.Active != "" {
		if _, ok := config.Controls[config.Active]; !ok {
			return fmt.Errorf("active runtime control %q does not exist", config.Active)
		}
	}
	return nil
}

func ValidateControl(control Control) error {
	control.Runtime = strings.ToLower(strings.TrimSpace(control.Runtime))
	if control.Runtime != "sliver" && control.Runtime != "cobaltstrike" {
		return fmt.Errorf("runtime must be sliver or cobaltstrike")
	}
	if strings.ToLower(strings.TrimSpace(control.Provider)) != "proxmox" {
		return fmt.Errorf("provider must be proxmox")
	}
	if strings.TrimSpace(control.ProxmoxPrep) == "" {
		return fmt.Errorf("proxmox preparation file is required")
	}
	if control.VMID < 1 {
		return fmt.Errorf("vmid must be positive")
	}
	if control.TemplateVMID < 0 {
		return fmt.Errorf("template vmid cannot be negative")
	}
	mode := strings.ToLower(strings.TrimSpace(control.CloneMode))
	if mode != "" && mode != "full" && mode != "linked" {
		return fmt.Errorf("clone mode must be full or linked")
	}
	if control.Name != "" && !validName.MatchString(control.Name) {
		return fmt.Errorf("invalid guest name %q", control.Name)
	}
	return nil
}

func Add(config *Config, name string, control Control, replace bool) error {
	if config == nil {
		return fmt.Errorf("runtime control config is nil")
	}
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid runtime control name %q", name)
	}
	if err := ValidateControl(control); err != nil {
		return err
	}
	if config.Controls == nil {
		config.Controls = map[string]Control{}
	}
	if _, exists := config.Controls[name]; exists && !replace {
		return fmt.Errorf("runtime control %q already exists; use --replace", name)
	}
	if control.CloneMode == "" {
		control.CloneMode = "full"
	}
	if control.Name == "" {
		control.Name = name
	}
	config.Controls[name] = control
	if config.Active == "" {
		config.Active = name
	}
	return nil
}

func Remove(config *Config, name string) error {
	if config == nil {
		return fmt.Errorf("runtime control config is nil")
	}
	if _, ok := config.Controls[name]; !ok {
		return fmt.Errorf("runtime control %q does not exist", name)
	}
	delete(config.Controls, name)
	if config.Active == name {
		config.Active = ""
	}
	return nil
}

func Names(config Config) []string {
	names := make([]string, 0, len(config.Controls))
	for name := range config.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func Resolve(config Config, name string) (string, Control, error) {
	if strings.TrimSpace(name) == "" {
		name = config.Active
	}
	if name == "" && len(config.Controls) == 1 {
		for candidate := range config.Controls {
			name = candidate
		}
	}
	control, ok := config.Controls[name]
	if !ok {
		return "", Control{}, fmt.Errorf("runtime control %q does not exist; available: %s", name, strings.Join(Names(config), ", "))
	}
	return name, control, nil
}

// LabProfile materializes the provider settings only for the duration of a
// lifecycle action. The API token is still resolved by lab.NewProxmoxProvider.
func LabProfile(control Control) (lab.Profile, error) {
	prep, err := lab.LoadProxmoxPreparation(control.ProxmoxPrep)
	if err != nil {
		return lab.Profile{}, err
	}
	mode := control.CloneMode
	if mode == "linked" {
		mode = "linked"
	} else {
		mode = "full"
	}
	profile := lab.DefaultProfile("proxmox")
	profile.Transport = "ssh"
	profile.BuildMode = "local"
	profile.Proxmox = &lab.ProxmoxProfile{
		Endpoint: prep.Endpoint, Node: prep.Node, VMID: control.VMID, Pool: prep.Pool,
		Storage: prep.Storage, ISOStorage: prep.ISOStorage, TokenID: prep.TokenID,
		TokenSecretSource: prep.TokenSecretSource, CAFile: prep.CAFile,
		TemplateVMID: control.TemplateVMID, CloneMode: mode, Bridge: prep.ResourcePlan.LabBridge,
		GuestIPv4CIDR: prep.ResourcePlan.LabSubnet, GuestAgent: true, SSHProxy: prep.SSHAlias,
	}
	return profile, nil
}
