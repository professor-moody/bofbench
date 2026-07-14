package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ConfigSchema  = "bofbench.lab"
	ConfigVersion = 1
)

type Config struct {
	Schema        string   `json:"schema"`
	SchemaVersion int      `json:"schema_version"`
	Provider      string   `json:"provider"`
	Topology      string   `json:"topology"`
	Transport     string   `json:"transport"`
	Host          string   `json:"host,omitempty"`
	RemoteRoot    string   `json:"remote_root,omitempty"`
	Executable    string   `json:"executable,omitempty"`
	VagrantFile   string   `json:"vagrant_file,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	UpdatedAt     string   `json:"updated_at"`
}

func DefaultConfig(provider string) Config {
	remote := DefaultRemoteOptions()
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "existing"
	}
	transport := "ssh"
	if provider == "vagrant" {
		transport = "winrm"
	}
	return Config{Schema: ConfigSchema, SchemaVersion: ConfigVersion, Provider: provider, Topology: "standalone", Transport: transport, Host: remote.Host, RemoteRoot: remote.RemoteRoot, Executable: remote.Executable, VagrantFile: "Vagrantfile", UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
}

func DefaultConfigPath() string {
	return filepath.Join(".bofbench", "lab.json")
}

func SaveConfig(path string, config Config) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	if err := ValidateConfig(config); err != nil {
		return err
	}
	config.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

func ValidateConfig(config Config) error {
	if config.Schema != ConfigSchema || config.SchemaVersion != ConfigVersion {
		return fmt.Errorf("schema must be %s version %d", ConfigSchema, ConfigVersion)
	}
	if config.Provider != "existing" && config.Provider != "vagrant" {
		return fmt.Errorf("provider must be existing or vagrant")
	}
	if config.Topology != "standalone" && config.Topology != "domain" {
		return fmt.Errorf("topology must be standalone or domain")
	}
	if config.Provider == "existing" {
		if config.Transport != "ssh" && config.Transport != "winrm" {
			return fmt.Errorf("existing provider transport must be ssh or winrm")
		}
		if strings.TrimSpace(config.Host) == "" || strings.TrimSpace(config.RemoteRoot) == "" || strings.TrimSpace(config.Executable) == "" {
			return fmt.Errorf("existing provider requires host, remote_root, and executable")
		}
	}
	return nil
}

func (config Config) RemoteOptions() RemoteOptions {
	return RemoteOptions{Host: config.Host, RemoteRoot: config.RemoteRoot, Executable: config.Executable, SSH: "ssh", SCP: "scp"}
}
