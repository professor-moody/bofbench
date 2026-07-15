package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	ProfilesSchema                = "bofbench.labs"
	ProfilesSchemaVersion         = 3
	PreviousProfilesSchemaVersion = 2
	SelectionSchema               = "bofbench.lab-selection"
	SelectionVersion              = 1
)

var validProfileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Profile describes one portable Windows target. Authentication secrets are
// deliberately excluded: SSH uses an agent or identity-file path, and WinRM
// passwords are resolved at execution time.
type Profile struct {
	Provider       string `json:"provider"`
	Topology       string `json:"topology,omitempty"`
	Transport      string `json:"transport"`
	Host           string `json:"host,omitempty"`
	User           string `json:"user,omitempty"`
	Port           int    `json:"port,omitempty"`
	IdentityFile   string `json:"identity_file,omitempty"`
	KnownHosts     string `json:"known_hosts,omitempty"`
	RemoteRoot     string `json:"remote_root,omitempty"`
	BuildMode      string `json:"build_mode,omitempty"`
	VagrantFile    string `json:"vagrant_file,omitempty"`
	VagrantMachine string `json:"vagrant_machine,omitempty"`
	SliverSession  string `json:"sliver_session,omitempty"`
	WinRMHTTPS     bool   `json:"winrm_https,omitempty"`
}

type ProfilesConfig struct {
	Schema         string                     `json:"schema"`
	SchemaVersion  int                        `json:"schema_version"`
	Active         string                     `json:"active,omitempty"`
	Profiles       map[string]Profile         `json:"profiles"`
	ActiveTopology string                     `json:"active_topology,omitempty"`
	Topologies     map[string]ProfileTopology `json:"topologies,omitempty"`
	UpdatedAt      string                     `json:"updated_at,omitempty"`
}

// ProfileTopology gives multi-host proofs stable role names without copying
// host or authentication details out of the referenced profiles.
type ProfileTopology struct {
	Execution        string `json:"execution"`
	Target           string `json:"target,omitempty"`
	DomainController string `json:"domain_controller,omitempty"`
}

type ResolvedTopology struct {
	Name             string           `json:"name"`
	Source           string           `json:"source"`
	Execution        ResolvedProfile  `json:"execution"`
	Target           *ResolvedProfile `json:"target,omitempty"`
	DomainController *ResolvedProfile `json:"domain_controller,omitempty"`
}

type ProjectSelection struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Profile       string `json:"profile"`
}

type ResolvedProfile struct {
	Name    string  `json:"name"`
	Source  string  `json:"source"`
	Profile Profile `json:"profile"`
}

func DefaultProfile(provider string) Profile {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "existing"
	}
	transport := "ssh"
	if provider == "vagrant" {
		transport = "winrm"
	}
	port := 22
	if transport == "winrm" {
		port = 5985
	}
	profile := Profile{
		Provider: provider, Topology: "standalone", Transport: transport,
		Port: port, RemoteRoot: `C:\bofbench`, BuildMode: "auto",
	}
	if provider == "vagrant" {
		profile.VagrantFile = "Vagrantfile"
	}
	return profile
}

func NewProfilesConfig() ProfilesConfig {
	return ProfilesConfig{Schema: ProfilesSchema, SchemaVersion: ProfilesSchemaVersion, Profiles: map[string]Profile{}, Topologies: map[string]ProfileTopology{}}
}

func ProfilesPath() string {
	root := strings.TrimSpace(os.Getenv("BOFBENCH_CONFIG_HOME"))
	if root != "" {
		return filepath.Join(root, "labs.json")
	}
	root, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(root) == "" {
		root = "."
	}
	return filepath.Join(root, "bofbench", "labs.json")
}

func ProjectSelectionPath(project string) string {
	if strings.TrimSpace(project) == "" {
		project = "."
	}
	return filepath.Join(project, ".bofbench", "lab.json")
}

func LoadProfiles(path string) (ProfilesConfig, error) {
	if strings.TrimSpace(path) == "" {
		path = ProfilesPath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewProfilesConfig(), nil
	}
	if err != nil {
		return ProfilesConfig{}, err
	}
	var config ProfilesConfig
	if err := decodeStrict(data, &config); err != nil {
		return ProfilesConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if config.Schema == ProfilesSchema && config.SchemaVersion == PreviousProfilesSchemaVersion {
		config.SchemaVersion = ProfilesSchemaVersion
		if config.Topologies == nil {
			config.Topologies = map[string]ProfileTopology{}
		}
	}
	if err := ValidateProfiles(config); err != nil {
		return ProfilesConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

func SaveProfiles(path string, config ProfilesConfig) error {
	if strings.TrimSpace(path) == "" {
		path = ProfilesPath()
	}
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	if config.Topologies == nil {
		config.Topologies = map[string]ProfileTopology{}
	}
	config.Schema = ProfilesSchema
	config.SchemaVersion = ProfilesSchemaVersion
	config.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := ValidateProfiles(config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

func ValidateProfiles(config ProfilesConfig) error {
	if config.Schema != ProfilesSchema || config.SchemaVersion != ProfilesSchemaVersion {
		return fmt.Errorf("schema must be %s version %d", ProfilesSchema, ProfilesSchemaVersion)
	}
	for name, profile := range config.Profiles {
		if err := ValidateProfileName(name); err != nil {
			return err
		}
		if err := ValidateProfile(profile); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	for name, topology := range config.Topologies {
		if err := ValidateProfileName(name); err != nil {
			return fmt.Errorf("topology: %w", err)
		}
		if strings.TrimSpace(topology.Execution) == "" {
			return fmt.Errorf("topology %q requires an execution profile", name)
		}
		for role, profileName := range map[string]string{"execution": topology.Execution, "target": topology.Target, "domain_controller": topology.DomainController} {
			if profileName == "" {
				continue
			}
			if _, ok := config.Profiles[profileName]; !ok {
				return fmt.Errorf("topology %q role %s references missing profile %q", name, role, profileName)
			}
		}
	}
	if config.Active != "" {
		if _, ok := config.Profiles[config.Active]; !ok {
			return fmt.Errorf("active profile %q does not exist", config.Active)
		}
	}
	if config.ActiveTopology != "" {
		if _, ok := config.Topologies[config.ActiveTopology]; !ok {
			return fmt.Errorf("active topology %q does not exist", config.ActiveTopology)
		}
	}
	return nil
}

func ValidateProfileName(name string) error {
	if !validProfileName.MatchString(name) {
		return fmt.Errorf("profile name %q must match %s", name, validProfileName.String())
	}
	return nil
}

func ValidateProfile(profile Profile) error {
	profile.Provider = strings.ToLower(strings.TrimSpace(profile.Provider))
	profile.Topology = strings.ToLower(strings.TrimSpace(profile.Topology))
	profile.Transport = strings.ToLower(strings.TrimSpace(profile.Transport))
	profile.BuildMode = strings.ToLower(strings.TrimSpace(profile.BuildMode))
	if profile.Provider != "existing" && profile.Provider != "vagrant" {
		return fmt.Errorf("provider must be existing or vagrant")
	}
	if profile.Topology == "" {
		profile.Topology = "standalone"
	}
	if profile.Topology != "standalone" && profile.Topology != "domain" {
		return fmt.Errorf("topology must be standalone or domain")
	}
	if profile.Transport != "ssh" && profile.Transport != "winrm" {
		return fmt.Errorf("transport must be ssh or winrm")
	}
	if profile.Provider == "vagrant" && profile.Transport != "winrm" {
		return fmt.Errorf("vagrant profiles use WinRM transport")
	}
	if profile.Provider == "existing" && strings.TrimSpace(profile.Host) == "" {
		return fmt.Errorf("existing provider requires host")
	}
	if profile.Transport != "ssh" && (strings.TrimSpace(profile.IdentityFile) != "" || strings.TrimSpace(profile.KnownHosts) != "") {
		return fmt.Errorf("identity_file and known_hosts apply only to SSH profiles")
	}
	if profile.Transport != "winrm" && profile.WinRMHTTPS {
		return fmt.Errorf("winrm_https applies only to WinRM profiles")
	}
	if strings.TrimSpace(profile.RemoteRoot) == "" {
		return fmt.Errorf("remote_root is required")
	}
	if !looksWindowsPath(profile.RemoteRoot) {
		return fmt.Errorf("remote_root must be an absolute Windows path")
	}
	if profile.BuildMode == "" {
		profile.BuildMode = "auto"
	}
	if profile.BuildMode != "auto" && profile.BuildMode != "local" && profile.BuildMode != "remote" {
		return fmt.Errorf("build_mode must be auto, local, or remote")
	}
	if profile.Port < 0 || profile.Port > 65535 {
		return fmt.Errorf("port must be zero for the transport default or between 1 and 65535")
	}
	return nil
}

func NormalizeProfile(profile Profile) Profile {
	defaults := DefaultProfile(profile.Provider)
	profile.Provider = strings.ToLower(strings.TrimSpace(profile.Provider))
	if profile.Provider == "" {
		profile.Provider = defaults.Provider
	}
	profile.Topology = strings.ToLower(strings.TrimSpace(profile.Topology))
	if profile.Topology == "" {
		profile.Topology = defaults.Topology
	}
	profile.Transport = strings.ToLower(strings.TrimSpace(profile.Transport))
	if profile.Transport == "" {
		profile.Transport = defaults.Transport
	}
	profile.BuildMode = strings.ToLower(strings.TrimSpace(profile.BuildMode))
	if profile.BuildMode == "" {
		profile.BuildMode = defaults.BuildMode
	}
	if profile.Port == 0 {
		if profile.Transport == "winrm" {
			if profile.WinRMHTTPS {
				profile.Port = 5986
			} else {
				profile.Port = 5985
			}
		} else {
			profile.Port = 22
		}
	}
	if strings.TrimSpace(profile.RemoteRoot) == "" {
		profile.RemoteRoot = defaults.RemoteRoot
	}
	if profile.Provider == "vagrant" && strings.TrimSpace(profile.VagrantFile) == "" {
		profile.VagrantFile = defaults.VagrantFile
	}
	return profile
}

func AddProfile(config *ProfilesConfig, name string, profile Profile, replace bool) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if err := ValidateProfileName(name); err != nil {
		return err
	}
	profile = NormalizeProfile(profile)
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	if config.Profiles == nil {
		config.Profiles = map[string]Profile{}
	}
	if _, exists := config.Profiles[name]; exists && !replace {
		return fmt.Errorf("profile %q already exists; use --replace to update it", name)
	}
	config.Schema = ProfilesSchema
	config.SchemaVersion = ProfilesSchemaVersion
	config.Profiles[name] = profile
	if config.Active == "" && len(config.Profiles) == 1 {
		config.Active = name
	}
	return nil
}

func RemoveProfile(config *ProfilesConfig, name string) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if _, ok := config.Profiles[name]; !ok {
		return fmt.Errorf("profile %q does not exist", name)
	}
	for topologyName, topology := range config.Topologies {
		if topology.Execution == name || topology.Target == name || topology.DomainController == name {
			return fmt.Errorf("profile %q is used by topology %q; remove or update the topology first", name, topologyName)
		}
	}
	delete(config.Profiles, name)
	if config.Active == name {
		config.Active = ""
	}
	return nil
}

func UseProfile(config *ProfilesConfig, name string) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if _, ok := config.Profiles[name]; !ok {
		return fmt.Errorf("profile %q does not exist; available: %s", name, strings.Join(ProfileNames(*config), ", "))
	}
	config.Active = name
	return nil
}

func ProfileNames(config ProfilesConfig) []string {
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TopologyNames(config ProfilesConfig) []string {
	names := make([]string, 0, len(config.Topologies))
	for name := range config.Topologies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func AddTopology(config *ProfilesConfig, name string, topology ProfileTopology, replace bool) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if err := ValidateProfileName(name); err != nil {
		return err
	}
	if config.Topologies == nil {
		config.Topologies = map[string]ProfileTopology{}
	}
	if _, exists := config.Topologies[name]; exists && !replace {
		return fmt.Errorf("topology %q already exists; use --replace to update it", name)
	}
	if strings.TrimSpace(topology.Execution) == "" {
		return fmt.Errorf("topology %q requires an execution profile", name)
	}
	for role, profileName := range map[string]string{"execution": topology.Execution, "target": topology.Target, "domain_controller": topology.DomainController} {
		if profileName == "" {
			continue
		}
		if _, ok := config.Profiles[profileName]; !ok {
			return fmt.Errorf("topology %q role %s references missing profile %q; available: %s", name, role, profileName, strings.Join(ProfileNames(*config), ", "))
		}
	}
	config.Topologies[name] = topology
	if config.ActiveTopology == "" && len(config.Topologies) == 1 {
		config.ActiveTopology = name
	}
	return nil
}

func RemoveTopology(config *ProfilesConfig, name string) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if _, ok := config.Topologies[name]; !ok {
		return fmt.Errorf("topology %q does not exist", name)
	}
	delete(config.Topologies, name)
	if config.ActiveTopology == name {
		config.ActiveTopology = ""
	}
	return nil
}

func UseTopology(config *ProfilesConfig, name string) error {
	if config == nil {
		return fmt.Errorf("profiles config is nil")
	}
	if _, ok := config.Topologies[name]; !ok {
		return fmt.Errorf("topology %q does not exist; available: %s", name, strings.Join(TopologyNames(*config), ", "))
	}
	config.ActiveTopology = name
	return nil
}

// ResolveTopology selects a reusable role mapping. Profiles remain the only
// place that contains connection details.
func ResolveTopology(explicit, profilesPath string) (ResolvedTopology, error) {
	if strings.TrimSpace(profilesPath) == "" {
		profilesPath = ProfilesPath()
	}
	config, err := LoadProfiles(profilesPath)
	if err != nil {
		return ResolvedTopology{}, err
	}
	selected := strings.TrimSpace(explicit)
	source := "--topology"
	if selected == "" {
		selected = strings.TrimSpace(os.Getenv("BOFBENCH_TOPOLOGY"))
		source = "BOFBENCH_TOPOLOGY"
	}
	if selected == "" {
		selected = config.ActiveTopology
		source = "active"
	}
	if selected == "" {
		return ResolvedTopology{}, fmt.Errorf("select a topology with --topology, BOFBENCH_TOPOLOGY, or 'bofbench lab topology use'; available: %s", strings.Join(TopologyNames(config), ", "))
	}
	topology, ok := config.Topologies[selected]
	if !ok {
		return ResolvedTopology{}, fmt.Errorf("topology %q selected by %s does not exist; available: %s", selected, source, strings.Join(TopologyNames(config), ", "))
	}
	resolveRole := func(name, role string) (*ResolvedProfile, error) {
		if name == "" {
			return nil, nil
		}
		profile, ok := config.Profiles[name]
		if !ok {
			return nil, fmt.Errorf("topology %q role %s references missing profile %q", selected, role, name)
		}
		resolved := &ResolvedProfile{Name: name, Source: "topology:" + selected + "/" + role, Profile: NormalizeProfile(profile)}
		return resolved, nil
	}
	execution, err := resolveRole(topology.Execution, "execution")
	if err != nil || execution == nil {
		if err == nil {
			err = fmt.Errorf("topology %q has no execution profile", selected)
		}
		return ResolvedTopology{}, err
	}
	target, err := resolveRole(topology.Target, "target")
	if err != nil {
		return ResolvedTopology{}, err
	}
	dc, err := resolveRole(topology.DomainController, "domain_controller")
	if err != nil {
		return ResolvedTopology{}, err
	}
	return ResolvedTopology{Name: selected, Source: source, Execution: *execution, Target: target, DomainController: dc}, nil
}

func SaveProjectSelection(path, profile string) error {
	if err := ValidateProfileName(profile); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		path = ProjectSelectionPath(".")
	}
	selection := ProjectSelection{Schema: SelectionSchema, SchemaVersion: SelectionVersion, Profile: profile}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(selection, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o644)
}

func LoadProjectSelection(path string) (ProjectSelection, error) {
	if strings.TrimSpace(path) == "" {
		path = ProjectSelectionPath(".")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ProjectSelection{}, err
	}
	var selection ProjectSelection
	if err := decodeStrict(data, &selection); err != nil {
		return ProjectSelection{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if selection.Schema != SelectionSchema || selection.SchemaVersion != SelectionVersion {
		return ProjectSelection{}, fmt.Errorf("%s: schema must be %s version %d", path, SelectionSchema, SelectionVersion)
	}
	if err := ValidateProfileName(selection.Profile); err != nil {
		return ProjectSelection{}, err
	}
	return selection, nil
}

// ResolveProfile applies the public selection precedence. It also migrates a
// project-local version-1 lab config on first use.
func ResolveProfile(explicit, project, profilesPath string) (ResolvedProfile, error) {
	if strings.TrimSpace(profilesPath) == "" {
		profilesPath = ProfilesPath()
	}
	config, err := LoadProfiles(profilesPath)
	if err != nil {
		return ResolvedProfile{}, err
	}
	selected := strings.TrimSpace(explicit)
	source := "--lab"
	if selected == "" {
		selected = strings.TrimSpace(os.Getenv("BOFBENCH_LAB"))
		source = "BOFBENCH_LAB"
	}
	if selected == "" {
		selectionPath := ProjectSelectionPath(project)
		selection, selectionErr := LoadProjectSelection(selectionPath)
		if selectionErr == nil {
			selected = selection.Profile
			source = "project"
		} else if !errors.Is(selectionErr, os.ErrNotExist) {
			migrated, migrationErr := migrateLegacySelection(selectionPath, profilesPath, &config)
			if migrationErr != nil {
				return ResolvedProfile{}, migrationErr
			}
			if migrated != "" {
				selected = migrated
				source = "project-migration"
			}
		}
	}
	if selected == "" && config.Active != "" {
		selected = config.Active
		source = "active"
	}
	if selected == "" && len(config.Profiles) == 1 {
		for name := range config.Profiles {
			selected = name
		}
		source = "only-profile"
	}
	if selected == "" {
		names := ProfileNames(config)
		if len(names) == 0 {
			return ResolvedProfile{}, fmt.Errorf("no lab profiles configured; add one with 'bofbench lab add <name>'")
		}
		return ResolvedProfile{}, fmt.Errorf("select a lab profile with --lab, BOFBENCH_LAB, a project default, or 'bofbench lab use'; available: %s", strings.Join(names, ", "))
	}
	profile, ok := config.Profiles[selected]
	if !ok {
		return ResolvedProfile{}, fmt.Errorf("lab profile %q selected by %s does not exist; available: %s", selected, source, strings.Join(ProfileNames(config), ", "))
	}
	return ResolvedProfile{Name: selected, Source: source, Profile: NormalizeProfile(profile)}, nil
}

func ProfileFromLegacy(config Config) Profile {
	profile := DefaultProfile(config.Provider)
	profile.Topology = config.Topology
	profile.Transport = config.Transport
	profile.Host = config.Host
	profile.RemoteRoot = config.RemoteRoot
	profile.VagrantFile = config.VagrantFile
	return NormalizeProfile(profile)
}

func (profile Profile) LegacyConfig() Config {
	profile = NormalizeProfile(profile)
	executable := windowsJoin(profile.RemoteRoot, "work", "bin", "bofbench.exe")
	return Config{
		Schema: ConfigSchema, SchemaVersion: ConfigVersion, Provider: profile.Provider,
		Topology: profile.Topology, Transport: profile.Transport, Host: profile.Host,
		RemoteRoot: profile.RemoteRoot, Executable: executable, VagrantFile: profile.VagrantFile,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func WinRMPasswordEnvironment(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return "BOFBENCH_LAB_" + b.String() + "_WINRM_PASSWORD"
}

func migrateLegacySelection(selectionPath, profilesPath string, profiles *ProfilesConfig) (string, error) {
	data, err := os.ReadFile(selectionPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	var header struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", fmt.Errorf("parse %s: %w", selectionPath, err)
	}
	if header.Schema != ConfigSchema || header.SchemaVersion != ConfigVersion {
		return "", fmt.Errorf("%s is neither a portable profile selection nor a migratable %s version %d config", selectionPath, ConfigSchema, ConfigVersion)
	}
	legacy, err := LoadConfig(selectionPath)
	if err != nil {
		return "", err
	}
	name := availableMigrationName(*profiles)
	if err := AddProfile(profiles, name, ProfileFromLegacy(legacy), false); err != nil {
		return "", err
	}
	backup := selectionPath + ".v1.bak"
	if _, statErr := os.Stat(backup); errors.Is(statErr, os.ErrNotExist) {
		if err := os.WriteFile(backup, data, 0o600); err != nil {
			return "", fmt.Errorf("retain legacy lab config backup: %w", err)
		}
	}
	if err := SaveProfiles(profilesPath, *profiles); err != nil {
		return "", err
	}
	if err := SaveProjectSelection(selectionPath, name); err != nil {
		return "", err
	}
	return name, nil
}

func availableMigrationName(config ProfilesConfig) string {
	if _, exists := config.Profiles["default"]; !exists {
		return "default"
	}
	if _, exists := config.Profiles["legacy"]; !exists {
		return "legacy"
	}
	for i := 2; ; i++ {
		name := "legacy-" + strconv.Itoa(i)
		if _, exists := config.Profiles[name]; !exists {
			return name
		}
	}
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".bofbench-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
