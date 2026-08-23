package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/lab"
	"github.com/professor-moody/bofbench/internal/runtimecontrol"
)

type sliverRemoteClient struct {
	Control      string
	Host         string
	User         string
	Port         int
	IdentityFile string
	KnownHosts   string
	JumpHost     string
	Path         string
	Home         string
	ConfigPath   string
}

type sliverSSHHost struct {
	HostName     string
	User         string
	Port         int
	IdentityFile string
	KnownHosts   string
}

var safeSliverRemoteTemp = regexp.MustCompile(`^/tmp/bofbench-sliver-(?:rc|extension|implant)\.[A-Za-z0-9]+$`)

func resolveRemoteSliverClient(ctx context.Context, opts sliverOptions) (sliverOptions, bool, error) {
	controlsPath := strings.TrimSpace(opts.Controls)
	if controlsPath == "" {
		controlsPath = runtimecontrol.Path()
	}
	config, err := runtimecontrol.Load(controlsPath)
	if err != nil {
		return opts, false, err
	}
	controlName := strings.TrimSpace(opts.Control)
	if controlName == "" {
		controlName = strings.TrimSpace(os.Getenv("BOFBENCH_SLIVER_CONTROL"))
	}
	explicit := controlName != ""
	if controlName == "" {
		controlName = config.Active
	}
	if controlName == "" {
		return opts, false, nil
	}
	resolvedName, control, err := runtimecontrol.Resolve(config, controlName)
	if err != nil {
		if explicit {
			return opts, false, err
		}
		return opts, false, nil
	}
	if strings.ToLower(strings.TrimSpace(control.Runtime)) != "sliver" {
		if explicit {
			return opts, false, fmt.Errorf("runtime control %s is for %s, not sliver", resolvedName, control.Runtime)
		}
		return opts, false, nil
	}
	if control.Client == nil {
		if explicit {
			return opts, false, fmt.Errorf("runtime control %s has no remote client transport", resolvedName)
		}
		return opts, false, nil
	}
	profile, err := runtimecontrol.LabProfile(control)
	if err != nil {
		return opts, false, err
	}
	status, err := lab.RunProviderAction(ctx, "runtime-control-"+resolvedName, profile, "status", lab.ProviderActionOptions{})
	if err != nil {
		return opts, false, err
	}
	if status.Resource.State != "running" || strings.TrimSpace(status.Resource.GuestIPv4) == "" {
		return opts, false, fmt.Errorf("Sliver control %s is not ready (state=%s host=%s); run 'bofbench runtime control up %s'", resolvedName, status.Resource.State, status.Resource.GuestIPv4, resolvedName)
	}
	client := control.Client
	remote := &sliverRemoteClient{
		Control: resolvedName, Host: status.Resource.GuestIPv4, User: client.User, Port: client.Port,
		IdentityFile: client.IdentityFile, KnownHosts: client.KnownHosts,
		Path: client.Path, Home: client.Home, ConfigPath: client.ConfigPath,
	}
	if profile.Proxmox != nil {
		remote.JumpHost = profile.Proxmox.SSHProxy
	}
	opts.Control = resolvedName
	opts.Controls = controlsPath
	opts.Client = client.Path
	opts.ControlHost = remote.Host
	opts.RemoteClient = remote
	return opts, true, nil
}

func sliverRemoteSSHArgs(remote *sliverRemoteClient) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "UserKnownHostsFile=" + remote.KnownHosts,
	}
	if remote.JumpHost != "" {
		args = append(args, "-o", "ProxyJump="+remote.JumpHost)
	}
	if remote.Port != 0 && remote.Port != 22 {
		args = append(args, "-p", strconv.Itoa(remote.Port))
	}
	if remote.IdentityFile != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", remote.IdentityFile)
	}
	return args
}

func sliverRemoteSCPArgs(remote *sliverRemoteClient) []string {
	args := []string{
		"-q",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=15",
		"-o", "UserKnownHostsFile=" + remote.KnownHosts,
	}
	if remote.JumpHost != "" {
		args = append(args, "-o", "ProxyJump="+remote.JumpHost)
	}
	if remote.Port != 0 && remote.Port != 22 {
		args = append(args, "-P", strconv.Itoa(remote.Port))
	}
	if remote.IdentityFile != "" {
		args = append(args, "-o", "IdentitiesOnly=yes", "-i", remote.IdentityFile)
	}
	return args
}

func sliverRemoteTarget(remote *sliverRemoteClient) string {
	return remote.User + "@" + remote.Host
}

func sliverRemoteCommand(ctx context.Context, remote *sliverRemoteClient, stdin io.Reader, script string) (string, error) {
	args := append(sliverRemoteSSHArgs(remote), sliverRemoteTarget(remote), script)
	command := exec.CommandContext(ctx, "ssh", args...)
	command.Stdin = stdin
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), ctx.Err()
	}
	if err != nil {
		return string(output), fmt.Errorf("remote Sliver client command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func sliverRemotePreflight(ctx context.Context, remote *sliverRemoteClient) error {
	for label, path := range map[string]string{"identity": remote.IdentityFile, "known_hosts": remote.KnownHosts} {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return fmt.Errorf("remote Sliver client %s file is unavailable: %s", label, path)
		}
	}
	configs := filepath.Join(remote.Home, "configs")
	script := strings.Join([]string{
		"set -eu",
		"test -x " + posixShellQuote(remote.Path),
		"test -f " + posixShellQuote(remote.ConfigPath),
		"test -r " + posixShellQuote(remote.ConfigPath),
		"test -z \"$(find " + posixShellQuote(remote.ConfigPath) + " -perm /077 -print)\"",
		"test \"$(find " + posixShellQuote(configs) + " -maxdepth 1 -type f -name '*.cfg' | wc -l | tr -d ' ')\" = 1",
	}, "; ")
	if _, err := sliverRemoteCommand(ctx, remote, nil, script); err != nil {
		return fmt.Errorf("remote Sliver client preflight failed for control %s: %w", remote.Control, err)
	}
	return nil
}

func sliverRemoteTempDir(ctx context.Context, remote *sliverRemoteClient, kind string) (string, error) {
	if kind != "rc" && kind != "extension" && kind != "implant" {
		return "", fmt.Errorf("unsupported Sliver remote temporary kind %q", kind)
	}
	output, err := sliverRemoteCommand(ctx, remote, nil, "umask 077; mktemp -d /tmp/bofbench-sliver-"+kind+".XXXXXXXXXX")
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(output)
	if !safeSliverRemoteTemp.MatchString(path) {
		return "", fmt.Errorf("remote Sliver client returned unsafe temporary path %q", path)
	}
	return path, nil
}

func cleanupSliverRemoteTemp(remote *sliverRemoteClient, path string) {
	if remote == nil || !safeSliverRemoteTemp.MatchString(path) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = sliverRemoteCommand(ctx, remote, nil, "rm -rf -- "+posixShellQuote(path))
}

func runRemoteSliverRCContext(ctx context.Context, remote *sliverRemoteClient, body string) (string, error) {
	if err := sliverRemotePreflight(ctx, remote); err != nil {
		return "", err
	}
	temporary, err := sliverRemoteTempDir(ctx, remote, "rc")
	if err != nil {
		return "", err
	}
	defer cleanupSliverRemoteTemp(remote, temporary)
	rcPath := temporary + "/command.rc"
	if _, err := sliverRemoteCommand(ctx, remote, strings.NewReader(body), "umask 077; cat > "+posixShellQuote(rcPath)); err != nil {
		return "", err
	}
	home := filepath.Dir(remote.Home)
	script := "env HOME=" + posixShellQuote(home) + " " + posixShellQuote(remote.Path) + " console --rc " + posixShellQuote(rcPath)
	output, err := sliverRemoteCommand(ctx, remote, strings.NewReader("1\n"), script)
	if ctx.Err() != nil {
		return output, fmt.Errorf("Sliver console stopped before completion: %w", ctx.Err())
	}
	if err != nil {
		return output, fmt.Errorf("Sliver console failed: %w\n%s", err, stripANSI(output))
	}
	return output, nil
}

func stageSliverRemoteExtension(ctx context.Context, remote *sliverRemoteClient, localPath string) (string, func(), error) {
	if err := rejectSliverStageSymlinks(localPath); err != nil {
		return "", nil, err
	}
	temporary, err := sliverRemoteTempDir(ctx, remote, "extension")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { cleanupSliverRemoteTemp(remote, temporary) }
	remoteExtension := temporary + "/extension"
	if _, err := sliverRemoteCommand(ctx, remote, nil, "install -d -m 0700 "+posixShellQuote(remoteExtension)); err != nil {
		cleanup()
		return "", nil, err
	}
	args := append(sliverRemoteSCPArgs(remote), "-r", filepath.Clean(localPath)+"/.", sliverRemoteTarget(remote)+":"+remoteExtension+"/")
	command := exec.CommandContext(ctx, "scp", args...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		cleanup()
		return "", nil, ctx.Err()
	}
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("stage Sliver extension on control %s: %w: %s", remote.Control, err, strings.TrimSpace(string(output)))
	}
	return remoteExtension, cleanup, nil
}

func rejectSliverStageSymlinks(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("Sliver extension staging rejects symlink %s", path)
		}
		return nil
	})
}

func uploadSliverRemoteFileToLab(ctx context.Context, remote *sliverRemoteClient, remotePath string, target lab.RemoteOptions, targetPath string) error {
	if !safeSliverRemotePath(remotePath) {
		return fmt.Errorf("unsafe remote Sliver file path %q", remotePath)
	}
	if strings.ToLower(strings.TrimSpace(target.Transport)) != "ssh" {
		return fmt.Errorf("diskless Sliver implant transfer requires the Windows SSH lab transport")
	}
	config, err := os.CreateTemp("", "bofbench-sliver-scp-*.conf")
	if err != nil {
		return err
	}
	configPath := config.Name()
	defer os.Remove(configPath)
	if err := config.Chmod(0o600); err != nil {
		config.Close()
		return err
	}
	contents, err := sliverTransferSSHConfig(remote, target)
	if err != nil {
		config.Close()
		return err
	}
	if _, err := config.WriteString(contents); err != nil {
		config.Close()
		return err
	}
	if err := config.Close(); err != nil {
		return err
	}
	scp := strings.TrimSpace(target.SCP)
	if scp == "" {
		scp = "scp"
	}
	source := "bofbench-sliver-source:" + remotePath
	destination := "bofbench-windows-target:" + strings.ReplaceAll(targetPath, `\`, "/")
	command := exec.CommandContext(ctx, scp, "-3", "-q", "-F", configPath, source, destination)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("transfer Sliver implant directly between lab VMs: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func sliverTransferSSHConfig(source *sliverRemoteClient, target lab.RemoteOptions) (string, error) {
	for label, value := range map[string]string{
		"source host": source.Host, "source user": source.User, "source identity": source.IdentityFile,
		"source known_hosts": source.KnownHosts, "source jump host": source.JumpHost,
		"target host": target.Host, "target user": target.User, "target identity": target.IdentityFile,
		"target known_hosts": target.KnownHosts, "target jump host": target.JumpHost,
	} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("%s contains control characters", label)
		}
	}
	var builder strings.Builder
	writeBlock := func(alias, host, user string, port int, identity, knownHosts, jumpHost string) {
		fmt.Fprintf(&builder, "Host %s\n  HostName %s\n  User %s\n  Port %d\n", alias, host, user, port)
		builder.WriteString("  BatchMode yes\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  LogLevel ERROR\n")
		if identity != "" {
			fmt.Fprintf(&builder, "  IdentityFile %s\n", sshConfigQuote(identity))
		}
		if knownHosts != "" {
			fmt.Fprintf(&builder, "  UserKnownHostsFile %s\n", sshConfigQuote(knownHosts))
		}
		if jumpHost != "" {
			fmt.Fprintf(&builder, "  ProxyJump %s\n", jumpHost)
		}
	}
	jumpAliases := map[string]string{}
	for _, name := range []string{source.JumpHost, target.JumpHost} {
		if name == "" {
			continue
		}
		if _, exists := jumpAliases[name]; exists {
			continue
		}
		resolved, err := resolveSliverJumpHost(name)
		if err != nil {
			return "", err
		}
		alias := fmt.Sprintf("bofbench-jump-%d", len(jumpAliases)+1)
		jumpAliases[name] = alias
		writeBlock(alias, resolved.HostName, resolved.User, resolved.Port, resolved.IdentityFile, resolved.KnownHosts, "")
	}
	writeBlock("bofbench-sliver-source", source.Host, source.User, source.Port, source.IdentityFile, source.KnownHosts, jumpAliases[source.JumpHost])
	writeBlock("bofbench-windows-target", target.Host, target.User, target.Port, target.IdentityFile, target.KnownHosts, jumpAliases[target.JumpHost])
	return builder.String(), nil
}

var resolveSliverJumpHost = resolveSliverSSHHost

func resolveSliverSSHHost(name string) (sliverSSHHost, error) {
	if strings.TrimSpace(name) == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\r\n;$`|&<>") {
		return sliverSSHHost{}, fmt.Errorf("invalid SSH jump host %q", name)
	}
	output, err := exec.Command("ssh", "-G", name).Output()
	if err != nil {
		return sliverSSHHost{}, fmt.Errorf("resolve SSH jump host %s: %w", name, err)
	}
	resolved := sliverSSHHost{Port: 22}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value := fields[1]
		switch fields[0] {
		case "hostname":
			resolved.HostName = value
		case "user":
			resolved.User = value
		case "port":
			if parsed, parseErr := strconv.Atoi(value); parseErr == nil {
				resolved.Port = parsed
			}
		case "identityfile":
			if resolved.IdentityFile == "" {
				resolved.IdentityFile = expandSliverUserPath(value)
			}
		case "userknownhostsfile":
			if resolved.KnownHosts == "" {
				resolved.KnownHosts = expandSliverUserPath(value)
			}
		}
	}
	if resolved.HostName == "" || resolved.User == "" || resolved.Port < 1 || resolved.Port > 65535 {
		return sliverSSHHost{}, fmt.Errorf("SSH jump host %s did not resolve to a complete connection", name)
	}
	return resolved, nil
}

func expandSliverUserPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func sshConfigQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func sliverRemoteSHA256(ctx context.Context, remote *sliverRemoteClient, path string) (string, error) {
	if !safeSliverRemotePath(path) {
		return "", fmt.Errorf("unsafe remote Sliver file path %q", path)
	}
	output, err := sliverRemoteCommand(ctx, remote, nil, "sha256sum -- "+posixShellQuote(path))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(output)
	if len(fields) < 1 || len(fields[0]) != 64 {
		return "", fmt.Errorf("remote Sliver client returned an invalid SHA-256")
	}
	for _, char := range strings.ToLower(fields[0]) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return "", fmt.Errorf("remote Sliver client returned an invalid SHA-256")
		}
	}
	return strings.ToLower(fields[0]), nil
}

func safeSliverRemotePath(path string) bool {
	for _, kind := range []string{"rc", "extension", "implant"} {
		prefix := "/tmp/bofbench-sliver-" + kind + "."
		if strings.HasPrefix(path, prefix) && !strings.ContainsAny(path, "\x00\r\n") && !strings.Contains(path, "..") {
			return true
		}
	}
	return false
}

func sliverRemoteFileExists(ctx context.Context, remote *sliverRemoteClient, path string) bool {
	_, err := sliverRemoteCommand(ctx, remote, nil, "test -f "+posixShellQuote(path))
	return err == nil
}

func posixShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
