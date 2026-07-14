package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

type vagrantCommandFunc func(context.Context, Profile, ...string) ([]byte, error)

var executeVagrantCommand vagrantCommandFunc = runVagrantCommand

// ResolveRemoteOptions turns a portable profile into a concrete connection.
// Existing hosts come directly from labs.json. Vagrant connection details are
// discovered at use time so forwarded ports and generated passwords are never
// copied into project or profile files.
func ResolveRemoteOptions(ctx context.Context, name string, profile Profile) (RemoteOptions, error) {
	profile = NormalizeProfile(profile)
	opts := RemoteOptionsFromProfile(name, profile)
	if profile.Provider != "vagrant" {
		if opts.Transport == "winrm" && opts.WinRMPassword == "" && term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintf(os.Stderr, "WinRM password for lab %s (%s\\%s): ", name, opts.Host, opts.User)
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return RemoteOptions{}, fmt.Errorf("read WinRM password: %w", err)
			}
			opts.WinRMPassword = string(password)
		}
		return opts, nil
	}
	output, err := executeVagrantCommand(ctx, profile, "winrm-config")
	if err != nil {
		return RemoteOptions{}, fmt.Errorf("discover Vagrant WinRM connection for lab %q: %w", name, err)
	}
	values := parseVagrantConnection(string(output))
	opts.Transport = "winrm"
	opts.Host = firstValue(values, "host", "hostname")
	opts.User = firstValue(values, "username", "user")
	if port := firstValue(values, "port"); port != "" {
		parsed, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsed < 1 || parsed > 65535 {
			return RemoteOptions{}, fmt.Errorf("Vagrant returned invalid WinRM port %q", port)
		}
		opts.Port = parsed
	}
	if password := firstValue(values, "password"); password != "" {
		opts.WinRMPassword = password
	}
	if scheme := strings.ToLower(firstValue(values, "scheme", "transport")); scheme == "ssl" || scheme == "https" {
		opts.WinRMHTTPS = true
	}
	if opts.Host == "" || opts.User == "" || opts.WinRMPassword == "" {
		return RemoteOptions{}, fmt.Errorf("Vagrant WinRM configuration is incomplete; require host, username, and password")
	}
	return opts, nil
}

func runVagrantCommand(ctx context.Context, profile Profile, args ...string) ([]byte, error) {
	commandArgs := append([]string(nil), args...)
	if profile.VagrantMachine != "" {
		commandArgs = append(commandArgs, profile.VagrantMachine)
	}
	command := exec.CommandContext(ctx, "vagrant", commandArgs...)
	if profile.VagrantFile != "" {
		absolute, err := filepath.Abs(expandUserPath(profile.VagrantFile))
		if err != nil {
			return nil, err
		}
		command.Dir = filepath.Dir(absolute)
		command.Env = append(os.Environ(), "VAGRANT_VAGRANTFILE="+filepath.Base(absolute))
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vagrant %s failed: %w: %s", strings.Join(commandArgs, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func parseVagrantConnection(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			key, value = fields[0], strings.Join(fields[1:], " ")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		values[key] = value
	}
	return values
}

func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}
