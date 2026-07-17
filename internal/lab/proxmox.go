package lab

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type proxmoxClient struct {
	endpoint string
	tokenID  string
	secret   string
	http     *http.Client
	tunnel   *sshTunnel
}

type sshTunnel struct {
	command *exec.Cmd
	done    chan error
}

type proxmoxEnvelope struct {
	Data   json.RawMessage   `json:"data"`
	Errors map[string]string `json:"errors,omitempty"`
}

type proxmoxTaskStatus struct {
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus,omitempty"`
}

type proxmoxProvider struct {
	profileName string
	profile     Profile
	config      ProxmoxProfile
	client      *proxmoxClient
}

func NewProxmoxProvider(profileName string, profile Profile) (Provider, error) {
	profile = NormalizeProfile(profile)
	if profile.Proxmox == nil {
		return nil, fmt.Errorf("proxmox provider requires proxmox settings")
	}
	secret, err := resolveSecretSource(profile.Proxmox.TokenSecretSource)
	if err != nil {
		return nil, fmt.Errorf("resolve Proxmox API token secret: %w", err)
	}
	client, err := newProxmoxClient(*profile.Proxmox, secret)
	if err != nil {
		return nil, err
	}
	return &proxmoxProvider{profileName: profileName, profile: profile, config: *profile.Proxmox, client: client}, nil
}

func (p *proxmoxProvider) Name() string { return "proxmox" }

func (p *proxmoxProvider) Close() {
	if p != nil && p.client != nil {
		p.client.close()
	}
}

func newProxmoxClient(config ProxmoxProfile, secret string) (*proxmoxClient, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("token secret is empty")
	}
	caBytes, err := os.ReadFile(expandUserPath(config.CAFile))
	if err != nil {
		return nil, fmt.Errorf("read Proxmox CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("Proxmox CA file contains no certificates")
	}
	endpoint := strings.TrimRight(config.Endpoint, "/")
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse Proxmox endpoint: %w", err)
	}
	serverName := parsedEndpoint.Hostname()
	var tunnel *sshTunnel
	if strings.TrimSpace(config.SSHProxy) != "" {
		forwarded, activeTunnel, err := startSSHTunnel(config.SSHProxy, parsedEndpoint)
		if err != nil {
			return nil, err
		}
		parsedEndpoint.Host = forwarded
		endpoint = strings.TrimRight(parsedEndpoint.String(), "/")
		tunnel = activeTunnel
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: serverName}
	return &proxmoxClient{
		endpoint: endpoint, tokenID: config.TokenID, secret: secret, tunnel: tunnel,
		http: &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}, nil
}

func startSSHTunnel(proxy string, endpoint *url.URL) (string, *sshTunnel, error) {
	host := endpoint.Hostname()
	port := endpoint.Port()
	if port == "" {
		port = "443"
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	localPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	forward := fmt.Sprintf("127.0.0.1:%d:%s:%s", localPort, host, port)
	command := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-N", "-L", forward, proxy)
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return "", nil, fmt.Errorf("start Proxmox SSH API tunnel: %w", err)
	}
	tunnel := &sshTunnel{command: command, done: make(chan error, 1)}
	go func() { tunnel.done <- command.Wait() }()
	address := fmt.Sprintf("127.0.0.1:%d", localPort)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return address, tunnel, nil
		}
		select {
		case waitErr := <-tunnel.done:
			return "", nil, fmt.Errorf("Proxmox SSH API tunnel exited: %v: %s", waitErr, strings.TrimSpace(stderr.String()))
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	tunnel.close()
	return "", nil, fmt.Errorf("timed out opening Proxmox SSH API tunnel through %s: %s", proxy, strings.TrimSpace(stderr.String()))
}

func (t *sshTunnel) close() {
	if t == nil || t.command == nil || t.command.Process == nil {
		return
	}
	_ = t.command.Process.Signal(os.Interrupt)
	select {
	case <-t.done:
	case <-time.After(time.Second):
		_ = t.command.Process.Kill()
		<-t.done
	}
}

func (c *proxmoxClient) close() {
	if c != nil && c.tunnel != nil {
		c.tunnel.close()
		c.tunnel = nil
	}
}

func resolveSecretSource(source SecretSource) (string, error) {
	switch strings.ToLower(strings.TrimSpace(source.Kind)) {
	case "env":
		value := os.Getenv(strings.TrimSpace(source.Name))
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty", source.Name)
		}
		return value, nil
	case "macos-keychain":
		if _, err := exec.LookPath("security"); err != nil {
			return "", fmt.Errorf("macOS security command is unavailable")
		}
		output, err := exec.Command("security", "find-generic-password", "-w", "-s", source.Service, "-a", source.Account).Output()
		if err != nil {
			return "", fmt.Errorf("read keychain item: %w", err)
		}
		value := strings.TrimSpace(string(output))
		if value == "" {
			return "", fmt.Errorf("keychain item is empty")
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported secret source %q", source.Kind)
	}
}

func (c *proxmoxClient) request(ctx context.Context, method, apiPath string, form url.Values, target any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+apiPath, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.tokenID+"="+c.secret)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var envelope proxmoxEnvelope
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &envelope); err != nil {
			return fmt.Errorf("decode Proxmox response (%s): %w", strings.TrimSpace(string(payload)), err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Proxmox API %s %s returned %s: %s", method, apiPath, resp.Status, proxmoxErrors(envelope.Errors, payload))
	}
	if target != nil && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
		if err := json.Unmarshal(envelope.Data, target); err != nil {
			return fmt.Errorf("decode Proxmox data: %w", err)
		}
	}
	return nil
}

func proxmoxErrors(values map[string]string, raw []byte) string {
	if len(values) == 0 {
		return strings.TrimSpace(string(raw))
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+": "+values[key])
	}
	return strings.Join(parts, "; ")
}

func (c *proxmoxClient) task(ctx context.Context, node, upid string) (proxmoxTaskStatus, error) {
	var status proxmoxTaskStatus
	err := c.request(ctx, http.MethodGet, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/status", nil, &status)
	return status, err
}

func (c *proxmoxClient) waitTask(ctx context.Context, node, upid string) (proxmoxTaskStatus, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := c.task(ctx, node, upid)
		if err != nil {
			return status, err
		}
		if strings.EqualFold(status.Status, "stopped") {
			if status.ExitStatus != "" && !strings.EqualFold(status.ExitStatus, "OK") {
				return status, fmt.Errorf("Proxmox task %s ended %s", upid, status.ExitStatus)
			}
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (p *proxmoxProvider) vmPath(suffix string) string {
	base := "/nodes/" + url.PathEscape(p.config.Node) + "/qemu/" + strconv.Itoa(p.config.VMID)
	if suffix == "" {
		return base
	}
	return base + "/" + suffix
}

func (p *proxmoxProvider) DiscoverGuest(ctx context.Context) (ProviderResource, error) {
	if strings.TrimSpace(p.config.Pool) != "" {
		var pool struct {
			Members []struct {
				VMID     int    `json:"vmid"`
				Name     string `json:"name"`
				Status   string `json:"status"`
				Template int    `json:"template"`
			} `json:"members"`
		}
		if err := p.client.request(ctx, http.MethodGet, "/pools/"+url.PathEscape(p.config.Pool), nil, &pool); err != nil {
			return ProviderResource{}, err
		}
		found := false
		for _, member := range pool.Members {
			if member.VMID == p.config.VMID {
				found = true
				break
			}
		}
		if !found {
			return ProviderResource{Node: p.config.Node, VMID: p.config.VMID, State: "absent", GuestAgent: p.config.GuestAgent}, nil
		}
	}
	var status struct {
		Name     string          `json:"name"`
		Status   string          `json:"status"`
		Template int             `json:"template"`
		Agent    json.RawMessage `json:"agent"`
	}
	if err := p.client.request(ctx, http.MethodGet, p.vmPath("status/current"), nil, &status); err != nil {
		return ProviderResource{}, err
	}
	resource := ProviderResource{Node: p.config.Node, VMID: p.config.VMID, Name: status.Name, State: status.Status, Template: status.Template == 1, GuestAgent: p.config.GuestAgent}
	if status.Status != "running" || !p.config.GuestAgent {
		return resource, nil
	}
	var agent struct {
		Result []struct {
			Name        string `json:"name"`
			IPAddresses []struct {
				Address string `json:"ip-address"`
				Type    string `json:"ip-address-type"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if err := p.client.request(ctx, http.MethodGet, p.vmPath("agent/network-get-interfaces"), nil, &agent); err != nil {
		return resource, nil
	}
	resource.GuestIPv4 = selectGuestIPv4(agent.Result, p.config.GuestIPv4CIDR)
	return resource, nil
}

func selectGuestIPv4(interfaces []struct {
	Name        string `json:"name"`
	IPAddresses []struct {
		Address string `json:"ip-address"`
		Type    string `json:"ip-address-type"`
	} `json:"ip-addresses"`
}, cidr string) string {
	var network *net.IPNet
	if strings.TrimSpace(cidr) != "" {
		_, network, _ = net.ParseCIDR(cidr)
	}
	var candidates []string
	for _, iface := range interfaces {
		for _, address := range iface.IPAddresses {
			ip := net.ParseIP(address.Address)
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if network != nil && network.Contains(ip) {
				return ip.String()
			}
			candidates = append(candidates, ip.String())
		}
	}
	sort.Strings(candidates)
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func (p *proxmoxProvider) Perform(ctx context.Context, action string, opts ProviderActionOptions) (ProviderReceipt, error) {
	receipt := newProviderReceipt(p.Name(), p.profileName, action)
	if action == "status" {
		resource, err := p.DiscoverGuest(ctx)
		receipt.Resource = resource
		if err != nil {
			return receipt, err
		}
		receipt.Status, receipt.TaskStatus = "complete", resource.State
		return receipt, nil
	}
	var method = http.MethodPost
	var path string
	form := url.Values{}
	switch action {
	case "up":
		path = p.vmPath("status/start")
	case "down":
		path = p.vmPath("status/shutdown")
		form.Set("timeout", "60")
	case "stop":
		path = p.vmPath("status/stop")
	case "snapshot":
		if strings.TrimSpace(opts.Snapshot) == "" {
			return receipt, fmt.Errorf("snapshot name is required")
		}
		receipt.Snapshot = opts.Snapshot
		path = p.vmPath("snapshot")
		form.Set("snapname", opts.Snapshot)
		if opts.Name != "" {
			form.Set("description", opts.Name)
		}
	case "restore":
		if strings.TrimSpace(opts.Snapshot) == "" {
			return receipt, fmt.Errorf("snapshot name is required")
		}
		receipt.Snapshot = opts.Snapshot
		path = p.vmPath("snapshot/" + url.PathEscape(opts.Snapshot) + "/rollback")
	case "destroy":
		method = http.MethodDelete
		path = p.vmPath("")
		form.Set("purge", "1")
		form.Set("destroy-unreferenced-disks", "1")
	case "clone":
		if p.config.TemplateVMID == 0 {
			return receipt, fmt.Errorf("proxmox clone requires template_vmid")
		}
		path = "/nodes/" + url.PathEscape(p.config.Node) + "/qemu/" + strconv.Itoa(p.config.TemplateVMID) + "/clone"
		form.Set("newid", strconv.Itoa(p.config.VMID))
		if opts.Name != "" {
			form.Set("name", opts.Name)
		}
		if p.config.CloneMode == "full" {
			form.Set("full", "1")
		} else {
			form.Set("full", "0")
		}
		if p.config.Pool != "" {
			form.Set("pool", p.config.Pool)
		}
		if p.config.Storage != "" {
			form.Set("storage", p.config.Storage)
		}
	case "template":
		path = p.vmPath("template")
	default:
		return receipt, fmt.Errorf("proxmox provider does not support action %q", action)
	}
	var upid string
	if err := p.client.request(ctx, method, path, form, &upid); err != nil {
		return receipt, err
	}
	receipt.TaskID = upid
	status, err := p.client.waitTask(ctx, p.config.Node, upid)
	receipt.TaskStatus = status.Status
	if status.ExitStatus != "" {
		receipt.TaskStatus = status.ExitStatus
	}
	if err != nil {
		return receipt, err
	}
	resource, discoverErr := p.DiscoverGuest(ctx)
	if discoverErr == nil && action == "up" {
		resource, discoverErr = waitForProviderGuestIPv4(ctx, p, resource, proxmoxGuestReadyTimeout)
	}
	if discoverErr == nil {
		receipt.Resource = resource
	} else if action != "destroy" {
		return receipt, discoverErr
	}
	receipt.Status = "complete"
	return receipt, nil
}
