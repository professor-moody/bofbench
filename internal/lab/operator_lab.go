package lab

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/professor-moody/operator-lab/labapi"
)

const operatorLabAPIVersion = labapi.APIVersion

// OperatorLabLease, OperatorLabEvidence and the doctor response are the
// operator-lab wire contract, owned by the shared labapi module. The previous
// hand-mirrored copies had drifted: the doctor copy modelled three of nine
// fields while do() decodes with DisallowUnknownFields, so the availability
// probe failed on every call and reported the whole provider unavailable.
type OperatorLabLease = labapi.Lease

type operatorLabDoctor = labapi.Doctor

type OperatorLabEvidence = labapi.EvidenceSnapshot

type OperatorLabClient struct {
	endpoint string
	http     *http.Client
}

func NewOperatorLabClient(profile OperatorLabProfile) (*OperatorLabClient, error) {
	endpoint := firstNonempty(profile.Endpoint, os.Getenv("OPERATOR_LAB_URL"))
	caFile := firstNonempty(profile.CAFile, os.Getenv("OPERATOR_LAB_CA"))
	certFile := firstNonempty(profile.ClientCertificate, os.Getenv("OPERATOR_LAB_CLIENT_CERT"))
	keyFile := firstNonempty(profile.ClientKey, os.Getenv("OPERATOR_LAB_CLIENT_KEY"))
	if endpoint == "" || caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("operator-lab requires URL, CA, client certificate, and client key through the profile or OPERATOR_LAB_* environment")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" {
		return nil, fmt.Errorf("operator-lab URL must be an HTTPS origin")
	}
	caPEM, err := os.ReadFile(expandUserPath(caFile))
	if err != nil {
		return nil, fmt.Errorf("read operator-lab CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("operator-lab CA contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(expandUserPath(certFile), expandUserPath(keyFile))
	if err != nil {
		return nil, fmt.Errorf("load operator-lab mTLS identity: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	return &OperatorLabClient{endpoint: strings.TrimRight(endpoint, "/"), http: &http.Client{Transport: transport, Timeout: 6 * time.Minute}}, nil
}

func (c *OperatorLabClient) Doctor(ctx context.Context) error {
	var result operatorLabDoctor
	if err := c.do(ctx, http.MethodGet, "/v1/doctor", nil, &result); err != nil {
		return err
	}
	if result.Version != operatorLabAPIVersion || !result.Ready {
		return fmt.Errorf("operator-lab is unavailable: version=%s ready=%t error=%s", result.Version, result.Ready, result.Error)
	}
	return nil
}

func (c *OperatorLabClient) Acquire(ctx context.Context, profile string, ttl time.Duration) (OperatorLabLease, error) {
	seconds := int(ttl / time.Second)
	if seconds < 60 {
		seconds = 3600
	}
	var lease OperatorLabLease
	err := c.do(ctx, http.MethodPost, "/v1/leases", map[string]any{"profile": profile, "ttl_seconds": seconds}, &lease)
	if err == nil && (lease.Version != operatorLabAPIVersion || lease.State != "active" || lease.Address == "" || lease.SSHHostKey == "") {
		err = fmt.Errorf("operator-lab returned an incomplete active lease")
	}
	return lease, err
}

func (c *OperatorLabClient) Marker(ctx context.Context, id, name string, sequence int64) error {
	return c.do(ctx, http.MethodPost, "/v1/leases/"+url.PathEscape(id)+"/markers", map[string]any{"name": name, "sequence": sequence}, nil)
}

func (c *OperatorLabClient) Heartbeat(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/leases/"+url.PathEscape(id)+"/heartbeat", map[string]any{}, nil)
}

func (c *OperatorLabClient) Evidence(ctx context.Context, id string) (OperatorLabEvidence, error) {
	var evidence OperatorLabEvidence
	err := c.do(ctx, http.MethodGet, "/v1/leases/"+url.PathEscape(id)+"/evidence", nil, &evidence)
	return evidence, err
}

func (c *OperatorLabClient) Release(ctx context.Context, id string) (OperatorLabLease, error) {
	var lease OperatorLabLease
	err := c.do(ctx, http.MethodDelete, "/v1/leases/"+url.PathEscape(id), nil, &lease)
	if err == nil && (lease.State != "released" || lease.DestructionProof == "") {
		err = fmt.Errorf("operator-lab release did not prove clone destruction")
	}
	return lease, err
}

func (c *OperatorLabClient) do(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("operator-lab %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if output != nil && len(bytes.TrimSpace(data)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(output); err != nil {
			return err
		}
	}
	return nil
}

func (c *OperatorLabClient) StartHeartbeat(ctx context.Context, id string) (func(), <-chan error) {
	heartbeatCtx, cancel := context.WithCancel(ctx)
	errors := make(chan error, 1)
	var once sync.Once
	go func() {
		defer close(errors)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				if err := c.Heartbeat(heartbeatCtx, id); err != nil {
					if heartbeatCtx.Err() != nil {
						return
					}
					errors <- err
					return
				}
			}
		}
	}()
	return func() { once.Do(cancel) }, errors
}

func OperatorLabRemoteOptions(profileName string, profile Profile, lease OperatorLabLease, runDir string) (RemoteOptions, error) {
	if profile.OperatorLab == nil {
		return RemoteOptions{}, fmt.Errorf("operator-lab settings are missing")
	}
	identity := firstNonempty(profile.OperatorLab.IdentityFile, os.Getenv("BOFBENCH_OPERATOR_LAB_SSH_IDENTITY"))
	if identity == "" {
		return RemoteOptions{}, fmt.Errorf("operator-lab SSH identity is required through the profile or BOFBENCH_OPERATOR_LAB_SSH_IDENTITY")
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return RemoteOptions{}, err
	}
	knownHosts := filepath.Join(runDir, "known_hosts")
	line, err := labapi.KnownHostsLine(lease.Address, lease.SSHHostKey)
	if err != nil {
		return RemoteOptions{}, err
	}
	if err := writeFileAtomic(knownHosts, []byte(line), 0o600); err != nil {
		return RemoteOptions{}, err
	}
	user := firstNonempty(profile.OperatorLab.User, "bofbench")
	return RemoteOptions{ProfileName: profileName, Transport: "ssh", Host: lease.Address, User: user, Port: 22, IdentityFile: expandUserPath(identity), KnownHosts: knownHosts, BuildMode: "local", RemoteRoot: profile.RemoteRoot}, nil
}

// CleanupOperatorLabWorkspace removes only the declared run-owned root inside
// the disposable lease, recreates it empty, and verifies the result. Clone
// destruction remains mandatory and is a separate proof.
func CleanupOperatorLabWorkspace(ctx context.Context, options RemoteOptions) error {
	root := strings.TrimSpace(options.RemoteRoot)
	if root == "" {
		return fmt.Errorf("operator-lab remote root is empty")
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';$root=%s;if(Test-Path -LiteralPath $root){Get-ChildItem -Force -LiteralPath $root|Remove-Item -Recurse -Force};if(-not(Test-Path -LiteralPath $root)){New-Item -ItemType Directory -Force -Path $root|Out-Null};if(@(Get-ChildItem -Force -LiteralPath $root).Count -ne 0){throw 'operator-lab workspace cleanup incomplete'}`, powerShellQuote(root))
	_, stderr, err := remoteExecute(ctx, options, script)
	if err != nil {
		return fmt.Errorf("operator-lab workspace cleanup: %w: %s", err, boundedText(string(stderr), 2048))
	}
	return nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
