package lab

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestProxmoxProviderUPIDAndGuestDiscovery(t *testing.T) {
	const tokenID = "bofbench@pve!provider"
	const secret = "test-secret-never-persist"
	var mu sync.Mutex
	requests := []string{}
	agentCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken="+tokenID+"="+secret {
			t.Errorf("authorization=%q", got)
		}
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/status/start"):
			fmt.Fprint(w, `{"data":"UPID:gr9:1:2:3:qmstart:4101:user:"}`)
		case strings.Contains(r.URL.Path, "/tasks/"):
			fmt.Fprint(w, `{"data":{"status":"stopped","exitstatus":"OK"}}`)
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			fmt.Fprint(w, `{"data":{"name":"bofbench-dev","status":"running","template":0}}`)
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			agentCalls++
			if agentCalls == 1 {
				fmt.Fprint(w, `{"data":{"result":[{"name":"Ethernet","ip-addresses":[]}]}}`)
			} else {
				fmt.Fprint(w, `{"data":{"result":[{"name":"Ethernet","ip-addresses":[{"ip-address":"10.12.90.21","ip-address-type":"ipv4"},{"ip-address":"fe80::1","ip-address-type":"ipv6"}]}]}}`)
			}
		default:
			http.Error(w, `{"errors":{"path":"unexpected"}}`, http.StatusNotFound)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	caPath := filepath.Join(root, "ca.pem")
	certificate, err := x509.ParseCertificate(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_TEST_PROXMOX_SECRET", secret)
	profile := DefaultProfile("proxmox")
	profile.Proxmox = &ProxmoxProfile{Endpoint: server.URL, Node: "gr9", VMID: 4101, TokenID: tokenID, TokenSecretSource: SecretSource{Kind: "env", Name: "BOFBENCH_TEST_PROXMOX_SECRET"}, CAFile: caPath, CloneMode: "full", GuestIPv4CIDR: "10.12.90.0/24", GuestAgent: true}
	provider, err := NewProxmoxProvider("dev", profile)
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*proxmoxProvider)
	receipt, err := p.Perform(context.Background(), "up", ProviderActionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaskID == "" || receipt.Resource.GuestIPv4 != "10.12.90.21" || receipt.Status != "complete" {
		t.Fatalf("receipt=%+v", receipt)
	}
	payload, _ := json.Marshal(receipt)
	if strings.Contains(string(payload), secret) {
		t.Fatal("provider receipt persisted token secret")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 6 {
		t.Fatalf("requests=%v", requests)
	}
}

func TestProxmoxTemplateFormAttachesOptionalDriverISO(t *testing.T) {
	prep := ProxmoxPreparation{Pool: "bofbench", Storage: "local-lvm"}
	spec := ProxmoxTemplateSpec{VMID: 4102, Name: "server", ISO: "local:iso/server.iso", DriverISO: " local:iso/virtio.iso ", Cores: 4, MemoryMB: 4096, DiskGB: 64, Bridge: "vmbr290", OSType: "win11"}
	form := proxmoxTemplateCreateForm(prep, spec)
	if form.Get("ide2") != "local:iso/server.iso,media=cdrom" {
		t.Fatalf("installer ISO=%q", form.Get("ide2"))
	}
	if form.Get("ide0") != "local:iso/virtio.iso,media=cdrom" {
		t.Fatalf("driver ISO=%q", form.Get("ide0"))
	}
	if form.Get("scsi0") != "local-lvm:64,discard=on,iothread=1,ssd=1" {
		t.Fatalf("disk=%q", form.Get("scsi0"))
	}
	withoutDriver := proxmoxTemplateCreateForm(prep, ProxmoxTemplateSpec{VMID: 4102, ISO: "local:iso/server.iso"})
	if withoutDriver.Has("ide0") {
		t.Fatalf("unexpected driver ISO: %q", withoutDriver.Get("ide0"))
	}
}
