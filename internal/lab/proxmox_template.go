package lab

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProxmoxMedia is one provider storage object suitable for VM installation.
type ProxmoxMedia struct {
	VolumeID string `json:"volume_id"`
	Format   string `json:"format,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Content  string `json:"content,omitempty"`
}

// ProxmoxTemplateSpec describes a BOFBench-owned installation VM. It does not
// contain API tokens, guest passwords, product keys, or unattend secrets.
type ProxmoxTemplateSpec struct {
	VMID     int    `json:"vmid"`
	Name     string `json:"name"`
	ISO      string `json:"iso"`
	Cores    int    `json:"cores"`
	MemoryMB int    `json:"memory_mb"`
	DiskGB   int    `json:"disk_gb"`
	Bridge   string `json:"bridge"`
	OSType   string `json:"os_type,omitempty"`
	Start    bool   `json:"start"`
}

type proxmoxStorageContent struct {
	VolumeID string `json:"volid"`
	Format   string `json:"format"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
}

func proxmoxClientFromPreparation(path string) (ProxmoxPreparation, *proxmoxClient, error) {
	prep, err := LoadProxmoxPreparation(path)
	if err != nil {
		return ProxmoxPreparation{}, nil, err
	}
	secret, err := resolveSecretSource(prep.TokenSecretSource)
	if err != nil {
		return ProxmoxPreparation{}, nil, fmt.Errorf("resolve Proxmox API token secret: %w", err)
	}
	profile := ProxmoxProfile{Endpoint: prep.Endpoint, Node: prep.Node, TokenID: prep.TokenID, CAFile: prep.CAFile, SSHProxy: prep.SSHAlias}
	client, err := newProxmoxClient(profile, secret)
	if err != nil {
		return ProxmoxPreparation{}, nil, err
	}
	return prep, client, nil
}

// ListProxmoxMedia lists ISO content without mutating provider state.
func ListProxmoxMedia(ctx context.Context, preparationPath string) ([]ProxmoxMedia, error) {
	prep, client, err := proxmoxClientFromPreparation(preparationPath)
	if err != nil {
		return nil, err
	}
	defer client.close()
	var content []proxmoxStorageContent
	path := "/nodes/" + url.PathEscape(prep.Node) + "/storage/" + url.PathEscape(prep.ISOStorage) + "/content?content=iso"
	if err := client.request(ctx, http.MethodGet, path, nil, &content); err != nil {
		return nil, err
	}
	media := make([]ProxmoxMedia, 0, len(content))
	for _, item := range content {
		if item.Content != "" && item.Content != "iso" {
			continue
		}
		media = append(media, ProxmoxMedia{VolumeID: item.VolumeID, Format: item.Format, Size: item.Size, Content: item.Content})
	}
	sort.Slice(media, func(i, j int) bool { return media[i].VolumeID < media[j].VolumeID })
	return media, nil
}

// ProxmoxTemplateStatus inspects the exact BOFBench-owned VMID.
func ProxmoxTemplateStatus(ctx context.Context, preparationPath string, vmid int) (ProviderResource, error) {
	prep, client, err := proxmoxClientFromPreparation(preparationPath)
	if err != nil {
		return ProviderResource{}, err
	}
	defer client.close()
	profile := DefaultProfile("proxmox")
	profile.Proxmox = &ProxmoxProfile{Endpoint: prep.Endpoint, Node: prep.Node, VMID: vmid, Pool: prep.Pool, TokenID: prep.TokenID, TokenSecretSource: prep.TokenSecretSource, CAFile: prep.CAFile, GuestIPv4CIDR: prep.ResourcePlan.LabSubnet, GuestAgent: true, SSHProxy: prep.SSHAlias}
	provider := &proxmoxProvider{profileName: "template-" + strconv.Itoa(vmid), profile: profile, config: *profile.Proxmox, client: client}
	return provider.DiscoverGuest(ctx)
}

// BuildProxmoxTemplate creates a BOFBench-owned installation VM from an
// operator-supplied ISO and optionally starts it. Windows installation and
// licensing remain explicit guest-side steps; converting to a template uses
// the existing provider template action after installation completes.
func BuildProxmoxTemplate(ctx context.Context, preparationPath string, spec ProxmoxTemplateSpec) (ProviderReceipt, error) {
	prep, client, err := proxmoxClientFromPreparation(preparationPath)
	if err != nil {
		return ProviderReceipt{}, err
	}
	defer client.close()
	if spec.VMID < prep.ResourcePlan.VMIDMin || (prep.ResourcePlan.VMIDMax > 0 && spec.VMID > prep.ResourcePlan.VMIDMax) {
		return ProviderReceipt{}, fmt.Errorf("vmid %d is outside the BOFBench allocation %d-%d", spec.VMID, prep.ResourcePlan.VMIDMin, prep.ResourcePlan.VMIDMax)
	}
	if strings.TrimSpace(spec.ISO) == "" {
		return ProviderReceipt{}, fmt.Errorf("ISO volume is required")
	}
	if spec.Name == "" {
		spec.Name = "bofbench-template-" + strconv.Itoa(spec.VMID)
	}
	if spec.Cores <= 0 {
		spec.Cores = 4
	}
	if spec.MemoryMB <= 0 {
		spec.MemoryMB = 4096
	}
	if spec.DiskGB <= 0 {
		spec.DiskGB = 64
	}
	if spec.Bridge == "" {
		spec.Bridge = prep.ResourcePlan.LabBridge
	}
	if spec.OSType == "" {
		spec.OSType = "win11"
	}
	receipt := newProviderReceipt("proxmox", "template-"+strconv.Itoa(spec.VMID), "template-build")
	status, statusErr := ProxmoxTemplateStatus(ctx, preparationPath, spec.VMID)
	if statusErr != nil {
		return receipt, statusErr
	}
	if status.State != "absent" {
		return receipt, fmt.Errorf("vmid %d already exists as %s; refusing to replace it", spec.VMID, status.Name)
	}
	form := url.Values{}
	form.Set("vmid", strconv.Itoa(spec.VMID))
	form.Set("name", spec.Name)
	form.Set("pool", prep.Pool)
	form.Set("cores", strconv.Itoa(spec.Cores))
	form.Set("memory", strconv.Itoa(spec.MemoryMB))
	form.Set("ostype", spec.OSType)
	form.Set("scsihw", "virtio-scsi-single")
	form.Set("scsi0", fmt.Sprintf("%s:%d,discard=on,iothread=1,ssd=1", prep.Storage, spec.DiskGB))
	form.Set("ide2", spec.ISO+",media=cdrom")
	form.Set("net0", "virtio,bridge="+spec.Bridge)
	form.Set("agent", "enabled=1")
	form.Set("boot", "order=ide2;scsi0")
	var task string
	if err := client.request(ctx, http.MethodPost, "/nodes/"+url.PathEscape(prep.Node)+"/qemu", form, &task); err != nil {
		return receipt, err
	}
	receipt.TaskID = task
	if strings.HasPrefix(task, "UPID:") {
		state, waitErr := client.waitTask(ctx, prep.Node, task)
		receipt.TaskStatus = state.ExitStatus
		if waitErr != nil {
			return receipt, waitErr
		}
	}
	if spec.Start {
		var startTask string
		if err := client.request(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/status/start", url.PathEscape(prep.Node), spec.VMID), url.Values{}, &startTask); err != nil {
			return receipt, err
		}
		receipt.TaskID = startTask
		if strings.HasPrefix(startTask, "UPID:") {
			state, waitErr := client.waitTask(ctx, prep.Node, startTask)
			receipt.TaskStatus = state.ExitStatus
			if waitErr != nil {
				return receipt, waitErr
			}
		}
	}
	receipt.Status = "complete"
	receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.Resource = ProviderResource{Node: prep.Node, VMID: spec.VMID, Name: spec.Name, State: map[bool]string{true: "running", false: "stopped"}[spec.Start]}
	if err := persistProviderReceipt(&receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}
