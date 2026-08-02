package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/bofbench/internal/lab"
	"github.com/professor-moody/bofbench/internal/runlog"
)

const domainProvisionReceiptSchema = "bofbench.domain-provision-receipt"

type domainRoleReceipt struct {
	Role         string `json:"role"`
	Profile      string `json:"profile"`
	ComputerName string `json:"computer_name,omitempty"`
	Domain       string `json:"domain,omitempty"`
	PartOfDomain bool   `json:"part_of_domain"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	Rebooted     bool   `json:"rebooted,omitempty"`
	Error        string `json:"error,omitempty"`
}

type domainProvisionReceipt struct {
	Schema        string              `json:"schema"`
	SchemaVersion int                 `json:"schema_version"`
	RunID         string              `json:"run_id"`
	Topology      string              `json:"topology"`
	Domain        string              `json:"domain"`
	NetBIOS       string              `json:"netbios"`
	Status        string              `json:"status"`
	StartedAt     string              `json:"started_at"`
	CompletedAt   string              `json:"completed_at"`
	Roles         []domainRoleReceipt `json:"roles"`
	ReceiptPath   string              `json:"receipt_path"`
}

type domainIdentity struct {
	ComputerName string `json:"computer_name"`
	Domain       string `json:"domain"`
	PartOfDomain bool   `json:"part_of_domain"`
	DomainRole   int    `json:"domain_role"`
}

func labTopologyProvisionCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, domainName, netbios, credentialSource, format string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "provision <name>", Short: "Start and idempotently configure a DC-plus-member topology", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		password, err := resolveSensitiveArgument("domain credential", credentialSource)
		if err != nil {
			return err
		}
		if password == "" {
			return fmt.Errorf("domain credential cannot be empty")
		}
		resolved, err := lab.ResolveTopology(args[0], profilesPath)
		if err != nil {
			return err
		}
		if resolved.DomainController == nil || resolved.Target == nil {
			return fmt.Errorf("topology %s requires execution, target, and domain-controller profiles", resolved.Name)
		}
		roles := orderedTopologyProviderRoles(resolved, false)
		for _, role := range roles {
			if _, err := runTopologyProviderRole(cmd.Context(), role.role, role.profile, "up", "", false); err != nil {
				return fmt.Errorf("start %s: %w", role.role, err)
			}
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()
		receipt, err := provisionDomainTopology(ctx, resolved, domainName, netbios, password)
		if format == "json" {
			_ = printJSON(stdout, receipt)
		}
		if err != nil {
			return err
		}
		if format != "json" {
			if format != "text" {
				return fmt.Errorf("lab topology provision format must be text or json")
			}
			fmt.Fprintf(stdout, "Domain topology provisioned\ntopology  %s\ndomain    %s\nnetbios   %s\nreceipt   %s\n", receipt.Topology, receipt.Domain, receipt.NetBIOS, receipt.ReceiptPath)
			for _, role := range receipt.Roles {
				fmt.Fprintf(stdout, "%-18s %-16s %-12s %s\n", strings.ReplaceAll(role.Role, "_", " "), role.ComputerName, role.Action, role.Status)
			}
		}
		return nil
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&domainName, "domain", "bofbench.test", "disposable DNS domain name")
	cmd.Flags().StringVar(&netbios, "netbios", "BOFBENCH", "disposable NetBIOS domain name")
	cmd.Flags().StringVar(&credentialSource, "credential", "@prompt", "DSRM/domain Administrator password source: @prompt, @env:NAME, or @file:path")
	cmd.Flags().DurationVar(&timeout, "timeout", 45*time.Minute, "overall promotion, reboot, and join timeout")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func labTopologyVerifyCommand(stdout io.Writer) *cobra.Command {
	var profilesPath, domainName, format string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "verify <name>", Short: "Verify resolved host identities and domain roles without changing them", Args: cobra.ExactArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		resolved, err := lab.ResolveTopology(args[0], profilesPath)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()
		receipt, verifyErr := verifyDomainTopology(ctx, resolved, domainName)
		if format == "json" {
			_ = printJSON(stdout, receipt)
		} else if format == "text" {
			fmt.Fprintf(stdout, "Topology verification  %s\n", receipt.Status)
			for _, role := range receipt.Roles {
				fmt.Fprintf(stdout, "%-18s %-16s domain=%-24s joined=%t status=%s\n", strings.ReplaceAll(role.Role, "_", " "), role.ComputerName, role.Domain, role.PartOfDomain, role.Status)
			}
			fmt.Fprintf(stdout, "receipt  %s\n", receipt.ReceiptPath)
		} else {
			return fmt.Errorf("lab topology verify format must be text or json")
		}
		return verifyErr
	}
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&domainName, "domain", "bofbench.test", "expected DNS domain name")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "verification timeout")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func newDomainReceipt(topology, domain, netbios, prefix string) (domainProvisionReceipt, error) {
	dir, err := runlog.NewDir(prefix)
	if err != nil {
		return domainProvisionReceipt{}, err
	}
	return domainProvisionReceipt{Schema: domainProvisionReceiptSchema, SchemaVersion: 1, RunID: runlog.ID(dir), Topology: topology, Domain: domain, NetBIOS: netbios, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ReceiptPath: filepath.Join(dir, "domain.json")}, nil
}

func provisionDomainTopology(ctx context.Context, topology lab.ResolvedTopology, domainName, netbios, password string) (domainProvisionReceipt, error) {
	receipt, err := newDomainReceipt(topology.Name, domainName, netbios, "domain-provision")
	if err != nil {
		return receipt, err
	}
	dc := *topology.DomainController
	dcOpts, err := lab.ResolveRemoteOptions(ctx, dc.Name, dc.Profile)
	if err != nil {
		return finishDomainReceipt(receipt, err)
	}
	dcIdentity, err := queryDomainIdentity(ctx, dcOpts)
	if err != nil {
		return finishDomainReceipt(receipt, err)
	}
	dcRole := domainRoleReceipt{Role: "domain_controller", Profile: dc.Name, ComputerName: dcIdentity.ComputerName, Domain: dcIdentity.Domain, PartOfDomain: dcIdentity.PartOfDomain, Status: "pass", Action: "unchanged"}
	if !dcIdentity.PartOfDomain || !strings.EqualFold(dcIdentity.Domain, domainName) || dcIdentity.DomainRole < 4 {
		script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null; Import-Module ADDSDeployment; $safe=ConvertTo-SecureString %s -AsPlainText -Force; Install-ADDSForest -DomainName %s -DomainNetbiosName %s -SafeModeAdministratorPassword $safe -InstallDNS -NoRebootOnCompletion -Force; New-Item -ItemType Directory -Path 'C:\ProgramData\BOFBench' -Force|Out-Null; [IO.File]::WriteAllText('C:\ProgramData\BOFBench\domain-controller-ready.json',([ordered]@{schema='bofbench.proxmox-domain-controller';schema_version=1;domain_name=%s;netbios_name=%s;reboot_required=$true}|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false))); Start-Process shutdown.exe -ArgumentList '/r /t 5 /f' -WindowStyle Hidden`, psLiteral(password), psLiteral(domainName), psLiteral(netbios), psLiteral(domainName), psLiteral(netbios))
		_, stderr, runErr := lab.ExecutePowerShell(ctx, dcOpts, script)
		if runErr != nil && !transportDroppedForReboot(runErr) {
			return finishDomainReceiptWithRole(receipt, dcRole, fmt.Errorf("promote domain controller: %w: %s", runErr, strings.TrimSpace(string(stderr))))
		}
		if err := waitForDomainRole(ctx, dcOpts, domainName, 4); err != nil {
			return finishDomainReceiptWithRole(receipt, dcRole, err)
		}
		dcRole.Action, dcRole.Rebooted = "promoted", true
	}
	receipt.Roles = append(receipt.Roles, dcRole)
	// Create only the disposable BOFBench OU used by automated proofs.
	_, stderr, err := lab.ExecutePowerShell(ctx, dcOpts, `$ErrorActionPreference='Stop'; Import-Module ActiveDirectory; $dn=(Get-ADDomain).DistinguishedName; if(-not(Get-ADOrganizationalUnit -LDAPFilter '(ou=BOFBench)' -SearchBase $dn -SearchScope OneLevel -ErrorAction SilentlyContinue)){New-ADOrganizationalUnit -Name 'BOFBench' -Path $dn -ProtectedFromAccidentalDeletion $false}|Out-Null`)
	if err != nil {
		return finishDomainReceipt(receipt, fmt.Errorf("prepare BOFBench OU: %w: %s", err, strings.TrimSpace(string(stderr))))
	}
	memberRoles := []struct {
		name    string
		profile lab.ResolvedProfile
	}{{"target", *topology.Target}, {"execution", topology.Execution}}
	for _, item := range memberRoles {
		opts, resolveErr := lab.ResolveRemoteOptions(ctx, item.profile.Name, item.profile.Profile)
		if resolveErr != nil {
			return finishDomainReceipt(receipt, resolveErr)
		}
		identity, queryErr := queryDomainIdentity(ctx, opts)
		if queryErr != nil {
			return finishDomainReceipt(receipt, queryErr)
		}
		role := domainRoleReceipt{Role: item.name, Profile: item.profile.Name, ComputerName: identity.ComputerName, Domain: identity.Domain, PartOfDomain: identity.PartOfDomain, Status: "pass", Action: "unchanged"}
		if !identity.PartOfDomain || !strings.EqualFold(identity.Domain, domainName) {
			script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $safe=ConvertTo-SecureString %s -AsPlainText -Force; $credential=New-Object Management.Automation.PSCredential(%s,$safe); Add-Computer -DomainName %s -Credential $credential -Force; New-Item -ItemType Directory -Path 'C:\ProgramData\BOFBench' -Force|Out-Null; [IO.File]::WriteAllText('C:\ProgramData\BOFBench\domain-member-ready.json',([ordered]@{schema='bofbench.proxmox-domain-member';schema_version=1;domain_name=%s;computer_name=$env:COMPUTERNAME;reboot_required=$true}|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false))); Start-Process shutdown.exe -ArgumentList '/r /t 5 /f' -WindowStyle Hidden`, psLiteral(password), psLiteral(netbios+`\Administrator`), psLiteral(domainName), psLiteral(domainName))
			_, joinStderr, joinErr := lab.ExecutePowerShell(ctx, opts, script)
			if joinErr != nil && !transportDroppedForReboot(joinErr) {
				return finishDomainReceiptWithRole(receipt, role, fmt.Errorf("join %s: %w: %s", item.name, joinErr, strings.TrimSpace(string(joinStderr))))
			}
			if err := waitForDomainRole(ctx, opts, domainName, 1); err != nil {
				return finishDomainReceiptWithRole(receipt, role, err)
			}
			role.Action, role.Rebooted = "joined", true
		}
		receipt.Roles = append(receipt.Roles, role)
	}
	return finishDomainReceipt(receipt, nil)
}

func verifyDomainTopology(ctx context.Context, topology lab.ResolvedTopology, domainName string) (domainProvisionReceipt, error) {
	receipt, err := newDomainReceipt(topology.Name, domainName, "", "domain-verify")
	if err != nil {
		return receipt, err
	}
	roles := []struct {
		name    string
		profile *lab.ResolvedProfile
		minimum int
	}{{"domain_controller", topology.DomainController, 4}, {"target", topology.Target, 1}, {"execution", &topology.Execution, 1}}
	for _, item := range roles {
		if item.profile == nil {
			continue
		}
		opts, resolveErr := lab.ResolveRemoteOptions(ctx, item.profile.Name, item.profile.Profile)
		if resolveErr != nil {
			return finishDomainReceipt(receipt, resolveErr)
		}
		identity, queryErr := queryDomainIdentity(ctx, opts)
		role := domainRoleReceipt{Role: item.name, Profile: item.profile.Name, ComputerName: identity.ComputerName, Domain: identity.Domain, PartOfDomain: identity.PartOfDomain, Action: "verified", Status: "pass"}
		if queryErr != nil {
			role.Status, role.Error = "failed", queryErr.Error()
			receipt.Roles = append(receipt.Roles, role)
			continue
		}
		if !identity.PartOfDomain || !strings.EqualFold(identity.Domain, domainName) || identity.DomainRole < item.minimum {
			role.Status, role.Error = "failed", "unexpected domain identity or role"
		}
		receipt.Roles = append(receipt.Roles, role)
	}
	for _, role := range receipt.Roles {
		if role.Status != "pass" {
			return finishDomainReceipt(receipt, fmt.Errorf("topology %s domain verification failed", topology.Name))
		}
	}
	return finishDomainReceipt(receipt, nil)
}

func queryDomainIdentity(ctx context.Context, opts lab.RemoteOptions) (domainIdentity, error) {
	stdout, stderr, err := lab.ExecutePowerShell(ctx, opts, `$ErrorActionPreference='Stop'; $cs=Get-CimInstance Win32_ComputerSystem; [ordered]@{computer_name=[string]$cs.Name;domain=[string]$cs.Domain;part_of_domain=[bool]$cs.PartOfDomain;domain_role=[int]$cs.DomainRole}|ConvertTo-Json -Compress`)
	if err != nil {
		return domainIdentity{}, fmt.Errorf("query %s domain identity: %w: %s", opts.ProfileName, err, strings.TrimSpace(string(stderr)))
	}
	var identity domainIdentity
	if err := json.Unmarshal(stdout, &identity); err != nil {
		return identity, fmt.Errorf("decode %s domain identity: %w", opts.ProfileName, err)
	}
	return identity, nil
}

func waitForDomainRole(ctx context.Context, opts lab.RemoteOptions, domain string, minimumRole int) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		identity, err := queryDomainIdentity(ctx, opts)
		if err == nil && identity.PartOfDomain && strings.EqualFold(identity.Domain, domain) && identity.DomainRole >= minimumRole {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s to enter domain %s", opts.ProfileName, domain)
		case <-ticker.C:
		}
	}
}

func finishDomainReceipt(receipt domainProvisionReceipt, result error) (domainProvisionReceipt, error) {
	receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.Status = "complete"
	if result != nil {
		receipt.Status = "failed"
	}
	if writeErr := writeJSON(receipt.ReceiptPath, receipt); writeErr != nil && result == nil {
		result = writeErr
	}
	return receipt, result
}

func finishDomainReceiptWithRole(receipt domainProvisionReceipt, role domainRoleReceipt, result error) (domainProvisionReceipt, error) {
	role.Status, role.Error = "failed", result.Error()
	receipt.Roles = append(receipt.Roles, role)
	return finishDomainReceipt(receipt, result)
}

func psLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func transportDroppedForReboot(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "connection") || strings.Contains(text, "broken pipe") || strings.Contains(text, "exit status 255")
}
