package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"bofbench/internal/lab"
	packsvc "bofbench/internal/pack"
)

type resolvedTopologyValues struct {
	Topology lab.ResolvedTopology
	Values   map[string]string
}

func resolveTopologyRuntimeValues(ctx context.Context, name, profilesPath string) (resolvedTopologyValues, error) {
	resolved, err := lab.ResolveTopology(name, profilesPath)
	if err != nil {
		return resolvedTopologyValues{}, err
	}
	values := map[string]string{}
	roles := []struct {
		key  string
		item *lab.ResolvedProfile
	}{{"execution", &resolved.Execution}, {"target", resolved.Target}, {"domain_controller", resolved.DomainController}}
	for _, role := range roles {
		if role.item == nil {
			continue
		}
		remote, err := lab.ResolveRemoteOptions(ctx, role.item.Name, role.item.Profile)
		if err != nil {
			return resolvedTopologyValues{}, fmt.Errorf("resolve topology %s role %s: %w", resolved.Name, role.key, err)
		}
		status, err := lab.RemoteStatus(ctx, remote)
		if err != nil {
			return resolvedTopologyValues{}, fmt.Errorf("inspect topology %s role %s: %w", resolved.Name, role.key, err)
		}
		if strings.TrimSpace(status.ComputerName) == "" {
			return resolvedTopologyValues{}, fmt.Errorf("topology %s role %s returned no Windows computer name", resolved.Name, role.key)
		}
		values[role.key+".computer_name"] = status.ComputerName
		if role.key == "domain_controller" {
			stdout, stderr, queryErr := lab.ExecutePowerShell(ctx, remote, `$ErrorActionPreference='Stop'; $cs=Get-CimInstance Win32_ComputerSystem; [ordered]@{domain=[string]$cs.Domain;part_of_domain=[bool]$cs.PartOfDomain}|ConvertTo-Json -Compress`)
			if queryErr != nil {
				return resolvedTopologyValues{}, fmt.Errorf("read domain identity from %s: %w: %s", role.item.Name, queryErr, strings.TrimSpace(string(stderr)))
			}
			var domain struct {
				Name         string `json:"domain"`
				PartOfDomain bool   `json:"part_of_domain"`
			}
			if err := json.Unmarshal(stdout, &domain); err != nil {
				return resolvedTopologyValues{}, fmt.Errorf("decode domain identity from %s: %w", role.item.Name, err)
			}
			if !domain.PartOfDomain || strings.TrimSpace(domain.Name) == "" {
				return resolvedTopologyValues{}, fmt.Errorf("topology %s domain_controller profile %s is not joined to a domain", resolved.Name, role.item.Name)
			}
			values["domain.name"] = domain.Name
			values["domain.base_dn"] = domainBaseDN(domain.Name)
		}
	}
	for setName, profiles := range resolved.TargetSets {
		computerNames := make([]string, 0, len(profiles))
		profileNames := make([]string, 0, len(profiles))
		for _, profile := range profiles {
			remote, err := lab.ResolveRemoteOptions(ctx, profile.Name, profile.Profile)
			if err != nil {
				return resolvedTopologyValues{}, fmt.Errorf("resolve topology %s target set %s profile %s: %w", resolved.Name, setName, profile.Name, err)
			}
			status, err := lab.RemoteStatus(ctx, remote)
			if err != nil {
				return resolvedTopologyValues{}, fmt.Errorf("inspect topology %s target set %s profile %s: %w", resolved.Name, setName, profile.Name, err)
			}
			if strings.TrimSpace(status.ComputerName) == "" {
				return resolvedTopologyValues{}, fmt.Errorf("topology %s target set %s profile %s returned no Windows computer name", resolved.Name, setName, profile.Name)
			}
			computerNames = append(computerNames, status.ComputerName)
			profileNames = append(profileNames, profile.Name)
			values["target_sets."+setName+"."+profile.Name+".computer_name"] = status.ComputerName
		}
		values["target_sets."+setName+".computer_names"] = strings.Join(computerNames, ",")
		values["target_sets."+setName+".profiles"] = strings.Join(profileNames, ",")
	}
	return resolvedTopologyValues{Topology: resolved, Values: values}, nil
}

func domainBaseDN(domain string) string {
	var parts []string
	for _, label := range strings.Split(domain, ".") {
		if label = strings.TrimSpace(label); label != "" {
			parts = append(parts, "DC="+label)
		}
	}
	return strings.Join(parts, ",")
}

func topologyNamedArguments(ctx context.Context, input string, topology resolvedTopologyValues, existing []string) ([]string, error) {
	lock, _, err := packsvc.LoadLock(input)
	if err != nil {
		return existing, err
	}
	provided := map[string]bool{}
	for _, value := range existing {
		if index := strings.IndexByte(value, '='); index > 0 {
			provided[strings.TrimSpace(value[:index])] = true
		}
	}
	result := append([]string(nil), existing...)
	for _, record := range lock.Packs {
		for _, argument := range record.Arguments {
			if argument.TopologyValue == "" || provided[argument.Name] {
				continue
			}
			value := topology.Values[argument.TopologyValue]
			if value == "" {
				return nil, fmt.Errorf("pack argument %s needs topology value %s, but topology %s does not provide it", argument.Name, argument.TopologyValue, topology.Topology.Name)
			}
			result = append(result, argument.Name+"="+value)
			provided[argument.Name] = true
		}
	}
	return result, nil
}
