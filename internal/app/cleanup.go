package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	packsvc "bofbench/internal/pack"
)

// prepareCleanupProject materializes only the cleanup companions selected by a
// project's lock file. The original project is never modified, so a normal run
// cannot accidentally execute its action and cleanup in the same entrypoint.
func prepareCleanupProject(project string) (string, []string, func(), error) {
	lock, _, err := packsvc.LoadLock(project)
	if err != nil {
		return "", nil, func() {}, err
	}
	var cleanupPacks []string
	seen := map[string]bool{}
	for _, record := range lock.Packs {
		cleanup := strings.TrimSpace(record.Cleanup)
		if cleanup == "" {
			continue
		}
		if !strings.Contains(cleanup, "/") && record.Catalog != "" {
			cleanup = record.Catalog + "/" + cleanup
		}
		if !seen[cleanup] {
			seen[cleanup] = true
			cleanupPacks = append(cleanupPacks, cleanup)
		}
	}
	if len(cleanupPacks) == 0 {
		return "", nil, func() {}, fmt.Errorf("%s has no packs with cleanup companions; use 'bofbench pack show <pack> --cleanup' to inspect one", project)
	}
	root, err := os.MkdirTemp("", "bofbench-cleanup-*")
	if err != nil {
		return "", nil, func() {}, err
	}
	remove := func() { _ = os.RemoveAll(root) }
	name := "cleanup"
	tpl, err := templateFor("hello", name)
	if err != nil {
		remove()
		return "", nil, func() {}, err
	}
	files := map[string]string{
		filepath.Join(root, name+".c"):       tpl.Source,
		filepath.Join(root, "beacon.h"):      tpl.Header,
		filepath.Join(root, "bofbench.toml"): tpl.Config,
		filepath.Join(root, "README.md"):     tpl.Readme,
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			remove()
			return "", nil, func() {}, err
		}
	}
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		remove()
		return "", nil, func() {}, err
	}
	if _, err := registry.Apply(root, cleanupPacks); err != nil {
		remove()
		return "", nil, func() {}, err
	}
	return root, cleanupPacks, remove, nil
}

func cleanupNamedArguments(sourceProject, cleanupProject string, values []string) []string {
	cleanupLock, _, err := packsvc.LoadLock(cleanupProject)
	if err != nil {
		return values
	}
	allowed := map[string]bool{}
	for _, record := range cleanupLock.Packs {
		for _, argument := range record.Arguments {
			allowed[strings.ToLower(argument.Name)] = true
		}
	}
	provided := map[string]string{}
	for _, value := range values {
		name, raw, ok := strings.Cut(value, "=")
		if ok {
			provided[strings.ToLower(strings.TrimSpace(name))] = raw
		}
	}
	mapped := map[string]string{}
	if sourceLock, _, lockErr := packsvc.LoadLock(sourceProject); lockErr == nil {
		for _, record := range sourceLock.Packs {
			for target, expression := range record.CleanupArguments {
				source := strings.ToLower(strings.TrimPrefix(expression, "$arg."))
				if raw, ok := provided[source]; ok && allowed[strings.ToLower(target)] {
					mapped[strings.ToLower(target)] = raw
				}
			}
		}
	}
	for name, raw := range provided {
		if allowed[name] {
			if _, mappedByContract := mapped[name]; mappedByContract {
				continue
			}
			mapped[name] = raw
		}
	}
	keys := make([]string, 0, len(mapped))
	for name := range mapped {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	filtered := make([]string, 0, len(keys))
	for _, name := range keys {
		filtered = append(filtered, name+"="+mapped[name])
	}
	return filtered
}
