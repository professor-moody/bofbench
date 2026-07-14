package app

import (
	"fmt"

	"bofbench/internal/runtimeadapter"
)

func resolveRuntimeAdapter(name string) (string, error) {
	var adapters []runtimeadapter.Adapter
	for _, adapterName := range []string{"native", "lab", "sliver", "cobaltstrike"} {
		adapter, err := runtimeadapter.New(adapterName, runtimeadapter.Hooks{})
		if err != nil {
			return "", err
		}
		adapters = append(adapters, adapter)
	}
	registry, err := runtimeadapter.NewRegistry(adapters...)
	if err != nil {
		return "", err
	}
	adapter, err := registry.Resolve(name)
	if err != nil {
		return "", fmt.Errorf("--via: %w", err)
	}
	return adapter.Name(), nil
}
