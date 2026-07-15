package app

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"bofbench/internal/argpack"
	packsvc "bofbench/internal/pack"
	"golang.org/x/term"
)

type resolvedRunArguments struct {
	Tokens    []string
	CLIValues []string
	Names     []string
	Optional  []bool
	Sensitive []bool
}

func resolveRunArguments(project string, named, legacy []string) (resolvedRunArguments, error) {
	if len(named) > 0 && len(legacy) > 0 {
		return resolvedRunArguments{}, fmt.Errorf("use named --arg values or compatibility --args tokens, not both")
	}
	if len(named) == 0 {
		items, err := argpack.ParseTokens(legacy)
		if err != nil {
			return resolvedRunArguments{}, err
		}
		result := resolvedRunArguments{Tokens: append([]string(nil), legacy...)}
		for _, item := range items {
			result.CLIValues = append(result.CLIValues, item.Value)
		}
		return result, nil
	}
	lock, _, err := packsvc.LoadLock(project)
	if err != nil {
		return resolvedRunArguments{}, err
	}
	definitions := map[string]packsvc.Argument{}
	var names []string
	for _, record := range lock.Packs {
		for _, argument := range record.Arguments {
			key := strings.ToLower(argument.Name)
			if existing, ok := definitions[key]; ok && normalizedPackArgumentType(existing.Type) != normalizedPackArgumentType(argument.Type) {
				return resolvedRunArguments{}, fmt.Errorf("pack argument %q has conflicting types %s and %s", argument.Name, existing.Type, argument.Type)
			}
			if _, exists := definitions[key]; !exists {
				names = append(names, key)
			}
			definitions[key] = argument
		}
	}
	if len(definitions) == 0 {
		return resolvedRunArguments{}, fmt.Errorf("%s has no pack argument contract; use compatibility tokens after --args", project)
	}
	values := map[string]string{}
	for _, value := range named {
		name, raw, ok := strings.Cut(value, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || name == "" {
			return resolvedRunArguments{}, fmt.Errorf("--arg %q must look like name=value", value)
		}
		if _, exists := definitions[name]; !exists {
			return resolvedRunArguments{}, fmt.Errorf("unknown pack argument %q", name)
		}
		if _, duplicate := values[name]; duplicate {
			return resolvedRunArguments{}, fmt.Errorf("pack argument %q was provided more than once", name)
		}
		values[name] = raw
	}
	// BOF arguments are positional. Optional arguments may be omitted at the
	// end of the contract, but an omitted optional value before a later value
	// still needs an empty typed slot or every following argument shifts left.
	// This matters in particular for optional authentication context followed
	// by the operation's required target and action arguments.
	lastEmitted := -1
	for index, name := range names {
		definition := definitions[name]
		_, supplied := values[name]
		if supplied || definition.Default != "" || definition.Required {
			lastEmitted = index
		}
	}
	result := resolvedRunArguments{}
	for index, name := range names {
		definition := definitions[name]
		value, supplied := values[name]
		if !supplied && definition.Default != "" {
			value = definition.Default
			supplied = true
		}
		if !supplied {
			if definition.Required {
				return resolvedRunArguments{}, fmt.Errorf("missing required pack argument %q", definition.Name)
			}
			if index > lastEmitted {
				continue
			}
			value = emptyPackArgumentValue(definition.Type)
		}
		if definition.Sensitive && supplied {
			value, err = resolveSensitiveArgument(definition.Name, value)
			if err != nil {
				return resolvedRunArguments{}, err
			}
		}
		token, cliValue, err := packArgumentToken(definition.Type, value)
		if err != nil {
			return resolvedRunArguments{}, fmt.Errorf("argument %s: %w", definition.Name, err)
		}
		result.Tokens = append(result.Tokens, token)
		result.CLIValues = append(result.CLIValues, cliValue)
		result.Names = append(result.Names, definition.Name)
		result.Optional = append(result.Optional, !definition.Required || definition.Default != "")
		result.Sensitive = append(result.Sensitive, definition.Sensitive)
	}
	return result, nil
}

func emptyPackArgumentValue(argumentType string) string {
	switch normalizedPackArgumentType(argumentType) {
	case "integer", "short":
		return "0"
	default:
		return ""
	}
}

func resolveSensitiveArgument(name, value string) (string, error) {
	switch {
	case value == "@prompt":
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", fmt.Errorf("sensitive argument %s requires a terminal for @prompt", name)
		}
		fmt.Fprintf(os.Stderr, "%s: ", name)
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read sensitive argument %s: %w", name, err)
		}
		return string(data), nil
	case strings.HasPrefix(value, "@env:"):
		key := strings.TrimPrefix(value, "@env:")
		if key == "" {
			return "", fmt.Errorf("sensitive argument %s has an empty environment variable name", name)
		}
		resolved, ok := os.LookupEnv(key)
		if !ok {
			return "", fmt.Errorf("sensitive argument %s environment variable %s is not set", name, key)
		}
		return resolved, nil
	case strings.HasPrefix(value, "@file:"):
		path := strings.TrimPrefix(value, "@file:")
		if path == "" {
			return "", fmt.Errorf("sensitive argument %s has an empty file path", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read sensitive argument %s: %w", name, err)
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
	default:
		return value, nil
	}
}

func packArgumentToken(argumentType, value string) (string, string, error) {
	switch normalizedPackArgumentType(argumentType) {
	case "string":
		return "z:" + value, value, nil
	case "wstring":
		return "Z:" + value, value, nil
	case "integer":
		return "i:" + value, value, nil
	case "short":
		return "s:" + value, value, nil
	case "bytes":
		raw := value
		if strings.HasPrefix(value, "@") {
			data, err := os.ReadFile(strings.TrimPrefix(value, "@"))
			if err != nil {
				return "", "", err
			}
			raw = base64.StdEncoding.EncodeToString(data)
		}
		if _, err := base64.StdEncoding.DecodeString(raw); err != nil {
			return "", "", fmt.Errorf("bytes must be base64 or @path: %w", err)
		}
		return "b:" + raw, value, nil
	case "file":
		if value == "" {
			return "x:", "", nil
		}
		data, err := os.ReadFile(value)
		if err != nil {
			return "", "", err
		}
		return "x:" + hex.EncodeToString(data), value, nil
	default:
		return "", "", fmt.Errorf("unsupported pack argument type %q", argumentType)
	}
}

func normalizedPackArgumentType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "str", "z":
		return "string"
	case "wide string", "wide_string", "wstr", "z16", "zwide", "z_upper", "wchar", "z-w", "z_w", "wstring", "zstring":
		return "wstring"
	case "int", "i", "int32":
		return "integer"
	case "int16", "s":
		return "short"
	case "binary", "blob", "b":
		return "bytes"
	case "path", "x":
		return "file"
	default:
		return value
	}
}
