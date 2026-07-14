package app

import (
	"strings"

	"bofbench/internal/argpack"
	packsvc "bofbench/internal/pack"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/runtimeadapter"
)

func runtimeSensitivity(project string, resolved resolvedRunArguments) (fields, names, values []string) {
	if lock, _, err := packsvc.LoadLock(project); err == nil {
		seen := map[string]bool{}
		for _, record := range lock.Packs {
			for _, field := range record.SensitiveOutputFields {
				if field != "" && !seen[field] {
					seen[field] = true
					fields = append(fields, field)
				}
			}
		}
	}
	for index, sensitive := range resolved.Sensitive {
		if !sensitive {
			continue
		}
		if index < len(resolved.Names) {
			names = append(names, resolved.Names[index])
		}
		if index < len(resolved.CLIValues) && resolved.CLIValues[index] != "" {
			values = append(values, resolved.CLIValues[index])
		}
	}
	return fields, names, values
}

func redactRuntimeLines(lines, fields, secrets []string) []string {
	result := make([]string, len(lines))
	for index, line := range lines {
		for _, secret := range secrets {
			if secret != "" {
				line = strings.ReplaceAll(line, secret, "<redacted>")
			}
		}
		for _, field := range fields {
			line = redactStructuredField(line, field)
		}
		result[index] = line
	}
	return result
}

func redactStructuredField(line, field string) string {
	needle := field + "="
	for start := 0; start < len(line); {
		index := strings.Index(line[start:], needle)
		if index < 0 {
			break
		}
		index += start
		if index > 0 {
			previous := line[index-1]
			if previous != ' ' && previous != '\t' && previous != '[' {
				start = index + len(needle)
				continue
			}
		}
		end := index + len(needle)
		for end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != '\r' && line[end] != '\n' {
			end++
		}
		line = line[:index+len(needle)] + "<redacted>" + line[end:]
		start = index + len(needle) + len("<redacted>")
	}
	return line
}

func (run *runtimeRunContext) redactReceipt(receipt runtimeadapter.Receipt) runtimeadapter.Receipt {
	return redactReceiptValues(receipt, run.sensitiveOutputFields, run.sensitiveArgumentNames, run.sensitiveValues)
}

func redactReceiptValues(receipt runtimeadapter.Receipt, fields, names, values []string) runtimeadapter.Receipt {
	receipt.Output = redactRuntimeLines(receipt.Output, fields, values)
	receipt.Error = redactRuntimeLines([]string{receipt.Error}, nil, values)[0]
	receipt.SensitiveArguments = append([]string(nil), names...)
	receipt.RedactedOutputFields = append([]string(nil), fields...)
	return receipt
}

func (run *runtimeRunContext) redactResult(result runtimesvc.Result) runtimesvc.Result {
	result.Output = redactRuntimeLines(result.Output, run.sensitiveOutputFields, run.sensitiveValues)
	result.Errors = redactRuntimeLines(result.Errors, nil, run.sensitiveValues)
	for index := range result.Events {
		result.Events[index].Message = redactRuntimeLines([]string{result.Events[index].Message}, run.sensitiveOutputFields, run.sensitiveValues)[0]
	}
	if result.LoaderProcess != nil {
		process := *result.LoaderProcess
		process.Stdout = redactRuntimeLines(process.Stdout, run.sensitiveOutputFields, run.sensitiveValues)
		process.Stderr = redactRuntimeLines(process.Stderr, nil, run.sensitiveValues)
		result.LoaderProcess = &process
	}
	return result
}

func (run *runtimeRunContext) redactItems(items []argpack.Item) []argpack.Item {
	result := append([]argpack.Item(nil), items...)
	for index := range result {
		if index < len(run.resolved.Sensitive) && run.resolved.Sensitive[index] {
			result[index].Value = "<redacted>"
		}
	}
	return result
}
