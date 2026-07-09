package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const maxProcessStreamBytes = 4 << 20

type boundedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit <= 0 {
		limit = maxProcessStreamBytes
	}
	return &boundedBuffer{limit: limit}
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	if written == 0 {
		return 0, nil
	}
	if len(value) >= buffer.limit {
		buffer.data = append(buffer.data[:0], value[len(value)-buffer.limit:]...)
		buffer.truncated = true
		return written, nil
	}
	if overflow := len(buffer.data) + len(value) - buffer.limit; overflow > 0 {
		copy(buffer.data, buffer.data[overflow:])
		buffer.data = buffer.data[:len(buffer.data)-overflow]
		buffer.truncated = true
	}
	buffer.data = append(buffer.data, value...)
	return written, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), buffer.data...)
}

func (buffer *boundedBuffer) Truncated() bool {
	return buffer.truncated
}

func decodeLoaderOutput(output []byte, result *Result) ([]string, bool) {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return nil, false
	}
	if json.Unmarshal(trimmed, result) == nil {
		return nil, true
	}
	lines := bytes.Split(trimmed, []byte{'\n'})
	for index := len(lines) - 1; index >= 0; index-- {
		candidate := bytes.TrimSpace(lines[index])
		if len(candidate) == 0 || candidate[0] != '{' {
			continue
		}
		if json.Unmarshal(candidate, result) == nil {
			return processLines(bytes.Join(lines[:index], []byte{'\n'})), true
		}
	}
	return processLines(trimmed), false
}

func processLines(value []byte) []string {
	text := strings.TrimSpace(string(value))
	if text == "" {
		return nil
	}
	raw := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func windowsExceptionCode(exitCode int) (string, bool) {
	value := uint32(exitCode)
	if value < 0x80000000 || value > 0xcfffffff {
		return "", false
	}
	return fmt.Sprintf("0x%08x", value), true
}
