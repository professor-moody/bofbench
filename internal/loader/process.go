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

type observedBuffer struct {
	buffer   *boundedBuffer
	partial  []byte
	onOutput func(string)
}

func newObservedBuffer(limit int, onOutput func(string)) *observedBuffer {
	return &observedBuffer{buffer: newBoundedBuffer(limit), onOutput: onOutput}
}

func (buffer *observedBuffer) Write(value []byte) (int, error) {
	written, err := buffer.buffer.Write(value)
	if err != nil || buffer.onOutput == nil {
		return written, err
	}
	buffer.partial = append(buffer.partial, value...)
	for {
		index := bytes.IndexByte(buffer.partial, '\n')
		if index < 0 {
			break
		}
		line := append([]byte(nil), bytes.TrimSpace(buffer.partial[:index])...)
		buffer.partial = append(buffer.partial[:0], buffer.partial[index+1:]...)
		if len(line) == 0 {
			continue
		}
		var event struct {
			ProtocolEvent string `json:"protocol_event"`
			Line          string `json:"line"`
		}
		if json.Unmarshal(line, &event) == nil && event.ProtocolEvent == "beacon_output" {
			buffer.onOutput(event.Line)
		}
	}
	return written, nil
}

func (buffer *observedBuffer) Bytes() []byte   { return buffer.buffer.Bytes() }
func (buffer *observedBuffer) Truncated() bool { return buffer.buffer.Truncated() }

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
	lines := bytes.Split(trimmed, []byte{'\n'})
	rawLines := make([][]byte, 0, len(lines))
	decoded := false
	var eventMemory *MemoryEvidence
	for index := 0; index < len(lines); index++ {
		candidate := bytes.TrimSpace(lines[index])
		if len(candidate) == 0 {
			continue
		}
		if candidate[0] != '{' {
			rawLines = append(rawLines, candidate)
			continue
		}
		var envelope struct {
			ProtocolEvent string          `json:"protocol_event"`
			Status        string          `json:"status"`
			ExitState     string          `json:"exit_state"`
			Memory        *MemoryEvidence `json:"memory"`
		}
		if json.Unmarshal(candidate, &envelope) != nil {
			rawLines = append(rawLines, candidate)
			continue
		}
		if envelope.ProtocolEvent != "" {
			if envelope.ProtocolEvent == "memory_protect" && envelope.Memory != nil {
				eventMemory = envelope.Memory
			}
			continue
		}
		if envelope.Status == "" && envelope.ExitState == "" {
			rawLines = append(rawLines, candidate)
			continue
		}
		var decodedResult Result
		if json.Unmarshal(candidate, &decodedResult) == nil {
			*result = decodedResult
			decoded = true
		}
	}
	if result.Memory == nil {
		result.Memory = eventMemory
	}
	return processLines(bytes.Join(rawLines, []byte{'\n'})), decoded
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
