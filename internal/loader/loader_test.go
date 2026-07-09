package loader

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestRunRequiresWindowsOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows behavior only")
	}
	res, err := Run(Request{Object: "missing.o", Entry: "go"})
	if !errors.Is(err, ErrRequiresWindows) {
		t.Fatalf("err = %v, want ErrRequiresWindows", err)
	}
	if res.Status != "setup_error" || res.ExitState != "requires_windows" || res.ErrorCode != "requires_windows" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestBoundedBufferRetainsTail(t *testing.T) {
	buffer := newBoundedBuffer(8)
	_, _ = buffer.Write([]byte("abcdef"))
	_, _ = buffer.Write([]byte("ghijkl"))
	if !buffer.Truncated() || string(buffer.Bytes()) != "efghijkl" {
		t.Fatalf("bounded buffer = %q truncated=%t", buffer.Bytes(), buffer.Truncated())
	}
}

func TestDecodeLoaderOutputUsesFinalJSONLine(t *testing.T) {
	var result Result
	prefix, ok := decodeLoaderOutput([]byte("direct stdout\r\n{\"object\":\"demo.o\",\"entry\":\"go\",\"status\":\"fail\",\"exit_state\":\"validation_error\",\"error_code\":\"section_table_range\"}\r\n"), &result)
	if !ok || result.ErrorCode != "section_table_range" || result.ExitState != "validation_error" {
		t.Fatalf("decoded result = %+v ok=%t", result, ok)
	}
	if len(prefix) != 1 || prefix[0] != "direct stdout" {
		t.Fatalf("protocol prefix = %#v", prefix)
	}
}

func TestDecodeLoaderOutputPreservesMemoryProtocolEvent(t *testing.T) {
	var result Result
	prefix, decoded := decodeLoaderOutput([]byte("{\"protocol_event\":\"memory_protect\",\"memory\":{\"initial_protection\":\"readwrite\",\"sections\":[{\"index\":1,\"name\":\".text\",\"protection\":\"execute_read\"}],\"stub_region\":{\"protection\":\"execute_read\"}}}\n"), &result)
	if decoded || len(prefix) != 0 || result.Memory == nil || len(result.Memory.Sections) != 1 || result.Memory.Sections[0].Protection != "execute_read" {
		t.Fatalf("memory event result = %+v prefix=%#v decoded=%t", result, prefix, decoded)
	}
}

func TestWindowsExceptionClassification(t *testing.T) {
	code, crashed := windowsExceptionCode(int(int32(-1073741819)))
	if !crashed || code != "0xc0000005" {
		t.Fatalf("access violation = %q crashed=%t", code, crashed)
	}
	if code, crashed := windowsExceptionCode(1); crashed || strings.TrimSpace(code) != "" {
		t.Fatalf("normal exit misclassified = %q crashed=%t", code, crashed)
	}
}
