package argpack

import (
	"encoding/binary"
	"testing"
)

func TestPackTokens(t *testing.T) {
	packed, items, err := PackTokens([]string{"z:hello", "Z:wide", "i:7", "s:2", "b:aGk=", "x:4142"})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 6 {
		t.Fatalf("items = %d", len(items))
	}
	if got := binary.LittleEndian.Uint32(packed[:4]); got != uint32(len(packed)-4) {
		t.Fatalf("argument buffer length = %d, want %d", got, len(packed)-4)
	}
	if got := binary.LittleEndian.Uint32(packed[4:8]); got != 6 {
		t.Fatalf("z length = %d, want 6", got)
	}
	if string(packed[8:14]) != "hello\x00" {
		t.Fatalf("z payload = %q", string(packed[8:14]))
	}
}

func TestPackTokensRejectsBadKind(t *testing.T) {
	if _, _, err := PackTokens([]string{"q:nope"}); err == nil {
		t.Fatal("expected bad kind error")
	}
}

func TestPackTokensRejectsBadInt(t *testing.T) {
	if _, _, err := PackTokens([]string{"i:not-int"}); err == nil {
		t.Fatal("expected bad int error")
	}
}
