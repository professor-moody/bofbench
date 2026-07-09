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
	if got := binary.LittleEndian.Uint32(packed[:4]); got != 6 {
		t.Fatalf("z length = %d, want 6", got)
	}
	if string(packed[4:10]) != "hello\x00" {
		t.Fatalf("z payload = %q", string(packed[4:10]))
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
