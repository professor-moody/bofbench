package argpack

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

type Item struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func ParseTokens(tokens []string) ([]Item, error) {
	items := make([]Item, 0, len(tokens))
	for _, token := range tokens {
		kind, value, ok := strings.Cut(token, ":")
		if !ok {
			return nil, fmt.Errorf("arg token %q must look like z:value, Z:value, i:1, s:1, or b:base64", token)
		}
		switch kind {
		case "z", "Z", "i", "s", "b", "x":
		default:
			return nil, fmt.Errorf("unsupported arg kind %q", kind)
		}
		items = append(items, Item{Kind: kind, Value: trimQuotes(value)})
	}
	return items, nil
}

func PackTokens(tokens []string) ([]byte, []Item, error) {
	items, err := ParseTokens(tokens)
	if err != nil {
		return nil, nil, err
	}
	packed, err := PackItems(items)
	if err != nil {
		return nil, nil, err
	}
	return packed, items, nil
}

func PackItems(items []Item) ([]byte, error) {
	var buf bytes.Buffer
	for _, item := range items {
		switch item.Kind {
		case "z":
			writeBytes(&buf, append([]byte(item.Value), 0))
		case "Z":
			var raw []byte
			for _, r := range utf16.Encode([]rune(item.Value + "\x00")) {
				tmp := make([]byte, 2)
				binary.LittleEndian.PutUint16(tmp, r)
				raw = append(raw, tmp...)
			}
			writeBytes(&buf, raw)
		case "i":
			n, err := strconv.ParseInt(item.Value, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("i:%s: %w", item.Value, err)
			}
			_ = binary.Write(&buf, binary.LittleEndian, int32(n))
		case "s":
			n, err := strconv.ParseInt(item.Value, 0, 16)
			if err != nil {
				return nil, fmt.Errorf("s:%s: %w", item.Value, err)
			}
			_ = binary.Write(&buf, binary.LittleEndian, int16(n))
		case "b":
			raw, err := base64.StdEncoding.DecodeString(item.Value)
			if err != nil {
				return nil, fmt.Errorf("b: invalid base64: %w", err)
			}
			writeBytes(&buf, raw)
		case "x":
			raw, err := hex.DecodeString(strings.TrimPrefix(item.Value, "0x"))
			if err != nil {
				return nil, fmt.Errorf("x: invalid hex: %w", err)
			}
			writeBytes(&buf, raw)
		}
	}
	return buf.Bytes(), nil
}

func Hex(raw []byte) string {
	return hex.EncodeToString(raw)
}

func writeBytes(buf *bytes.Buffer, raw []byte) {
	_ = binary.Write(buf, binary.LittleEndian, int32(len(raw)))
	buf.Write(raw)
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}
