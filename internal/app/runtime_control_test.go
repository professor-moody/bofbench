package app

import "testing"

func TestParseSSHKeyscanPinsExactHostAndKeyType(t *testing.T) {
	data := []byte("# 10.12.90.40:22 SSH-2.0-OpenSSH\n10.12.90.40 ssh-rsa ignored\n10.12.90.40 ssh-ed25519 AQID\n")
	line, fingerprint, err := parseSSHKeyscan(data, "10.12.90.40", 22)
	if err != nil {
		t.Fatal(err)
	}
	if line != "10.12.90.40 ssh-ed25519 AQID" {
		t.Fatalf("line = %q", line)
	}
	if fingerprint != "SHA256:A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc+4E" {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
}

func TestParseSSHKeyscanRequiresBracketedNonDefaultPort(t *testing.T) {
	if _, _, err := parseSSHKeyscan([]byte("10.12.90.40 ssh-ed25519 AQID\n"), "10.12.90.40", 2222); err == nil {
		t.Fatal("expected an unbracketed non-default-port host key to be rejected")
	}
	if _, _, err := parseSSHKeyscan([]byte("[10.12.90.40]:2222 ssh-ed25519 AQID\n"), "10.12.90.40", 2222); err != nil {
		t.Fatal(err)
	}
}
