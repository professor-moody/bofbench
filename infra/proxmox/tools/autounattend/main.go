package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	var template, provision, upload, sshPublicKeyFile string
	flag.StringVar(&template, "template", "infra/proxmox/windows/Autounattend.xml.tmpl", "answer-file template")
	flag.StringVar(&provision, "provision", "infra/proxmox/windows/provision.ps1", "PowerShell provisioner")
	flag.StringVar(&sshPublicKeyFile, "ssh-public-key", "", "OpenSSH public key installed for Windows Administrators")
	flag.StringVar(&upload, "upload", "", "scp destination for the generated ISO")
	flag.Parse()
	if upload == "" {
		fatalf("--upload is required")
	}
	password := os.Getenv("BOFBENCH_WINDOWS_TEMPLATE_PASSWORD")
	if password == "" {
		fatalf("BOFBENCH_WINDOWS_TEMPLATE_PASSWORD is empty")
	}
	if sshPublicKeyFile == "" {
		sshPublicKeyFile = os.Getenv("BOFBENCH_WINDOWS_SSH_PUBLIC_KEY_FILE")
	}
	if sshPublicKeyFile == "" {
		fatalf("--ssh-public-key or BOFBENCH_WINDOWS_SSH_PUBLIC_KEY_FILE is required")
	}
	answer, err := os.ReadFile(template)
	if err != nil {
		fatalf("read template: %v", err)
	}
	if strings.ContainsAny(password, "<&") {
		fatalf("template password contains XML-sensitive characters")
	}
	answer = bytes.ReplaceAll(answer, []byte("@@PASSWORD@@"), []byte(password))
	directory, err := os.MkdirTemp("", "bofbench-autounattend-*")
	if err != nil {
		fatalf("temp directory: %v", err)
	}
	defer os.RemoveAll(directory)
	source := filepath.Join(directory, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		fatalf("create ISO source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "Autounattend.xml"), answer, 0o600); err != nil {
		fatalf("write answer: %v", err)
	}
	payload, err := os.ReadFile(provision)
	if err != nil {
		fatalf("read provisioner: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "provision.ps1"), payload, 0o600); err != nil {
		fatalf("write provisioner: %v", err)
	}
	publicKey, err := os.ReadFile(sshPublicKeyFile)
	if err != nil {
		fatalf("read SSH public key: %v", err)
	}
	publicKey = bytes.TrimSpace(publicKey)
	if len(publicKey) == 0 || bytes.ContainsAny(publicKey, "\r\n") {
		fatalf("SSH public key must contain exactly one non-empty line")
	}
	if !bytes.HasPrefix(publicKey, []byte("ssh-")) {
		fatalf("SSH public key has an unsupported format")
	}
	if err := os.WriteFile(filepath.Join(source, "bofbench-authorized-key.pub"), append(publicKey, '\n'), 0o600); err != nil {
		fatalf("write SSH public key: %v", err)
	}
	iso := filepath.Join(directory, "bofbench-win11-autounattend.iso")
	command := exec.Command("hdiutil", "makehybrid", "-quiet", "-iso", "-joliet", "-o", iso, source)
	if output, err := command.CombinedOutput(); err != nil {
		fatalf("build ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	command = exec.Command("scp", iso, upload)
	if output, err := command.CombinedOutput(); err != nil {
		fatalf("upload ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	fmt.Println("Autounattend ISO uploaded; transient plaintext material removed locally")
}

func fatalf(format string, values ...any) { fmt.Fprintf(os.Stderr, format+"\n", values...); os.Exit(1) }
