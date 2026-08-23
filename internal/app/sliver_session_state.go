package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/runtimecontrol"
)

const activeSliverSessionSchema = "bofbench.active-sliver-session"

type activeSliverSession struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Lab           string `json:"lab"`
	Control       string `json:"control"`
	Session       string `json:"session"`
	ControlHost   string `json:"control_host,omitempty"`
	ReceiptPath   string `json:"receipt_path"`
	ActivatedAt   string `json:"activated_at"`
}

func activeSliverSessionPath(labName string) (string, error) {
	labName = strings.TrimSpace(labName)
	if !safeSliverCommand.MatchString(labName) {
		return "", fmt.Errorf("invalid lab name %q for active Sliver session", labName)
	}
	return filepath.Join(filepath.Dir(runtimecontrol.Path()), "sliver-sessions", labName+".json"), nil
}

func saveActiveSliverSession(state activeSliverSession) error {
	path, err := activeSliverSessionPath(state.Lab)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.Control) == "" || strings.TrimSpace(state.Session) == "" || strings.TrimSpace(state.ReceiptPath) == "" {
		return fmt.Errorf("active Sliver session requires control, session, and receipt path")
	}
	state.Schema = activeSliverSessionSchema
	state.SchemaVersion = 1
	state.ActivatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeOwnerFile(path, append(data, '\n'))
}

func loadActiveSliverSession(labName string) (activeSliverSession, error) {
	path, err := activeSliverSessionPath(labName)
	if err != nil {
		return activeSliverSession{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return activeSliverSession{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var state activeSliverSession
	if err := decoder.Decode(&state); err != nil {
		return activeSliverSession{}, fmt.Errorf("parse active Sliver session %s: %w", path, err)
	}
	if state.Schema != activeSliverSessionSchema || state.SchemaVersion != 1 || state.Lab != strings.TrimSpace(labName) || strings.TrimSpace(state.Session) == "" {
		return activeSliverSession{}, fmt.Errorf("active Sliver session %s has an invalid contract", path)
	}
	return state, nil
}

func removeActiveSliverSession(labName string) error {
	path, err := activeSliverSessionPath(labName)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
