package runlog

import (
	"os"
	"path/filepath"
	"time"
)

func NewDir(prefix string) (string, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	dir := filepath.Join("runs", stamp+"-"+prefix)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
