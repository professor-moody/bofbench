package runlog

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func NewDir(prefix string) (string, error) {
	stamp := time.Now().UTC().Format("20060102-150405")
	if err := os.MkdirAll("runs", 0o755); err != nil {
		return "", err
	}
	base := stamp + "-" + prefix
	for suffix := 0; ; suffix++ {
		name := base
		if suffix > 0 {
			name = fmt.Sprintf("%s-%d", base, suffix+1)
		}
		dir := filepath.Join("runs", name)
		if err := os.Mkdir(dir, 0o755); err == nil {
			return dir, nil
		} else if !os.IsExist(err) {
			return "", err
		}
	}
}

func ID(dir string) string {
	return filepath.Base(filepath.Clean(dir))
}
