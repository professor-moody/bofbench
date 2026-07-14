//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "BOFBenchTarget"
	targetRoot  = `C:\bofbench\target`
)

var memoryCanary = make([]byte, 64*1024)

type targetState struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Service       string `json:"service"`
	PID           int    `json:"pid"`
	AlertableTID  uint32 `json:"alertable_tid"`
	User          string `json:"user"`
	CanaryFile    string `json:"canary_file"`
	StartedAt     string `json:"started_at"`
}

type handler struct {
	name string
	root string
}

func (service handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if err := os.MkdirAll(service.root, 0o755); err != nil {
		return true, 1
	}
	copy(memoryCanary, []byte("BOFBENCH-TARGET-MEMORY-CANARY-20260713"))
	canaryPath := filepath.Join(service.root, "canary.txt")
	if err := os.WriteFile(canaryPath, []byte("BOFBENCH-TARGET-FILE-CANARY-20260713\n"), 0o600); err != nil {
		return true, 2
	}
	stop := make(chan struct{})
	threadID := make(chan uint32, 1)
	go alertableThread(stop, threadID)
	state := targetState{
		Schema: "bofbench.target", SchemaVersion: 1, Service: service.name,
		PID: os.Getpid(), AlertableTID: <-threadID, User: `NT AUTHORITY\SYSTEM`,
		CanaryFile: canaryPath, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(service.root, "target.json"), append(data, '\n'), 0o600) != nil {
		close(stop)
		return true, 3
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			runtime.KeepAlive(memoryCanary)
			return false, 0
		}
	}
	close(stop)
	return false, 0
}

func alertableThread(stop <-chan struct{}, ready chan<- uint32) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ready <- windows.GetCurrentThreadId()
	for {
		select {
		case <-stop:
			return
		default:
			windows.SleepEx(500, true)
		}
	}
}

func main() {
	name := flag.String("service-name", serviceName, "Windows service name")
	root := flag.String("root", targetRoot, "canary and state directory")
	flag.Parse()
	if err := svc.Run(*name, handler{name: *name, root: *root}); err != nil {
		os.Exit(1)
	}
}
