//go:build windows

package main

import (
	"flag"
	"os"

	"golang.org/x/sys/windows/svc"
)

type handler struct{}

func (handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

func main() {
	name := flag.String("service-name", "BOFBenchProofService", "Windows service name")
	flag.Parse()
	if err := svc.Run(*name, handler{}); err != nil {
		os.Exit(1)
	}
}
