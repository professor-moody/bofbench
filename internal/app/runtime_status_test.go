package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"bofbench/internal/runtimeadapter"
)

func TestWaitForRuntimeSessionPollsUntilReady(t *testing.T) {
	polls := 0
	adapter, err := runtimeadapter.New("sliver", runtimeadapter.Hooks{Sessions: func(context.Context) ([]runtimeadapter.Session, error) {
		polls++
		if polls < 3 {
			return nil, nil
		}
		return []runtimeadapter.Session{{ID: "session-1", Host: "DEVBOX"}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := waitForRuntimeSession(context.Background(), adapter, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "session-1" || polls != 3 {
		t.Fatalf("sessions=%+v polls=%d", sessions, polls)
	}
}

func TestWaitForRuntimeSessionHonorsTimeout(t *testing.T) {
	adapter, err := runtimeadapter.New("sliver", runtimeadapter.Hooks{Sessions: func(context.Context) ([]runtimeadapter.Session, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err = waitForRuntimeSession(ctx, adapter, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("error=%v", err)
	}
}
