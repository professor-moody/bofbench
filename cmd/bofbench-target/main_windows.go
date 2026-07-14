//go:build windows

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName     = "BOFBenchTarget"
	targetRoot      = `C:\bofbench\target`
	credentialName  = "BOFBench-LiveProof"
	credentialType  = 1
	credentialLocal = 2
	dpapiMachine    = 0x4
)

var (
	memoryCanary     = make([]byte, 64*1024)
	advapi32         = windows.NewLazySystemDLL("advapi32.dll")
	crypt32          = windows.NewLazySystemDLL("crypt32.dll")
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procCredWriteW   = advapi32.NewProc("CredWriteW")
	procCredDeleteW  = advapi32.NewProc("CredDeleteW")
	procCryptProtect = crypt32.NewProc("CryptProtectData")
	procLocalFree    = kernel32.NewProc("LocalFree")
)

type targetState struct {
	Schema              string `json:"schema"`
	SchemaVersion       int    `json:"schema_version"`
	Service             string `json:"service"`
	PID                 int    `json:"pid"`
	AlertableTID        uint32 `json:"alertable_tid"`
	NamedPipe           string `json:"named_pipe,omitempty"`
	User                string `json:"user"`
	CanaryFile          string `json:"canary_file"`
	CanaryFileSHA256    string `json:"canary_file_sha256"`
	MemoryCanaryAddress string `json:"memory_canary_address"`
	MemoryCanarySize    int    `json:"memory_canary_size"`
	MemoryCanarySHA256  string `json:"memory_canary_sha256"`
	FixtureError        string `json:"fixture_error,omitempty"`
	StartedAt           string `json:"started_at"`
}

type fixtureState struct {
	Schema             string `json:"schema"`
	SchemaVersion      int    `json:"schema_version"`
	User               string `json:"user"`
	CredentialTarget   string `json:"credential_target"`
	CredentialSHA256   string `json:"credential_sha256"`
	CredentialSize     int    `json:"credential_size"`
	DPAPIUserPath      string `json:"dpapi_user_path"`
	DPAPIUserSHA256    string `json:"dpapi_user_sha256"`
	DPAPIMachinePath   string `json:"dpapi_machine_path"`
	DPAPIMachineSHA256 string `json:"dpapi_machine_sha256"`
	WMIMarkerPath      string `json:"wmi_marker_path"`
	CreatedAt          string `json:"created_at"`
}

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type dataBlob struct {
	Size uint32
	Data *byte
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
	canary := randomBytes(64)
	copy(memoryCanary, canary)
	fileCanary := append([]byte("BOFBENCH-TARGET-FILE-CANARY\n"), randomBytes(32)...)
	canaryPath := filepath.Join(service.root, "canary.txt")
	if err := os.WriteFile(canaryPath, fileCanary, 0o600); err != nil {
		return true, 2
	}
	stop := make(chan struct{})
	threadID := make(chan uint32, 1)
	go alertableThread(stop, threadID)
	pipeReady := make(chan namedPipeResult, 1)
	go namedPipeFixture(stop, pipeReady)
	pipe := <-pipeReady
	fixtureErr := launchFixtureInConsoleSession(service.root, "deploy")
	state := targetState{
		Schema: "bofbench.target", SchemaVersion: 2, Service: service.name,
		PID: os.Getpid(), AlertableTID: <-threadID, NamedPipe: pipe.Name, User: `NT AUTHORITY\SYSTEM`,
		CanaryFile: canaryPath, CanaryFileSHA256: hashBytes(fileCanary),
		MemoryCanaryAddress: fmt.Sprintf("0x%X", uintptr(unsafe.Pointer(&memoryCanary[0]))),
		MemoryCanarySize:    len(canary), MemoryCanarySHA256: hashBytes(canary),
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if fixtureErr != nil {
		state.FixtureError = fixtureErr.Error()
	}
	if pipe.Err != nil {
		if state.FixtureError != "" {
			state.FixtureError += "; "
		}
		state.FixtureError += pipe.Err.Error()
	}
	if err := writeJSON(filepath.Join(service.root, "target.json"), state); err != nil {
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
			_ = launchFixtureInConsoleSession(service.root, "remove")
			close(stop)
			runtime.KeepAlive(memoryCanary)
			return false, 0
		}
	}
	close(stop)
	runtime.KeepAlive(memoryCanary)
	return false, 0
}

func launchFixtureInConsoleSession(root, operation string) error {
	sessionID, token, err := interactiveUserToken()
	if err != nil {
		return fmt.Errorf("select interactive user for %s fixtures: %w", operation, err)
	}
	defer token.Close()
	var environment *uint16
	if err := windows.CreateEnvironmentBlock(&environment, token, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock session %d: %w", sessionID, err)
	}
	defer windows.DestroyEnvironmentBlock(environment)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	commandLine, err := windows.UTF16PtrFromString(fmt.Sprintf(`"%s" --fixture %s --root "%s"`, executable, operation, root))
	if err != nil {
		return err
	}
	currentDirectory, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var process windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, nil, commandLine, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, environment, currentDirectory, &startup, &process); err != nil {
		return fmt.Errorf("CreateProcessAsUser session %d: %w", sessionID, err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	wait, err := windows.WaitForSingleObject(process.Process, 15_000)
	if err != nil {
		return fmt.Errorf("wait for fixture process: %w", err)
	}
	if wait != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("fixture process wait result %d", wait)
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("fixture process exited %d", exitCode)
	}
	return nil
}

func interactiveUserToken() (uint32, windows.Token, error) {
	consoleID := windows.WTSGetActiveConsoleSessionId()
	if consoleID != 0xffffffff {
		var token windows.Token
		if err := windows.WTSQueryUserToken(consoleID, &token); err == nil {
			return consoleID, token, nil
		}
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return 0, 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	items := unsafe.Slice(sessions, int(count))
	for _, wanted := range []uint32{windows.WTSActive, windows.WTSConnected, windows.WTSDisconnected} {
		for _, session := range items {
			if session.State != wanted || session.SessionID == consoleID {
				continue
			}
			var token windows.Token
			if err := windows.WTSQueryUserToken(session.SessionID, &token); err == nil {
				return session.SessionID, token, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("no active, connected, or disconnected user token is available")
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

type namedPipeResult struct {
	Name string
	Err  error
}

func namedPipeFixture(stop <-chan struct{}, ready chan<- namedPipeResult) {
	name := fmt.Sprintf(`\\.\pipe\BOFBenchTarget-%d`, os.Getpid())
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		ready <- namedPipeResult{Err: fmt.Errorf("prepare named-pipe fixture: %w", err)}
		return
	}
	handle, err := windows.CreateNamedPipe(namePtr, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		ready <- namedPipeResult{Err: fmt.Errorf("create named-pipe fixture: %w", err)}
		return
	}
	ready <- namedPipeResult{Name: name}
	<-stop
	_ = windows.CloseHandle(handle)
}

func deployFixtures(root string) (fixtureState, error) {
	fixtureRoot := filepath.Join(root, "fixtures")
	if err := os.MkdirAll(fixtureRoot, 0o700); err != nil {
		return fixtureState{}, err
	}
	credentialCanary := randomBytes(48)
	userCanary := randomBytes(48)
	machineCanary := randomBytes(48)
	if err := writeCredential(credentialName, credentialCanary); err != nil {
		return fixtureState{}, err
	}
	userPath := filepath.Join(fixtureRoot, "dpapi-user.bin")
	machinePath := filepath.Join(fixtureRoot, "dpapi-machine.bin")
	if err := protectFile(userPath, userCanary, false); err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	if err := protectFile(machinePath, machineCanary, true); err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	state := fixtureState{
		Schema: "bofbench.target-fixtures", SchemaVersion: 1, User: currentUser(),
		CredentialTarget: credentialName, CredentialSHA256: hashBytes(credentialCanary), CredentialSize: len(credentialCanary),
		DPAPIUserPath: userPath, DPAPIUserSHA256: hashBytes(userCanary),
		DPAPIMachinePath: machinePath, DPAPIMachineSHA256: hashBytes(machineCanary),
		WMIMarkerPath: filepath.Join(fixtureRoot, "wmi-marker.txt"), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSON(filepath.Join(fixtureRoot, "fixture.json"), state); err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	return state, nil
}

func readFixtures(root string) (fixtureState, error) {
	var state fixtureState
	data, err := os.ReadFile(filepath.Join(root, "fixtures", "fixture.json"))
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	return state, nil
}

func removeFixtures(root string) error {
	deleteCredential(credentialName)
	return os.RemoveAll(filepath.Join(root, "fixtures"))
}

func writeCredential(name string, payload []byte) error {
	target, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	comment, _ := windows.UTF16PtrFromString("Disposable BOFBench capability-proof fixture")
	username, _ := windows.UTF16PtrFromString(currentUser())
	value := credential{Type: credentialType, TargetName: target, Comment: comment, CredentialBlobSize: uint32(len(payload)), CredentialBlob: &payload[0], Persist: credentialLocal, UserName: username}
	ok, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&value)), 0)
	runtime.KeepAlive(payload)
	if ok == 0 {
		return fmt.Errorf("CredWriteW: %w", callErr)
	}
	return nil
}

func deleteCredential(name string) {
	target, err := windows.UTF16PtrFromString(name)
	if err == nil {
		procCredDeleteW.Call(uintptr(unsafe.Pointer(target)), credentialType, 0)
	}
}

func protectFile(path string, payload []byte, machine bool) error {
	in := dataBlob{Size: uint32(len(payload)), Data: &payload[0]}
	var out dataBlob
	flags := uintptr(0)
	if machine {
		flags = dpapiMachine
	}
	description, _ := windows.UTF16PtrFromString("BOFBench disposable fixture")
	ok, _, callErr := procCryptProtect.Call(uintptr(unsafe.Pointer(&in)), uintptr(unsafe.Pointer(description)), 0, 0, 0, flags, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(payload)
	if ok == 0 {
		return fmt.Errorf("CryptProtectData: %w", callErr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	protected := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	return os.WriteFile(path, protected, 0o600)
}

func currentUser() string {
	domain := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	user := strings.TrimSpace(os.Getenv("USERNAME"))
	if domain != "" && user != "" {
		return domain + `\` + user
	}
	if user != "" {
		return user
	}
	return "unknown"
}

func randomBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return value
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func main() {
	name := flag.String("service-name", serviceName, "Windows service name")
	root := flag.String("root", targetRoot, "canary and state directory")
	fixture := flag.String("fixture", "", "fixture operation: deploy, status, or remove")
	flag.Parse()
	switch strings.ToLower(strings.TrimSpace(*fixture)) {
	case "deploy":
		state, err := deployFixtures(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := printJSON(state); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "status":
		state, err := readFixtures(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := printJSON(state); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case "remove":
		if err := removeFixtures(*root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = printJSON(map[string]string{"status": "removed"})
		return
	case "":
	default:
		os.Exit(2)
	}
	if err := svc.Run(*name, handler{name: *name, root: *root}); err != nil {
		os.Exit(1)
	}
}
