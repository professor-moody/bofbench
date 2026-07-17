//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName     = "BOFBenchTarget"
	targetRoot      = `C:\bofbench\target`
	etwProviderGUID = "{E62DA5C7-2D12-4F34-A73C-832889B50F3B}"
	credentialName  = "BOFBench-LiveProof"
	credentialType  = 1
	credentialLocal = 2
	dpapiMachine    = 0x4
)

var (
	memoryCanary         = make([]byte, 64*1024)
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	ntdll                = windows.NewLazySystemDLL("ntdll.dll")
	procCredWriteW       = advapi32.NewProc("CredWriteW")
	procCredDeleteW      = advapi32.NewProc("CredDeleteW")
	procEventRegister    = advapi32.NewProc("EventRegister")
	procEventWriteString = advapi32.NewProc("EventWriteString")
	procEventUnregister  = advapi32.NewProc("EventUnregister")
	procCryptProtect     = crypt32.NewProc("CryptProtectData")
	procLocalFree        = kernel32.NewProc("LocalFree")
	procModuleHandle     = kernel32.NewProc("GetModuleHandleW")
	procCreateMutex      = kernel32.NewProc("CreateMutexW")
	procCreateSemaphore  = kernel32.NewProc("CreateSemaphoreW")
	procCreateTimer      = kernel32.NewProc("CreateWaitableTimerW")
	procCreateMailslot   = kernel32.NewProc("CreateMailslotW")
	procGetMailslotInfo  = kernel32.NewProc("GetMailslotInfo")
	procPeekNamedPipe    = kernel32.NewProc("PeekNamedPipe")
	procNtQuerySystem    = ntdll.NewProc("NtQuerySystemInformation")
)

type targetState struct {
	Schema                string `json:"schema"`
	SchemaVersion         int    `json:"schema_version"`
	Service               string `json:"service"`
	PID                   int    `json:"pid"`
	Architecture          string `json:"architecture,omitempty"`
	KnownModuleBase       string `json:"known_module_base,omitempty"`
	KnownModulePath       string `json:"known_module_path,omitempty"`
	X86PID                int    `json:"x86_pid,omitempty"`
	X86AlertableTID       uint32 `json:"x86_alertable_tid,omitempty"`
	X86KnownModuleBase    string `json:"x86_known_module_base,omitempty"`
	X86KnownModulePath    string `json:"x86_known_module_path,omitempty"`
	AlertableTID          uint32 `json:"alertable_tid"`
	NamedPipe             string `json:"named_pipe,omitempty"`
	NamedPipeHandle       string `json:"named_pipe_handle,omitempty"`
	NamedPipeClientHandle string `json:"named_pipe_client_handle,omitempty"`
	NamedPipeSHA256       string `json:"named_pipe_sha256,omitempty"`
	ProcessPipePID        int    `json:"process_pipe_pid,omitempty"`
	ProcessStdinHandle    string `json:"process_stdin_handle,omitempty"`
	ProcessStdoutHandle   string `json:"process_stdout_handle,omitempty"`
	ProcessPipeSHA256     string `json:"process_pipe_sha256,omitempty"`
	KnownHandle           string `json:"known_handle,omitempty"`
	HolderPID             int    `json:"holder_pid,omitempty"`
	JobMemberPID          int    `json:"job_member_pid,omitempty"`
	EventName             string `json:"event_name,omitempty"`
	SectionName           string `json:"section_name,omitempty"`
	JobName               string `json:"job_name,omitempty"`
	MutexName             string `json:"mutex_name,omitempty"`
	SemaphoreName         string `json:"semaphore_name,omitempty"`
	TimerName             string `json:"timer_name,omitempty"`
	MailslotName          string `json:"mailslot_name,omitempty"`
	MailslotHandle        string `json:"mailslot_handle,omitempty"`
	MailslotSHA256        string `json:"mailslot_sha256,omitempty"`
	MailslotAccess        uint32 `json:"mailslot_access,omitempty"`
	ALPCPort              string `json:"alpc_port,omitempty"`
	ALPCHandle            string `json:"alpc_handle,omitempty"`
	WindowHandle          string `json:"window_handle,omitempty"`
	WindowTextHandle      string `json:"window_text_handle,omitempty"`
	WindowHelperPID       int    `json:"window_helper_pid,omitempty"`
	WindowStation         string `json:"window_station,omitempty"`
	WindowClass           string `json:"window_class,omitempty"`
	WindowMessage         uint32 `json:"window_message,omitempty"`
	WindowPostMessage     uint32 `json:"window_post_message,omitempty"`
	WatchRegistryHive     string `json:"watch_registry_hive,omitempty"`
	WatchRegistryPath     string `json:"watch_registry_path,omitempty"`
	WatchRegistryValue    string `json:"watch_registry_value,omitempty"`
	WatchDirectory        string `json:"watch_directory,omitempty"`
	WatchService          string `json:"watch_service,omitempty"`
	ExitPID               int    `json:"exit_pid,omitempty"`
	EventLogChannel       string `json:"event_log_channel,omitempty"`
	EventLogProvider      string `json:"event_log_provider,omitempty"`
	ETWProviderGUID       string `json:"etw_provider_guid,omitempty"`
	ETWSessionName        string `json:"etw_session_name,omitempty"`
	TCPHost               string `json:"tcp_host,omitempty"`
	TCPPort               int    `json:"tcp_port,omitempty"`
	UDPHost               string `json:"udp_host,omitempty"`
	UDPPort               int    `json:"udp_port,omitempty"`
	HTTPURL               string `json:"http_url,omitempty"`
	HTTPBlobURL           string `json:"http_blob_url,omitempty"`
	HTTPTransientURL      string `json:"http_transient_url,omitempty"`
	HTTPSURL              string `json:"https_url,omitempty"`
	HTTPSBlobURL          string `json:"https_blob_url,omitempty"`
	HTTPSAuthURL          string `json:"https_auth_url,omitempty"`
	HTTPAuthUser          string `json:"http_auth_user,omitempty"`
	TLSCertificateSHA256  string `json:"tls_certificate_sha256,omitempty"`
	WebSocketURL          string `json:"websocket_url,omitempty"`
	DNSName               string `json:"dns_name,omitempty"`
	NetworkPayloadSHA256  string `json:"network_payload_sha256,omitempty"`
	User                  string `json:"user"`
	CanaryFile            string `json:"canary_file"`
	CanaryFileSHA256      string `json:"canary_file_sha256"`
	MoveCanaryFile        string `json:"move_canary_file"`
	MoveCanarySHA256      string `json:"move_canary_sha256"`
	MemoryCanaryAddress   string `json:"memory_canary_address"`
	MemoryCanarySize      int    `json:"memory_canary_size"`
	MemoryCanarySHA256    string `json:"memory_canary_sha256"`
	ExecutionAddress      string `json:"execution_address"`
	MemoryWriteAddress    string `json:"memory_write_address,omitempty"`
	MemoryWriteSize       int    `json:"memory_write_size,omitempty"`
	MemoryWriteSHA256     string `json:"memory_write_sha256,omitempty"`
	MemoryProtectAddress  string `json:"memory_protection_address,omitempty"`
	MemoryProtectSize     int    `json:"memory_protection_size,omitempty"`
	MemoryProtection      string `json:"memory_protection,omitempty"`
	FixtureError          string `json:"fixture_error,omitempty"`
	StartedAt             string `json:"started_at"`
}

type fixtureState struct {
	Schema                 string `json:"schema"`
	SchemaVersion          int    `json:"schema_version"`
	User                   string `json:"user"`
	CredentialTarget       string `json:"credential_target"`
	CredentialSHA256       string `json:"credential_sha256"`
	CredentialSize         int    `json:"credential_size"`
	DPAPIUserPath          string `json:"dpapi_user_path"`
	DPAPIUserSHA256        string `json:"dpapi_user_sha256"`
	DPAPIUserFileSHA256    string `json:"dpapi_user_file_sha256"`
	DPAPIMachinePath       string `json:"dpapi_machine_path"`
	DPAPIMachineSHA256     string `json:"dpapi_machine_sha256"`
	DPAPIMachineFileSHA256 string `json:"dpapi_machine_file_sha256"`
	WMIMarkerPath          string `json:"wmi_marker_path"`
	VaultGUID              string `json:"vault_guid,omitempty"`
	VaultResource          string `json:"vault_resource,omitempty"`
	VaultIdentity          string `json:"vault_identity,omitempty"`
	VaultSHA256            string `json:"vault_sha256,omitempty"`
	VaultSize              int    `json:"vault_size,omitempty"`
	CertificateStore       string `json:"certificate_store,omitempty"`
	CertificateSubject     string `json:"certificate_subject,omitempty"`
	CertificateThumbprint  string `json:"certificate_thumbprint,omitempty"`
	CreatedAt              string `json:"created_at"`
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

type helperHandler struct {
	name string
	root string
}

func (service helperHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if err := os.MkdirAll(service.root, 0o755); err != nil {
		return true, 1
	}
	stop := make(chan struct{})
	threadID := make(chan uint32, 1)
	go alertableThread(stop, threadID)
	state := targetState{Schema: "bofbench.target-helper", SchemaVersion: 11, Service: service.name, PID: os.Getpid(), Architecture: runtime.GOARCH, AlertableTID: <-threadID, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if module, _, _ := procModuleHandle.Call(0); module != 0 {
		state.KnownModuleBase = fmt.Sprintf("0x%X", module)
	}
	state.KnownModulePath, _ = os.Executable()
	if err := writeJSON(filepath.Join(service.root, "x86-helper.json"), state); err != nil {
		close(stop)
		return true, 2
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			return false, 0
		}
	}
	close(stop)
	return false, 0
}

func (service handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if err := os.MkdirAll(service.root, 0o755); err != nil {
		return true, 1
	}
	canary := randomBytes(64)
	copy(canary[24:], []byte("BOFBenchOperationNeedle"))
	copy(memoryCanary, canary)
	executionRegion, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return true, 2
	}
	defer windows.VirtualFree(executionRegion, 0, windows.MEM_RELEASE)
	*(*byte)(unsafe.Pointer(executionRegion)) = 0xc3
	writeRegion, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return true, 3
	}
	defer windows.VirtualFree(writeRegion, 0, windows.MEM_RELEASE)
	writeCanary := randomBytes(18)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(writeRegion)), 18), writeCanary)
	protectRegion, err := windows.VirtualAlloc(0, 4096, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return true, 2
	}
	defer windows.VirtualFree(protectRegion, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(protectRegion)), 64), randomBytes(64))
	fileCanary := append([]byte("BOFBENCH-TARGET-FILE-CANARY\n"), randomBytes(32)...)
	canaryPath := filepath.Join(service.root, "canary.txt")
	if err := os.WriteFile(canaryPath, fileCanary, 0o600); err != nil {
		return true, 2
	}
	moveCanary := append([]byte("BOFBENCH-TARGET-MOVE-CANARY\n"), randomBytes(32)...)
	moveCanaryPath := filepath.Join(service.root, "move-canary.bin")
	if err := os.WriteFile(moveCanaryPath, moveCanary, 0o600); err != nil {
		return true, 2
	}
	knownFile, err := os.Open(canaryPath)
	if err != nil {
		return true, 2
	}
	defer knownFile.Close()
	objectSD, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)S:(ML;;NW;;;LW)")
	if err != nil {
		return true, 2
	}
	currentProcess, currentProcessErr := windows.GetCurrentProcess()
	currentProcessDACL, _, currentProcessDACLErr := objectSD.DACL()
	if currentProcessErr != nil || currentProcessDACLErr != nil || windows.SetSecurityInfo(currentProcess, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, currentProcessDACL, nil) != nil {
		return true, 2
	}
	objectSA := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: objectSD}
	eventName := fmt.Sprintf(`Global\BOFBenchTargetEvent-%d`, os.Getpid())
	eventNamePtr, _ := windows.UTF16PtrFromString(eventName)
	eventHandle, err := windows.CreateEvent(objectSA, 1, 0, eventNamePtr)
	if err != nil {
		return true, 2
	}
	defer windows.CloseHandle(eventHandle)
	mutexName := fmt.Sprintf(`Global\BOFBenchTargetMutex-%d`, os.Getpid())
	mutexNamePtr, _ := windows.UTF16PtrFromString(mutexName)
	mutexRaw, _, mutexErr := procCreateMutex.Call(uintptr(unsafe.Pointer(objectSA)), 0, uintptr(unsafe.Pointer(mutexNamePtr)))
	if mutexRaw == 0 {
		_ = mutexErr
		return true, 2
	}
	mutexHandle := windows.Handle(mutexRaw)
	defer windows.CloseHandle(mutexHandle)
	semaphoreName := fmt.Sprintf(`Global\BOFBenchTargetSemaphore-%d`, os.Getpid())
	semaphoreNamePtr, _ := windows.UTF16PtrFromString(semaphoreName)
	semaphoreRaw, _, semaphoreErr := procCreateSemaphore.Call(uintptr(unsafe.Pointer(objectSA)), 1, 4, uintptr(unsafe.Pointer(semaphoreNamePtr)))
	if semaphoreRaw == 0 {
		_ = semaphoreErr
		return true, 2
	}
	semaphoreHandle := windows.Handle(semaphoreRaw)
	defer windows.CloseHandle(semaphoreHandle)
	timerName := fmt.Sprintf(`Global\BOFBenchTargetTimer-%d`, os.Getpid())
	timerNamePtr, _ := windows.UTF16PtrFromString(timerName)
	timerRaw, _, timerErr := procCreateTimer.Call(uintptr(unsafe.Pointer(objectSA)), 0, uintptr(unsafe.Pointer(timerNamePtr)))
	if timerRaw == 0 {
		_ = timerErr
		return true, 2
	}
	timerHandle := windows.Handle(timerRaw)
	defer windows.CloseHandle(timerHandle)
	mailslotName := fmt.Sprintf(`\\.\mailslot\BOFBenchTarget-%d`, os.Getpid())
	mailslotNamePtr, _ := windows.UTF16PtrFromString(mailslotName)
	mailslotRaw, _, mailslotErr := procCreateMailslot.Call(uintptr(unsafe.Pointer(mailslotNamePtr)), 65536, 5000, uintptr(unsafe.Pointer(objectSA)))
	if windows.Handle(mailslotRaw) == windows.InvalidHandle {
		_ = mailslotErr
		return true, 2
	}
	mailslotHandle := windows.Handle(mailslotRaw)
	defer windows.CloseHandle(mailslotHandle)
	mailslotMessage := []byte(fmt.Sprintf("BOFBenchMailslotFixture-%d", os.Getpid()))
	sectionName := fmt.Sprintf(`Global\BOFBenchTargetSection-%d`, os.Getpid())
	sectionNamePtr, _ := windows.UTF16PtrFromString(sectionName)
	sectionHandle, err := windows.CreateFileMapping(windows.InvalidHandle, objectSA, windows.PAGE_READWRITE, 0, 4096, sectionNamePtr)
	if err != nil {
		return true, 2
	}
	defer windows.CloseHandle(sectionHandle)
	sectionView, err := windows.MapViewOfFile(sectionHandle, windows.FILE_MAP_WRITE|windows.FILE_MAP_READ, 0, 0, 4096)
	if err != nil {
		return true, 2
	}
	sectionCanary := randomBytes(32)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(sectionView)), len(sectionCanary)), sectionCanary)
	defer windows.UnmapViewOfFile(sectionView)
	jobName := fmt.Sprintf(`BOFBenchTargetJob-%d`, os.Getpid())
	jobNamePtr, _ := windows.UTF16PtrFromString(jobName)
	jobHandle, err := windows.CreateJobObject(objectSA, jobNamePtr)
	if err != nil {
		return true, 2
	}
	defer windows.CloseHandle(jobHandle)
	objectDACL, _, err := objectSD.DACL()
	if err != nil || windows.SetSecurityInfo(jobHandle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, objectDACL, nil) != nil {
		return true, 2
	}
	executable, _ := os.Executable()
	jobChild := exec.Command(executable, "--job-child")
	jobChild.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB}
	if err := jobChild.Start(); err != nil {
		return true, 2
	}
	childHandle, childErr := windows.OpenProcess(windows.WRITE_DAC|windows.WRITE_OWNER|windows.ACCESS_SYSTEM_SECURITY, false, uint32(jobChild.Process.Pid))
	if childErr != nil {
		_ = jobChild.Process.Kill()
		_, _ = jobChild.Process.Wait()
		return true, 2
	}
	childDACL, _, childErr := objectSD.DACL()
	if childErr == nil {
		var childSACL *windows.ACL
		childSACL, _, childErr = objectSD.SACL()
		if childErr == nil {
			childErr = windows.SetSecurityInfo(childHandle, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, nil, nil, childDACL, childSACL)
		}
	}
	windows.CloseHandle(childHandle)
	if childErr != nil {
		_ = jobChild.Process.Kill()
		_, _ = jobChild.Process.Wait()
		return true, 2
	}
	defer func() {
		if jobChild.Process != nil {
			_ = jobChild.Process.Kill()
			_, _ = jobChild.Process.Wait()
		}
	}()
	stop := make(chan struct{})
	threadID := make(chan uint32, 1)
	go alertableThread(stop, threadID)
	networkState, networkErr := startNetworkFixtures(stop, service.root)
	if networkErr != nil {
		close(stop)
		return true, 22
	}
	pipeReady := make(chan namedPipeResult, 1)
	go namedPipeFixture(stop, pipeReady)
	go maintainMailslot(stop, mailslotHandle, mailslotName, mailslotMessage)
	pipe := <-pipeReady
	heldPipe, err := createHeldPipeFixture()
	if err != nil {
		close(stop)
		return true, 2
	}
	defer windows.CloseHandle(heldPipe.Server)
	defer windows.CloseHandle(heldPipe.Client)
	go maintainHeldPipe(stop, heldPipe.Client, heldPipe.Server, heldPipe.Response)
	alpc, err := createALPCFixture(service.root)
	if err != nil {
		writeTargetStartupError(service.root, "alpc", err)
		close(stop)
		return true, 20
	}
	defer alpc.stop()
	var windowState targetState
	windowData, err := os.ReadFile(filepath.Join(service.root, "window-helper.json"))
	if err != nil {
		writeTargetStartupError(service.root, "window-helper-read", err)
		close(stop)
		return true, 21
	}
	if err := json.Unmarshal(windowData, &windowState); err != nil || windowState.PID <= 0 || windowState.WindowHandle == "" || windowState.WindowTextHandle == "" {
		if err == nil {
			err = fmt.Errorf("window helper state is incomplete")
		}
		writeTargetStartupError(service.root, "window-helper-state", err)
		close(stop)
		return true, 21
	}
	pipeChild := exec.Command(executable, "--pipe-child")
	pipeStdin, err := pipeChild.StdinPipe()
	if err != nil {
		close(stop)
		return true, 2
	}
	pipeStdout, err := pipeChild.StdoutPipe()
	if err != nil {
		close(stop)
		return true, 2
	}
	if err := pipeChild.Start(); err != nil {
		close(stop)
		return true, 2
	}
	defer func() {
		_ = pipeStdin.Close()
		_ = pipeStdout.Close()
		if pipeChild.Process != nil {
			_ = pipeChild.Process.Kill()
			_, _ = pipeChild.Process.Wait()
		}
	}()
	pipeMessage := []byte(fmt.Sprintf("BOFBenchProcessPipeFixture-%d", os.Getpid()))
	_, _ = pipeStdin.Write(pipeMessage)
	time.Sleep(100 * time.Millisecond)
	if stdinFile, ok := pipeStdin.(*os.File); ok {
		if stdoutFile, stdoutOK := pipeStdout.(*os.File); stdoutOK {
			go maintainProcessPipe(stop, windows.Handle(stdoutFile.Fd()), pipeStdin, pipeMessage)
			_ = stdinFile
		}
	}
	fixtureErr := launchFixtureInConsoleSession(service.root, "deploy")
	if runtime.GOARCH == "amd64" {
		if etwErr := startETWFixture(stop); etwErr != nil {
			if fixtureErr == nil {
				fixtureErr = etwErr
			} else {
				fixtureErr = fmt.Errorf("%v; %w", fixtureErr, etwErr)
			}
		}
	}
	state := targetState{
		Schema: "bofbench.target", SchemaVersion: 11, Service: service.name,
		PID: os.Getpid(), Architecture: runtime.GOARCH, AlertableTID: <-threadID, NamedPipe: pipe.Name, User: `NT AUTHORITY\SYSTEM`,
		NamedPipeHandle: fmt.Sprintf("0x%X", uintptr(heldPipe.Server)), NamedPipeClientHandle: fmt.Sprintf("0x%X", uintptr(heldPipe.Client)), NamedPipeSHA256: hashBytes(heldPipe.Response),
		ProcessPipePID: pipeChild.Process.Pid, ProcessStdinHandle: fmt.Sprintf("0x%X", pipeStdin.(*os.File).Fd()), ProcessStdoutHandle: fmt.Sprintf("0x%X", pipeStdout.(*os.File).Fd()), ProcessPipeSHA256: hashBytes(pipeMessage),
		KnownHandle: fmt.Sprintf("0x%X", knownFile.Fd()),
		HolderPID:   os.Getpid(), JobMemberPID: jobChild.Process.Pid, EventName: eventName, SectionName: sectionName, JobName: jobName,
		MutexName: mutexName, SemaphoreName: semaphoreName, TimerName: timerName, MailslotName: mailslotName,
		MailslotHandle: fmt.Sprintf("0x%X", uintptr(mailslotHandle)), MailslotSHA256: hashBytes(mailslotMessage), MailslotAccess: systemHandleGrantedAccess(mailslotHandle),
		ALPCPort: alpc.Name, ALPCHandle: fmt.Sprintf("0x%X", uintptr(alpc.Client)),
		WindowHandle: windowState.WindowHandle, WindowTextHandle: windowState.WindowTextHandle, WindowHelperPID: windowState.PID, WindowStation: windowState.WindowStation, WindowClass: windowState.WindowClass, WindowMessage: windowState.WindowMessage, WindowPostMessage: windowState.WindowPostMessage,
		WatchRegistryHive: "HKLM", WatchRegistryPath: `Software\BOFBench`, WatchRegistryValue: "RemoteCanary",
		WatchDirectory: `C:\bofbench\proof`, WatchService: service.name, ExitPID: pipeChild.Process.Pid,
		EventLogChannel: "Application", EventLogProvider: "BOFBenchTarget",
		ETWProviderGUID: etwProviderGUID, ETWSessionName: "BOFBench-ETW",
		TCPHost: networkState.TCPHost, TCPPort: networkState.TCPPort, UDPHost: networkState.UDPHost, UDPPort: networkState.UDPPort,
		HTTPURL: networkState.HTTPURL, HTTPBlobURL: networkState.HTTPBlobURL, HTTPTransientURL: networkState.HTTPTransientURL,
		HTTPSURL: networkState.HTTPSURL, HTTPSBlobURL: networkState.HTTPSBlobURL, HTTPSAuthURL: networkState.HTTPSAuthURL,
		HTTPAuthUser: networkState.HTTPAuthUser, TLSCertificateSHA256: networkState.TLSCertificateSHA256,
		WebSocketURL: networkState.WebSocketURL, DNSName: networkState.DNSName, NetworkPayloadSHA256: networkState.NetworkPayloadSHA256,
		CanaryFile: canaryPath, CanaryFileSHA256: hashBytes(fileCanary), MoveCanaryFile: moveCanaryPath, MoveCanarySHA256: hashBytes(moveCanary),
		MemoryCanaryAddress: fmt.Sprintf("0x%X", uintptr(unsafe.Pointer(&memoryCanary[0]))),
		MemoryCanarySize:    len(canary), MemoryCanarySHA256: hashBytes(canary),
		ExecutionAddress:   fmt.Sprintf("0x%X", executionRegion),
		MemoryWriteAddress: fmt.Sprintf("0x%X", writeRegion), MemoryWriteSize: len(writeCanary), MemoryWriteSHA256: hashBytes(writeCanary),
		MemoryProtectAddress: fmt.Sprintf("0x%X", protectRegion), MemoryProtectSize: 4096, MemoryProtection: "0x04",
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if module, _, _ := procModuleHandle.Call(0); module != 0 {
		state.KnownModuleBase = fmt.Sprintf("0x%X", module)
	}
	state.KnownModulePath, _ = os.Executable()
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

func writeTargetStartupError(root, stage string, err error) {
	record := map[string]any{
		"schema":         "bofbench.target-startup-error",
		"schema_version": 1,
		"stage":          stage,
		"error":          err.Error(),
		"recorded_at":    time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = writeJSON(filepath.Join(root, "startup-error.json"), record)
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

func startETWFixture(stop <-chan struct{}) error {
	provider, err := windows.GUIDFromString(etwProviderGUID)
	if err != nil {
		return fmt.Errorf("parse fixture ETW provider: %w", err)
	}
	var handle uint64
	status, _, _ := procEventRegister.Call(uintptr(unsafe.Pointer(&provider)), 0, 0, uintptr(unsafe.Pointer(&handle)))
	if status != 0 {
		return fmt.Errorf("EventRegister fixture provider failed: %d", status)
	}
	go func() {
		defer procEventUnregister.Call(uintptr(handle))
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		emit := func() {
			message, pointerErr := windows.UTF16PtrFromString(fmt.Sprintf("BOFBenchTarget pid=%d tick=%d", os.Getpid(), time.Now().UTC().UnixNano()))
			if pointerErr == nil {
				procEventWriteString.Call(uintptr(handle), 4, 0, uintptr(unsafe.Pointer(message)))
			}
		}
		emit()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				emit()
			}
		}
	}()
	return nil
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

type heldPipeResult struct {
	Name     string
	Server   windows.Handle
	Client   windows.Handle
	Response []byte
}

func createHeldPipeFixture() (heldPipeResult, error) {
	result := heldPipeResult{Name: fmt.Sprintf(`\\.\pipe\BOFBenchHeldPipe-%d`, os.Getpid()), Response: []byte(fmt.Sprintf("BOFBenchNamedPipeFixture-%d", os.Getpid()))}
	name, err := windows.UTF16PtrFromString(result.Name)
	if err != nil {
		return result, err
	}
	result.Server, err = windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT, 1, 65536, 65536, 5000, nil)
	if err != nil {
		return result, err
	}
	connected := make(chan error, 1)
	go func() {
		err := windows.ConnectNamedPipe(result.Server, nil)
		if err == windows.ERROR_PIPE_CONNECTED {
			err = nil
		}
		connected <- err
	}()
	result.Client, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		windows.CloseHandle(result.Server)
		return result, err
	}
	if err = <-connected; err != nil {
		windows.CloseHandle(result.Client)
		windows.CloseHandle(result.Server)
		return result, err
	}
	probe := []byte("BOFBenchPipeClient")
	var written, read uint32
	if err = windows.WriteFile(result.Client, probe, &written, nil); err != nil {
		windows.CloseHandle(result.Client)
		windows.CloseHandle(result.Server)
		return result, err
	}
	drain := make([]byte, len(probe))
	if err = windows.ReadFile(result.Server, drain, &read, nil); err != nil {
		windows.CloseHandle(result.Client)
		windows.CloseHandle(result.Server)
		return result, err
	}
	if err = windows.WriteFile(result.Server, result.Response, &written, nil); err != nil {
		windows.CloseHandle(result.Client)
		windows.CloseHandle(result.Server)
		return result, err
	}
	return result, nil
}

func maintainHeldPipe(stop <-chan struct{}, client, server windows.Handle, response []byte) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			var available uint32
			ok, _, _ := procPeekNamedPipe.Call(uintptr(client), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
			if ok != 0 && available == 0 {
				var written uint32
				_ = windows.WriteFile(server, response, &written, nil)
			}
		}
	}
}

func maintainProcessPipe(stop <-chan struct{}, stdout windows.Handle, stdin interface{ Write([]byte) (int, error) }, message []byte) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	peek := make([]byte, 65536)
	drain := make([]byte, 65536)
	pending := true
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			var read, available uint32
			ok, _, _ := procPeekNamedPipe.Call(uintptr(stdout), uintptr(unsafe.Pointer(&peek[0])), uintptr(len(peek)), uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&available)), 0)
			if ok == 0 {
				continue
			}
			if available == 0 {
				if pending {
					continue
				}
				_, _ = stdin.Write(message)
				pending = true
				continue
			}
			if int(read) == len(message) && available == uint32(len(message)) && bytes.Equal(peek[:read], message) {
				pending = false
				continue
			}
			_ = windows.ReadFile(stdout, drain[:min(int(available), len(drain))], &read, nil)
			_, _ = stdin.Write(message)
			pending = true
		}
	}
}

func namedPipeFixture(stop <-chan struct{}, ready chan<- namedPipeResult) {
	name := fmt.Sprintf(`\\.\pipe\BOFBenchTarget-%d`, os.Getpid())
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		ready <- namedPipeResult{Err: fmt.Errorf("prepare named-pipe fixture: %w", err)}
		return
	}
	handle, err := windows.CreateNamedPipe(namePtr, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		ready <- namedPipeResult{Err: fmt.Errorf("create named-pipe fixture: %w", err)}
		return
	}
	ready <- namedPipeResult{Name: name}
	closed := make(chan struct{})
	go func() {
		select {
		case <-stop:
			_ = windows.CloseHandle(handle)
		case <-closed:
		}
	}()
	defer close(closed)
	buffer := make([]byte, 65536)
	for {
		err = windows.ConnectNamedPipe(handle, nil)
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			select {
			case <-stop:
				return
			default:
			}
			return
		}
		var read uint32
		if err = windows.ReadFile(handle, buffer, &read, nil); err == nil && read > 0 {
			var written uint32
			_ = windows.WriteFile(handle, buffer[:read], &written, nil)
		}
		_ = windows.FlushFileBuffers(handle)
		_ = windows.DisconnectNamedPipe(handle)
	}
}

func maintainMailslot(stop <-chan struct{}, handle windows.Handle, name string, message []byte) {
	write := func() {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return
		}
		client, err := windows.CreateFile(namePtr, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return
		}
		defer windows.CloseHandle(client)
		var written uint32
		_ = windows.WriteFile(client, message, &written, nil)
	}
	ensure := func() {
		var maximum, next, count, timeout uint32
		ok, _, _ := procGetMailslotInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&maximum)), uintptr(unsafe.Pointer(&next)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&timeout)))
		if ok != 0 && count == 0 {
			write()
		}
	}
	ensure()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ensure()
		}
	}
}

type extendedHandleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

func systemHandleGrantedAccess(handle windows.Handle) uint32 {
	const (
		systemExtendedHandleInformation = 64
		statusInfoLengthMismatch        = uint32(0xC0000004)
	)
	size := uint32(1 << 20)
	for attempt := 0; attempt < 8; attempt++ {
		buffer := make([]byte, size)
		var needed uint32
		status, _, _ := procNtQuerySystem.Call(systemExtendedHandleInformation, uintptr(unsafe.Pointer(&buffer[0])), uintptr(size), uintptr(unsafe.Pointer(&needed)))
		if uint32(status) == statusInfoLengthMismatch {
			if needed > size {
				size = needed + 1<<16
			} else {
				size *= 2
			}
			continue
		}
		if int32(status) < 0 {
			return 0
		}
		count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
		headerSize := uintptr(unsafe.Sizeof(uintptr(0)) * 2)
		entrySize := unsafe.Sizeof(extendedHandleEntry{})
		available := (uintptr(len(buffer)) - headerSize) / entrySize
		if count > available {
			count = available
		}
		pid := uintptr(os.Getpid())
		wanted := uintptr(handle)
		base := uintptr(unsafe.Pointer(&buffer[0])) + headerSize
		for index := uintptr(0); index < count; index++ {
			entry := (*extendedHandleEntry)(unsafe.Pointer(base + index*entrySize))
			if entry.UniqueProcessID == pid && entry.HandleValue == wanted {
				return entry.GrantedAccess
			}
		}
		return 0
	}
	return 0
}

func deployFixtures(root string) (fixtureState, error) {
	fixtureRoot := filepath.Join(root, "fixtures")
	if err := os.MkdirAll(fixtureRoot, 0o700); err != nil {
		return fixtureState{}, err
	}
	credentialCanary := randomBytes(48)
	userCanary := randomBytes(48)
	machineCanary := randomBytes(48)
	vaultSecret := hex.EncodeToString(randomBytes(24))
	runID := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	vaultResource := "BOFBench-Vault-" + runID
	vaultIdentity := "operator-" + runID
	certificateName := "BOFBench-Auth-" + runID
	certificateSubject := "CN=" + certificateName
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
	userProtected, err := os.ReadFile(userPath)
	if err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	machineProtected, err := os.ReadFile(machinePath)
	if err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	vaultGUID, thumbprint, err := deployVaultAndCertificate(vaultResource, vaultIdentity, vaultSecret, certificateSubject)
	if err != nil {
		deleteCredential(credentialName)
		return fixtureState{}, err
	}
	state := fixtureState{
		Schema: "bofbench.target-fixtures", SchemaVersion: 2, User: currentUser(),
		CredentialTarget: credentialName, CredentialSHA256: hashBytes(credentialCanary), CredentialSize: len(credentialCanary),
		DPAPIUserPath: userPath, DPAPIUserSHA256: hashBytes(userCanary), DPAPIUserFileSHA256: hashBytes(userProtected),
		DPAPIMachinePath: machinePath, DPAPIMachineSHA256: hashBytes(machineCanary), DPAPIMachineFileSHA256: hashBytes(machineProtected),
		WMIMarkerPath: filepath.Join(fixtureRoot, "wmi-marker.txt"), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		VaultGUID: vaultGUID, VaultResource: vaultResource, VaultIdentity: vaultIdentity, VaultSHA256: hashBytes([]byte(vaultSecret)), VaultSize: len(vaultSecret),
		CertificateStore: "MY", CertificateSubject: certificateName, CertificateThumbprint: thumbprint,
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
	if state, err := readFixtures(root); err == nil {
		_ = removeVaultAndCertificate(state)
	}
	deleteCredential(credentialName)
	return os.RemoveAll(filepath.Join(root, "fixtures"))
}

func deployVaultAndCertificate(resource, identity, secret, subject string) (string, string, error) {
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null; $vault=New-Object Windows.Security.Credentials.PasswordVault; $credential=New-Object Windows.Security.Credentials.PasswordCredential(%s,%s,%s); $vault.Add($credential); $cert=New-SelfSignedCertificate -Subject %s -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(7); [ordered]@{vault_guid='4BF4C442-9B8A-41A0-B380-DD4A704DDB28';thumbprint=$cert.Thumbprint} | ConvertTo-Json -Compress`, psQuote(resource), psQuote(identity), psQuote(secret), psQuote(subject))
	output, err := runPowerShell(script)
	if err != nil {
		return "", "", err
	}
	var result struct {
		VaultGUID  string `json:"vault_guid"`
		Thumbprint string `json:"thumbprint"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return "", "", fmt.Errorf("decode Vault/certificate fixture: %w", err)
	}
	if result.VaultGUID == "" || result.Thumbprint == "" {
		return "", "", fmt.Errorf("Vault/certificate fixture returned incomplete identifiers")
	}
	return result.VaultGUID, result.Thumbprint, nil
}

func removeVaultAndCertificate(state fixtureState) error {
	script := fmt.Sprintf(`$ErrorActionPreference='Continue'; [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime] | Out-Null; $vault=New-Object Windows.Security.Credentials.PasswordVault; try{$item=$vault.Retrieve(%s,%s); if($item){$vault.Remove($item)}}catch{}; Remove-Item -LiteralPath (%s + %s) -Force -ErrorAction SilentlyContinue`, psQuote(state.VaultResource), psQuote(state.VaultIdentity), psQuote(`Cert:\CurrentUser\My\`), psQuote(state.CertificateThumbprint))
	_, err := runPowerShell(script)
	return err
}

func runPowerShell(script string) ([]byte, error) {
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("PowerShell fixture: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
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
	helper := flag.Bool("helper", false, "run a persistent architecture-specific proof helper")
	helperService := flag.Bool("helper-service", false, "run the architecture-specific proof helper as a Windows service")
	windowHelper := flag.Bool("window-helper", false, "run the operator-context window proof helper")
	jobChild := flag.Bool("job-child", false, "run a disposable job-member child")
	pipeChild := flag.Bool("pipe-child", false, "run a disposable standard-pipe echo child")
	jobState := flag.String("job-state", "", "optional PID file written by a disposable job-member child")
	flag.Parse()
	if *pipeChild {
		buffer := make([]byte, 65536)
		for {
			count, err := os.Stdin.Read(buffer)
			if count > 0 {
				if _, writeErr := os.Stdout.Write(buffer[:count]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	if *jobChild {
		if *jobState != "" {
			if err := os.MkdirAll(filepath.Dir(*jobState), 0o755); err != nil {
				os.Exit(1)
			}
			if err := os.WriteFile(*jobState, []byte(fmt.Sprintf("%d", os.Getpid())), 0o600); err != nil {
				os.Exit(1)
			}
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	if *helperService {
		if err := svc.Run(*name, helperHandler{name: *name, root: *root}); err != nil {
			os.Exit(1)
		}
		return
	}
	if *helper {
		if err := runArchitectureHelper(*root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *windowHelper {
		if err := runWindowHelper(*root); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
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

func runArchitectureHelper(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	stop := make(chan struct{})
	threadID := make(chan uint32, 1)
	go alertableThread(stop, threadID)
	state := targetState{Schema: "bofbench.target-helper", SchemaVersion: 11, PID: os.Getpid(), Architecture: runtime.GOARCH, AlertableTID: <-threadID, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if module, _, _ := procModuleHandle.Call(0); module != 0 {
		state.KnownModuleBase = fmt.Sprintf("0x%X", module)
	}
	state.KnownModulePath, _ = os.Executable()
	if err := writeJSON(filepath.Join(root, "x86-helper.json"), state); err != nil {
		close(stop)
		return err
	}
	select {}
}

func runWindowHelper(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	window, err := createWindowFixture(root)
	if err != nil {
		return err
	}
	state := targetState{
		Schema: "bofbench.target-window-helper", SchemaVersion: 11, PID: os.Getpid(), Architecture: runtime.GOARCH,
		WindowHandle: fmt.Sprintf("0x%X", uintptr(window.Handle)), WindowTextHandle: fmt.Sprintf("0x%X", uintptr(window.TextHandle)),
		WindowStation: `BOFBenchTargetStation\BOFBenchTargetDesktop`, WindowClass: window.Class,
		WindowMessage: window.MessageID, WindowPostMessage: window.PostMessage,
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSON(filepath.Join(root, "window-helper.json"), state); err != nil {
		window.stop()
		return err
	}
	select {}
}
