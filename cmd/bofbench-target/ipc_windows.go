//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmCopyData            = 0x004A
	wmSetText             = 0x000C
	wmClose               = 0x0010
	wmApp                 = 0x8000
	targetWindowMessage   = wmApp + 0x42
	targetWindowPost      = wmApp + 0x43
	hwndMessage           = ^uintptr(2)
	alpcObjectInsensitive = 0x40
)

var (
	user32IPC                       = windows.NewLazySystemDLL("user32.dll")
	procRegisterClassExW            = user32IPC.NewProc("RegisterClassExW")
	procCreateWindowExW             = user32IPC.NewProc("CreateWindowExW")
	procSetWindowLongPtrW           = user32IPC.NewProc("SetWindowLongPtrW")
	procDefWindowProcW              = user32IPC.NewProc("DefWindowProcW")
	procDestroyWindow               = user32IPC.NewProc("DestroyWindow")
	procGetMessageW                 = user32IPC.NewProc("GetMessageW")
	procTranslateMessage            = user32IPC.NewProc("TranslateMessage")
	procDispatchMessageW            = user32IPC.NewProc("DispatchMessageW")
	procPostMessageW                = user32IPC.NewProc("PostMessageW")
	procChangeWindowMessageFilterEx = user32IPC.NewProc("ChangeWindowMessageFilterEx")
	procCreateWindowStationW        = user32IPC.NewProc("CreateWindowStationW")
	procCreateDesktopW              = user32IPC.NewProc("CreateDesktopW")
	procSetProcessWindowStation     = user32IPC.NewProc("SetProcessWindowStation")
	procSetThreadDesktop            = user32IPC.NewProc("SetThreadDesktop")
	procCloseWindowStation          = user32IPC.NewProc("CloseWindowStation")
	procCloseDesktop                = user32IPC.NewProc("CloseDesktop")
	ntdllIPC                        = windows.NewLazySystemDLL("ntdll.dll")
	procRtlInitUnicodeString        = ntdllIPC.NewProc("RtlInitUnicodeString")
	procNtAlpcCreatePort            = ntdllIPC.NewProc("NtAlpcCreatePort")
	procNtAlpcConnectPort           = ntdllIPC.NewProc("NtAlpcConnectPort")
	procNtAlpcAcceptPort            = ntdllIPC.NewProc("NtAlpcAcceptConnectPort")
	procNtAlpcSendWaitReceive       = ntdllIPC.NewProc("NtAlpcSendWaitReceivePort")
)

type windowClassEx struct {
	Size, Style                        uint32
	WindowProc                         uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background windows.Handle
	MenuName, ClassName                *uint16
	IconSmall                          windows.Handle
}

type windowMessage struct {
	Window  windows.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PointX  int32
	PointY  int32
	Private uint32
}

type copyData struct {
	DataID uintptr
	Size   uint32
	Data   uintptr
}

type windowFixtureState struct {
	Schema         string `json:"schema"`
	SchemaVersion  int    `json:"schema_version"`
	Handle         string `json:"handle"`
	TextHandle     string `json:"text_handle,omitempty"`
	Class          string `json:"class"`
	MessageID      uint32 `json:"message_id,omitempty"`
	WParam         string `json:"wparam,omitempty"`
	LParam         string `json:"lparam,omitempty"`
	CopyDataID     string `json:"copydata_id,omitempty"`
	CopyDataSize   int    `json:"copydata_size,omitempty"`
	CopyDataSHA256 string `json:"copydata_sha256,omitempty"`
	Text           string `json:"text,omitempty"`
	TextSHA256     string `json:"text_sha256,omitempty"`
}

type windowFixture struct {
	Handle      windows.Handle
	TextHandle  windows.Handle
	Class       string
	MessageID   uint32
	PostMessage uint32
	stop        func()
}

var (
	activeWindowRoot string
	activeWindow     windowFixtureState
	activeWindowMu   sync.Mutex
)

func createWindowFixture(root string) (windowFixture, error) {
	ready := make(chan windowFixture, 1)
	fail := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		securityDescriptor, securityErr := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)")
		if securityErr != nil {
			fail <- fmt.Errorf("window fixture security descriptor: %w", securityErr)
			return
		}
		securityAttributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: securityDescriptor}
		windowStationName, _ := windows.UTF16PtrFromString("BOFBenchTargetStation")
		windowStation, _, stationErr := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(windowStationName)), 0, 0x0000037f, uintptr(unsafe.Pointer(&securityAttributes)))
		if windowStation == 0 {
			fail <- fmt.Errorf("CreateWindowStationW BOFBenchTargetStation: %w", stationErr)
			return
		}
		defer procCloseWindowStation.Call(windowStation)
		if changed, _, changeErr := procSetProcessWindowStation.Call(windowStation); changed == 0 {
			fail <- fmt.Errorf("SetProcessWindowStation BOFBenchTargetStation: %w", changeErr)
			return
		}
		desktopName, _ := windows.UTF16PtrFromString("BOFBenchTargetDesktop")
		desktop, _, desktopErr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(desktopName)), 0, 0, 0, 0x000001ff, uintptr(unsafe.Pointer(&securityAttributes)))
		if desktop == 0 {
			fail <- fmt.Errorf("CreateDesktopW BOFBenchTargetDesktop: %w", desktopErr)
			return
		}
		defer procCloseDesktop.Call(desktop)
		if changed, _, changeErr := procSetThreadDesktop.Call(desktop); changed == 0 {
			fail <- fmt.Errorf("SetThreadDesktop BOFBenchTargetDesktop: %w", changeErr)
			return
		}
		className := fmt.Sprintf("BOFBenchTargetWindow-%d", os.Getpid())
		classPtr, _ := windows.UTF16PtrFromString(className)
		titlePtr, _ := windows.UTF16PtrFromString("BOFBench IPC fixture")
		instance, _, _ := procModuleHandle.Call(0)
		callback := syscall.NewCallback(targetWindowProcedure)
		class := windowClassEx{Size: uint32(unsafe.Sizeof(windowClassEx{})), WindowProc: callback, Instance: windows.Handle(instance), ClassName: classPtr}
		atom, _, registerErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class)))
		if atom == 0 {
			fail <- fmt.Errorf("RegisterClassExW: %w", registerErr)
			return
		}
		handle, _, createErr := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(classPtr)), uintptr(unsafe.Pointer(titlePtr)), 0, 0, 0, 0, 0, 0, 0, instance, 0)
		if handle == 0 {
			fail <- fmt.Errorf("CreateWindowExW: %w", createErr)
			return
		}
		staticClass, _ := windows.UTF16PtrFromString("STATIC")
		staticTitle, _ := windows.UTF16PtrFromString("BOFBench text fixture")
		textHandle, _, textErr := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(staticClass)), uintptr(unsafe.Pointer(staticTitle)), 0, 0, 0, 0, 0, 0, 0, instance, 0)
		if textHandle == 0 {
			_, _, _ = procDestroyWindow.Call(handle)
			fail <- fmt.Errorf("CreateWindowExW STATIC: %w", textErr)
			return
		}
		if previous, _, subclassErr := procSetWindowLongPtrW.Call(textHandle, ^uintptr(3), callback); previous == 0 {
			_, _, _ = procDestroyWindow.Call(textHandle)
			_, _, _ = procDestroyWindow.Call(handle)
			fail <- fmt.Errorf("SetWindowLongPtrW STATIC: %w", subclassErr)
			return
		}
		_, _, _ = procChangeWindowMessageFilterEx.Call(textHandle, wmSetText, 1, 0)
		for _, messageID := range []uint32{targetWindowMessage, targetWindowPost, wmCopyData, wmSetText} {
			_, _, _ = procChangeWindowMessageFilterEx.Call(handle, uintptr(messageID), 1, 0)
		}
		activeWindowMu.Lock()
		activeWindowRoot = root
		activeWindow = windowFixtureState{Schema: "bofbench.target-window", SchemaVersion: 1, Handle: fmt.Sprintf("0x%X", handle), TextHandle: fmt.Sprintf("0x%X", textHandle), Class: className, Text: "BOFBench IPC fixture", TextSHA256: hashBytes([]byte("BOFBench IPC fixture"))}
		writeWindowStateLocked()
		activeWindowMu.Unlock()
		ready <- windowFixture{Handle: windows.Handle(handle), TextHandle: windows.Handle(textHandle), Class: className, MessageID: targetWindowMessage, PostMessage: targetWindowPost, stop: func() {
			_, _, _ = procPostMessageW.Call(textHandle, wmClose, 0, 0)
			_, _, _ = procPostMessageW.Call(handle, wmClose, 0, 0)
		}}
		var message windowMessage
		for {
			result, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
			if int32(result) <= 0 {
				break
			}
			_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
			_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
		}
	}()
	select {
	case fixture := <-ready:
		return fixture, nil
	case err := <-fail:
		return windowFixture{}, err
	}
}

func targetWindowProcedure(window uintptr, message uint32, wparam, lparam uintptr) uintptr {
	activeWindowMu.Lock()
	switch message {
	case targetWindowMessage, targetWindowPost:
		activeWindow.MessageID = message
		activeWindow.WParam = fmt.Sprintf("0x%X", wparam)
		activeWindow.LParam = fmt.Sprintf("0x%X", lparam)
		writeWindowStateLocked()
		activeWindowMu.Unlock()
		return 0x424F46
	case wmCopyData:
		if lparam != 0 {
			payload := (*copyData)(unsafe.Pointer(lparam))
			activeWindow.CopyDataID = fmt.Sprintf("0x%X", payload.DataID)
			activeWindow.CopyDataSize = int(payload.Size)
			if payload.Data != 0 && payload.Size > 0 && payload.Size <= 1<<20 {
				activeWindow.CopyDataSHA256 = hashBytes(append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(payload.Data)), int(payload.Size))...))
			}
			writeWindowStateLocked()
		}
		activeWindowMu.Unlock()
		return 1
	case wmSetText:
		if lparam != 0 {
			activeWindow.Text = windows.UTF16PtrToString((*uint16)(unsafe.Pointer(lparam)))
			activeWindow.TextSHA256 = hashBytes([]byte(activeWindow.Text))
			writeWindowStateLocked()
		}
		activeWindowMu.Unlock()
		return 1
	case wmClose:
		activeWindowMu.Unlock()
		_, _, _ = procDestroyWindow.Call(window)
		return 0
	default:
		activeWindowMu.Unlock()
		result, _, _ := procDefWindowProcW.Call(window, uintptr(message), wparam, lparam)
		return result
	}
}

func writeWindowStateLocked() {
	if activeWindowRoot == "" {
		return
	}
	data, _ := json.MarshalIndent(activeWindow, "", "  ")
	_ = os.WriteFile(filepath.Join(activeWindowRoot, "window-state.json"), append(data, '\n'), 0o600)
}

type alpcUnicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type alpcObjectAttributes struct {
	Length             uint32
	RootDirectory      windows.Handle
	ObjectName         *alpcUnicodeString
	Attributes         uint32
	SecurityDescriptor uintptr
	SecurityQoS        uintptr
}

type alpcSecurityQoS struct {
	Length              uint32
	ImpersonationLevel  uint32
	ContextTrackingMode byte
	EffectiveOnly       byte
}

type alpcPortAttributes struct {
	Flags                                            uint32
	SecurityQoS                                      alpcSecurityQoS
	MaxMessageLength, MemoryBandwidth, MaxPoolUsage  uintptr
	MaxSectionSize, MaxViewSize, MaxTotalSectionSize uintptr
	DupObjectTypes, Reserved                         uint32
}

type alpcClientID struct {
	Process, Thread uintptr
}

type alpcPortMessage struct {
	DataLength, TotalLength uint16
	Type, DataInfoOffset    uint16
	ClientID                alpcClientID
	MessageID               uint32
	CallbackID              uintptr
}

type alpcMessageBuffer struct {
	Header alpcPortMessage
	Data   [60000]byte
}

type alpcFixture struct {
	Name   string
	Client windows.Handle
	stop   func()
}

type alpcFixtureState struct {
	Schema         string `json:"schema"`
	SchemaVersion  int    `json:"schema_version"`
	RequestBytes   int    `json:"request_bytes"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
}

var activeALPCRoot string

func createALPCFixture(root string) (alpcFixture, error) {
	name := fmt.Sprintf(`\RPC Control\BOFBenchTargetALPC-%d`, os.Getpid())
	activeALPCRoot = root
	ready := make(chan windows.Handle, 1)
	fail := make(chan error, 1)
	stop := make(chan struct{})
	go alpcEchoServer(name, ready, fail, stop)
	var server windows.Handle
	select {
	case server = <-ready:
	case err := <-fail:
		return alpcFixture{}, err
	}
	_ = server
	namePtr, _ := windows.UTF16PtrFromString(name)
	var unicode alpcUnicodeString
	_, _, _ = procRtlInitUnicodeString.Call(uintptr(unsafe.Pointer(&unicode)), uintptr(unsafe.Pointer(namePtr)))
	var client windows.Handle
	attrs := defaultALPCAttributes()
	var connection alpcMessageBuffer
	connection.Header.TotalLength = uint16(unsafe.Sizeof(connection.Header))
	connectionSize := uintptr(unsafe.Sizeof(connection.Header))
	timeout := int64(-50_000_000)
	status, _, callErr := procNtAlpcConnectPort.Call(uintptr(unsafe.Pointer(&client)), uintptr(unsafe.Pointer(&unicode)), 0, uintptr(unsafe.Pointer(&attrs)), 0, 0, uintptr(unsafe.Pointer(&connection.Header)), uintptr(unsafe.Pointer(&connectionSize)), 0, 0, uintptr(unsafe.Pointer(&timeout)))
	if int32(status) < 0 {
		close(stop)
		return alpcFixture{}, fmt.Errorf("NtAlpcConnectPort 0x%08X: %w", uint32(status), callErr)
	}
	return alpcFixture{Name: name, Client: client, stop: func() { close(stop); _ = windows.CloseHandle(client) }}, nil
}

func defaultALPCAttributes() alpcPortAttributes {
	return alpcPortAttributes{
		SecurityQoS:      alpcSecurityQoS{Length: uint32(unsafe.Sizeof(alpcSecurityQoS{})), ImpersonationLevel: 2, ContextTrackingMode: 1},
		MaxMessageLength: 60000,
	}
}

func alpcEchoServer(name string, ready chan<- windows.Handle, fail chan<- error, stop <-chan struct{}) {
	namePtr, _ := windows.UTF16PtrFromString(name)
	var unicode alpcUnicodeString
	_, _, _ = procRtlInitUnicodeString.Call(uintptr(unsafe.Pointer(&unicode)), uintptr(unsafe.Pointer(namePtr)))
	objects := alpcObjectAttributes{Length: uint32(unsafe.Sizeof(alpcObjectAttributes{})), ObjectName: &unicode, Attributes: alpcObjectInsensitive}
	attrs := defaultALPCAttributes()
	var server windows.Handle
	status, _, callErr := procNtAlpcCreatePort.Call(uintptr(unsafe.Pointer(&server)), uintptr(unsafe.Pointer(&objects)), uintptr(unsafe.Pointer(&attrs)))
	if int32(status) < 0 {
		fail <- fmt.Errorf("NtAlpcCreatePort 0x%08X: %w", uint32(status), callErr)
		return
	}
	defer windows.CloseHandle(server)
	go func() {
		<-stop
		_ = windows.CloseHandle(server)
	}()
	ready <- server
	for {
		var connection alpcMessageBuffer
		size := uintptr(60000)
		status, _, _ = procNtAlpcSendWaitReceive.Call(uintptr(server), 0, 0, 0, uintptr(unsafe.Pointer(&connection.Header)), uintptr(unsafe.Pointer(&size)), 0, 0)
		if int32(status) < 0 {
			writeALPCError("accept-receive", uint32(status))
			return
		}
		writeALPCConnection(connection.Header, size)
		messageType := connection.Header.Type & 0x0fff
		if messageType != 10 {
			if messageType == 1 {
				if status = alpcReply(server, &connection); int32(status) < 0 {
					writeALPCError("connection-reply", uint32(status))
				}
			}
			continue
		}
		var communication windows.Handle
		status, _, _ = procNtAlpcAcceptPort.Call(uintptr(unsafe.Pointer(&communication)), uintptr(server), 0, 0, 0, 0, uintptr(unsafe.Pointer(&connection.Header)), 0, 1)
		if int32(status) < 0 {
			writeALPCError("accept-connect", uint32(status))
			continue
		}
		go alpcServeConnection(communication)
	}
}

func writeALPCConnection(message alpcPortMessage, size uintptr) {
	record := map[string]any{
		"schema": "bofbench.target-alpc-connection", "schema_version": 1,
		"data_length": message.DataLength, "total_length": message.TotalLength,
		"type": message.Type, "data_info_offset": message.DataInfoOffset,
		"message_id": message.MessageID, "buffer_size": size,
	}
	if data, err := json.MarshalIndent(record, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(activeALPCRoot, "alpc-connection.json"), append(data, '\n'), 0o600)
	}
}

func alpcServeConnection(communication windows.Handle) {
	defer windows.CloseHandle(communication)
	var receive alpcMessageBuffer
	for {
		size := uintptr(60000)
		status, _, _ := procNtAlpcSendWaitReceive.Call(uintptr(communication), 0, 0, 0, uintptr(unsafe.Pointer(&receive.Header)), uintptr(unsafe.Pointer(&size)), 0, 0)
		if int32(status) < 0 {
			writeALPCError("exchange", uint32(status))
			return
		}
		if status = alpcReply(communication, &receive); int32(status) < 0 {
			writeALPCError("exchange-reply", uint32(status))
			return
		}
	}
}

func alpcReply(port windows.Handle, receive *alpcMessageBuffer) uintptr {
	var reply alpcMessageBuffer
	length := int(receive.Header.DataLength)
	if length > len(reply.Data) {
		length = len(reply.Data)
	}
	copy(reply.Data[:length], receive.Data[:length])
	state := alpcFixtureState{Schema: "bofbench.target-alpc", SchemaVersion: 1, RequestBytes: length, RequestSHA256: hashBytes(receive.Data[:length]), ResponseSHA256: hashBytes(receive.Data[:length])}
	if data, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(activeALPCRoot, "alpc-state.json"), append(data, '\n'), 0o600)
	}
	reply.Header.DataLength = uint16(length)
	reply.Header.TotalLength = uint16(int(unsafe.Sizeof(reply.Header)) + length)
	reply.Header.ClientID = receive.Header.ClientID
	reply.Header.MessageID = receive.Header.MessageID
	status, _, _ := procNtAlpcSendWaitReceive.Call(uintptr(port), 1, uintptr(unsafe.Pointer(&reply.Header)), 0, 0, 0, 0, 0)
	return status
}

func writeALPCError(stage string, status uint32) {
	record := map[string]any{
		"schema": "bofbench.target-alpc-error", "schema_version": 1,
		"stage": stage, "ntstatus": fmt.Sprintf("0x%08X", status),
		"recorded_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if data, err := json.MarshalIndent(record, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(activeALPCRoot, "alpc-error.json"), append(data, '\n'), 0o600)
	}
}
