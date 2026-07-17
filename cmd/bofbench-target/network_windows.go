//go:build windows

package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type networkFixtureState struct {
	TCPHost              string
	TCPPort              int
	UDPHost              string
	UDPPort              int
	HTTPURL              string
	HTTPBlobURL          string
	HTTPTransientURL     string
	WebSocketURL         string
	DNSName              string
	NetworkPayloadSHA256 string
}

type networkObservation struct {
	mu                 sync.Mutex `json:"-"`
	path               string     `json:"-"`
	TCPRequests        uint32     `json:"tcp_requests"`
	UDPRequests        uint32     `json:"udp_requests"`
	HTTPRequests       uint32     `json:"http_requests"`
	WebSocketRequests  uint32     `json:"websocket_requests"`
	TransientAttempts  uint32     `json:"transient_attempts"`
	LastTransport      string     `json:"last_transport,omitempty"`
	LastRequestSHA256  string     `json:"last_request_sha256,omitempty"`
	LastResponseSHA256 string     `json:"last_response_sha256,omitempty"`
}

func (state *networkObservation) record(transport string, request, response []byte, transient uint32) {
	state.mu.Lock()
	defer state.mu.Unlock()
	switch transport {
	case "tcp":
		state.TCPRequests++
	case "udp":
		state.UDPRequests++
	case "http":
		state.HTTPRequests++
	case "websocket":
		state.WebSocketRequests++
	}
	if transient > state.TransientAttempts {
		state.TransientAttempts = transient
	}
	state.LastTransport = transport
	state.LastRequestSHA256 = hashBytes(request)
	state.LastResponseSHA256 = hashBytes(response)
	_ = writeJSON(state.path, state)
}

func startNetworkFixtures(stop <-chan struct{}, root string) (networkFixtureState, error) {
	payload := []byte(fmt.Sprintf("BOFBenchNetworkFixture-%d", time.Now().UTC().UnixNano()))
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return networkFixtureState{}, err
	}
	udpConnection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_ = tcpListener.Close()
		return networkFixtureState{}, err
	}
	httpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = tcpListener.Close()
		_ = udpConnection.Close()
		return networkFixtureState{}, err
	}

	go func() {
		<-stop
		_ = tcpListener.Close()
		_ = udpConnection.Close()
		_ = httpListener.Close()
	}()
	observation := &networkObservation{path: filepath.Join(root, "network-state.json")}
	_ = writeJSON(observation.path, observation)
	go serveTCPEcho(tcpListener, observation)
	go serveUDPEcho(udpConnection, observation)

	var transientMu sync.Mutex
	transientByRequest := map[string]uint32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		observation.record("http", body, body, 0)
		writer.Header().Set("X-BOFBench-Request-SHA256", hashBytes(body))
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	})
	mux.HandleFunc("/blob", func(writer http.ResponseWriter, _ *http.Request) {
		observation.record("http", nil, payload, 0)
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("X-BOFBench-Payload-SHA256", hashBytes(payload))
		_, _ = writer.Write(payload)
	})
	mux.HandleFunc("/transient", func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		requestKey := hashBytes(body)
		transientMu.Lock()
		transientByRequest[requestKey]++
		attempt := transientByRequest[requestKey]
		transientMu.Unlock()
		observation.record("http", body, body, attempt)
		writer.Header().Set("X-BOFBench-Attempt", strconv.FormatUint(uint64(attempt), 10))
		if attempt == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
		} else {
			writer.WriteHeader(http.StatusOK)
		}
		_, _ = writer.Write(body)
	})
	mux.HandleFunc("/ws", func(writer http.ResponseWriter, request *http.Request) { websocketEcho(writer, request, observation) })
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(httpListener) }()

	tcpAddress := tcpListener.Addr().(*net.TCPAddr)
	udpAddress := udpConnection.LocalAddr().(*net.UDPAddr)
	httpAddress := httpListener.Addr().(*net.TCPAddr)
	base := fmt.Sprintf("http://127.0.0.1:%d", httpAddress.Port)
	return networkFixtureState{
		TCPHost: "127.0.0.1", TCPPort: tcpAddress.Port,
		UDPHost: "127.0.0.1", UDPPort: udpAddress.Port,
		HTTPURL: base + "/echo", HTTPBlobURL: base + "/blob", HTTPTransientURL: base + "/transient",
		WebSocketURL: fmt.Sprintf("ws://127.0.0.1:%d/ws", httpAddress.Port),
		DNSName:      "localhost", NetworkPayloadSHA256: hashBytes(payload),
	}, nil
}

func serveTCPEcho(listener net.Listener, observation *networkObservation) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			data, _ := io.ReadAll(io.LimitReader(connection, 1<<20))
			observation.record("tcp", data, data, 0)
			_, _ = connection.Write(data)
		}()
	}
}

func serveUDPEcho(connection *net.UDPConn, observation *networkObservation) {
	buffer := make([]byte, 65507)
	for {
		count, address, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		observation.record("udp", buffer[:count], buffer[:count], 0)
		_, _ = connection.WriteToUDP(buffer[:count], address)
	}
}

func websocketEcho(writer http.ResponseWriter, request *http.Request, observation *networkObservation) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok || request.Header.Get("Sec-WebSocket-Key") == "" {
		http.Error(writer, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	connection, stream, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	acceptDigest := sha1.Sum([]byte(request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(acceptDigest[:])
	_, _ = fmt.Fprintf(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	_ = stream.Flush()
	opcode, payload, err := readWebSocketFrame(stream.Reader)
	if err != nil {
		return
	}
	observation.record("websocket", payload, payload, 0)
	_ = writeWebSocketFrame(stream.Writer, opcode, payload)
	_ = stream.Flush()
}

func readWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0f
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		value := make([]byte, 2)
		if _, err := io.ReadFull(reader, value); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(value))
	} else if length == 127 {
		value := make([]byte, 8)
		if _, err := io.ReadFull(reader, value); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(value)
	}
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("websocket fixture frame exceeds limit")
	}
	mask := make([]byte, 4)
	if header[1]&0x80 != 0 {
		if _, err := io.ReadFull(reader, mask); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if header[1]&0x80 != 0 {
		for index := range payload {
			payload[index] ^= mask[index%4]
		}
	}
	return opcode, payload, nil
}

func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
