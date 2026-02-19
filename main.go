package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
)

// Requires the bas/tai branch of  github.com/bwesterb/go

//go:embed index.html
var htmlTemplate string

var tmpl *template.Template
var useTLS bool

func errResp(w http.ResponseWriter, status int, msg string, args ...any) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	fmt.Fprintf(w, msg, args...)
}

func isPQ(kex tls.CurveID) bool {
	switch kex {
	case tls.X25519MLKEM768:
		return true
	}
	return false
}

type transportResult struct {
	Kex   tls.CurveID `json:"Kex"`
	PQ    bool        `json:"PQ"`
	TAIs  []string    `json:"TAIs"`
	Error string      `json:"Error,omitempty"`
}

func taisFromState(state tls.ConnectionState) []string {
	if state.TrustAnchorIdentifiers == nil {
		return nil
	}
	tais := []string{}
	for _, tai := range state.TrustAnchorIdentifiers {
		tais = append(tais, tai.String())
	}
	return tais
}

func testTCP(remote, serverName string, insecure bool) transportResult {
	tcpConn, err := net.Dial("tcp", remote)
	if err != nil {
		return transportResult{Error: fmt.Sprintf("dial: %v", err)}
	}
	defer tcpConn.Close()

	conn := tls.Client(tcpConn, &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     insecure,
		TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{},
	})
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return transportResult{Error: fmt.Sprintf("handshake: %v", err)}
	}

	state := conn.ConnectionState()
	return transportResult{
		Kex:  state.CurveID,
		PQ:   isPQ(state.CurveID),
		TAIs: taisFromState(state),
	}
}

func testQUIC(remote, serverName string, insecure bool) transportResult {
	udpAddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return transportResult{Error: fmt.Sprintf("resolve: %v", err)}
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return transportResult{Error: fmt.Sprintf("listen udp: %v", err)}
	}

	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()

	tlsConfig := &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     insecure,
		NextProtos:             []string{"h3"},
		TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{},
	}

	ctx := context.Background()
	conn, err := transport.Dial(ctx, udpAddr, tlsConfig, &quic.Config{})
	if err != nil {
		return transportResult{Error: fmt.Sprintf("dial: %v", err)}
	}
	defer conn.CloseWithError(0, "done")

	state := conn.ConnectionState().TLS
	return transportResult{
		Kex:  state.CurveID,
		PQ:   isPQ(state.CurveID),
		TAIs: taisFromState(state),
	}
}

func remoteTest(w http.ResponseWriter, req *http.Request) {
	remote := req.PostFormValue("remote")
	remoteHost, _, err := net.SplitHostPort(remote)
	if err != nil {
		errResp(w, 400, "can't parse remote: %v", err)
		return
	}

	serverName := remoteHost
	if req.PostFormValue("servername") != "" {
		serverName = req.PostFormValue("servername")
	}

	insecure := req.PostFormValue("insecure") != ""

	transport := req.PostFormValue("transport")

	var result transportResult
	switch transport {
	case "quic":
		result = testQUIC(remote, serverName, insecure)
	case "tcp":
		result = testTCP(remote, serverName, insecure)
	default:
		errResp(w, 400, "missing or invalid transport parameter (use tcp or quic)")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&result)
}

func handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		err := req.ParseForm()
		if err != nil {
			errResp(w, 400, "can't parse form: %v", err)
			return
		}
		if req.PostFormValue("remote") != "" {
			remoteTest(w, req)
			return
		}

		errResp(w, 400, "missing remote parameter")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	data := struct {
		TLS       bool
		ClientKex string
		ClientPQ  bool
		TAIs      string
	}{TLS: useTLS}
	if req.TLS != nil {
		data.ClientKex = req.TLS.CurveID.String()
		data.ClientPQ = isPQ(req.TLS.CurveID)
		if req.TLS.TrustAnchorIdentifiers != nil {
			data.TAIs = fmt.Sprintf("%v", req.TLS.TrustAnchorIdentifiers)
		}
	}
	err := tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Failed to render template: %v", err)
		errResp(w, 500, "template render failed")
	}
	return
}

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Address to bind to")
	certFile := flag.String("cert", "", "Path to TLS certificate file")
	keyFile := flag.String("key", "", "Path to TLS private key file")

	flag.Parse()

	var err error
	tmpl, err = template.New("index").Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	http.HandleFunc("/", handler)

	// Configure server with dummy TAI for testing.
	var tai tls.TrustAnchorIdentifier
	tai.FromSegments([]uint32{62253})

	srv := http.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{tai},
		},
	}

	if *certFile != "" && *keyFile != "" {
		useTLS = true
		log.Printf("Listening on %s (TLS)", *addr)
		if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			log.Fatalf("ListenAndServeTLS: %v", err)
		}
	}

	if *certFile == "" && *keyFile == "" {
		log.Printf("Listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}

	log.Fatalf("-cert and -key must be set together")
}
