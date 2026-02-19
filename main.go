package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Requires the bas/tai branch of  github.com/bwesterb/go

//go:embed index.html
var htmlTemplate string

var tmpl *template.Template
var useTLS bool

// OID for MTC proof signature algorithm (experimental):
// 1.3.6.1.4.1.44363.47.0
var oidMTCProof = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}

// Base TAI for the MTCA shard3 landmark sequence.
const mtcBaseTAI = "44363.48.7"
const landmarkURL = "https://bootstrap-mtca-shard3.cloudflareresearch.com/landmark"

var (
	latestTAIMu sync.RWMutex
	latestTAI   tls.TrustAnchorIdentifier
)

func fetchLandmark() error {
	resp, err := http.Get(landmarkURL)
	if err != nil {
		return fmt.Errorf("fetching landmark: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("landmark endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading landmark body: %w", err)
	}

	// First line: <last_landmark> <num_active_landmarks>
	firstLine, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
	parts := strings.Fields(firstLine)
	if len(parts) != 2 {
		return fmt.Errorf("invalid landmark header: %q", firstLine)
	}
	lastLandmark, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid last_landmark: %w", err)
	}

	// Build the TAI for the latest landmark: 44363.48.7.<lastLandmark>
	taiStr := fmt.Sprintf("%s.%d", mtcBaseTAI, lastLandmark)
	var tai tls.TrustAnchorIdentifier
	if err := tai.UnmarshalText([]byte(taiStr)); err != nil {
		return fmt.Errorf("parsing TAI %q: %w", taiStr, err)
	}

	latestTAIMu.Lock()
	latestTAI = tai
	latestTAIMu.Unlock()

	log.Printf("Updated landmark: last=%d, TAI=%s", lastLandmark, taiStr)
	return nil
}

func refreshLandmarkPeriodically() {
	for {
		time.Sleep(1 * time.Hour)
		if err := fetchLandmark(); err != nil {
			log.Printf("Failed to refresh landmark: %v", err)
		}
	}
}

func getLatestTAI() tls.TrustAnchorIdentifier {
	latestTAIMu.RLock()
	defer latestTAIMu.RUnlock()
	return latestTAI
}

// isMTC checks if a certificate is a Merkle Tree Certificate by inspecting
// the signature algorithm OID.
func isMTC(cert *x509.Certificate) bool {
	// Parse the raw certificate to get the actual signature algorithm OID,
	// since Go's x509 package maps unknown algorithms to UnknownSignatureAlgorithm.
	var rawCert struct {
		TBSCertificate struct {
			Version            asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber       asn1.RawValue
			SignatureAlgorithm asn1.RawValue
		}
		SignatureAlgorithm asn1.RawValue
	}
	if _, err := asn1.Unmarshal(cert.Raw, &rawCert); err != nil {
		return false
	}

	var algID struct {
		Algorithm asn1.ObjectIdentifier
	}
	if _, err := asn1.Unmarshal(rawCert.SignatureAlgorithm.FullBytes, &algID); err != nil {
		return false
	}

	return algID.Algorithm.Equal(oidMTCProof)
}

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
	MTC   bool        `json:"MTC"`
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

	latestTAI := getLatestTAI()
	conn := tls.Client(tcpConn, &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{latestTAI},
	})
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return transportResult{Error: fmt.Sprintf("handshake: %v", err)}
	}

	state := conn.ConnectionState()
	result := transportResult{
		Kex:  state.CurveID,
		PQ:   isPQ(state.CurveID),
		TAIs: taisFromState(state),
	}
	if len(state.PeerCertificates) > 0 {
		result.MTC = isMTC(state.PeerCertificates[0])
	}
	return result
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

	latestTAI := getLatestTAI()
	tlsConfig := &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h3"},
		TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{latestTAI},
	}

	ctx := context.Background()
	conn, err := transport.Dial(ctx, udpAddr, tlsConfig, &quic.Config{})
	if err != nil {
		return transportResult{Error: fmt.Sprintf("dial: %v", err)}
	}
	defer conn.CloseWithError(0, "done")

	state := conn.ConnectionState().TLS
	result := transportResult{
		Kex:  state.CurveID,
		PQ:   isPQ(state.CurveID),
		TAIs: taisFromState(state),
	}
	if len(state.PeerCertificates) > 0 {
		result.MTC = isMTC(state.PeerCertificates[0])
	}
	return result
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

	// Fetch landmarks on startup.
	if err := fetchLandmark(); err != nil {
		log.Fatalf("Failed to fetch initial landmark: %v", err)
	}
	go refreshLandmarkPeriodically()

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
