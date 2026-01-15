package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
)

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

func remoteTest(w http.ResponseWriter, req *http.Request) {
	remote := req.PostFormValue("remote")
	remoteHost, _, err := net.SplitHostPort(remote)
	if err != nil {
		errResp(w, 400, "can't parse remote: %v", err)
		return
	}
	tcpConn, err := net.Dial("tcp", remote)
	if err != nil {
		errResp(w, 400, "can't dial: %v", err)
		return
	}
	defer tcpConn.Close()

	serverName := remoteHost
	if req.PostFormValue("servername") != "" {
		serverName = req.PostFormValue("servername")
	}

	insecure := req.PostFormValue("insecure") != ""

	conn := tls.Client(tcpConn, &tls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     insecure,
		TrustAnchorIdentifiers: []tls.TrustAnchorIdentifier{},
	})

	defer conn.Close()
	err = conn.Handshake()
	if err != nil {
		errResp(w, 400, "handshake: %v", err)
		return
	}

	state := conn.ConnectionState()
	var tais []string
	if state.TrustAnchorIdentifiers != nil {
		tais = []string{}
		for _, tai := range state.TrustAnchorIdentifiers {
			tais = append(tais, tai.String())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	ret := struct {
		Kex    tls.CurveID
		Remote string
		PQ     bool
		TAIs   []string
	}{
		Kex:    state.CurveID,
		Remote: remote,
		PQ:     isPQ(state.CurveID),
		TAIs:   tais,
	}
	json.NewEncoder(w).Encode(&ret)
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

	srv := http.Server{
		Addr: *addr,
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
