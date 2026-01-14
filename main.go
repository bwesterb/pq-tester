package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

//go:embed index.html
var html string

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

func handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		err := req.ParseForm()
		if err != nil {
			errResp(w, 400, "can't parse form: %v", err)
			return
		}
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
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
		})

		defer conn.Close()
		err = conn.Handshake()
		if err != nil {
			errResp(w, 400, "handshake: %v", err)
			return
		}

		state := conn.ConnectionState()
		w.Header().Set("Content-Type", "application/json")
		ret := struct {
			Kex    tls.CurveID
			Remote string
			PQ     bool
		}{
			Kex:    state.CurveID,
			Remote: remote,
			PQ:     isPQ(state.CurveID),
		}
		json.NewEncoder(w).Encode(&ret)

		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, html)
	return
}

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Address to bind to")

	flag.Parse()

	http.HandleFunc("/", handler)

	log.Printf("Listening on %s", *addr)
	srv := http.Server{
		Addr: *addr,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
