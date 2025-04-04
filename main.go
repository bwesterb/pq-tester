package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

type ConnContextKey struct{}

type Conn struct {
	kex tls.CurveID
	hrr bool
}

func (c *Conn) eventHandler(ev tls.CFEvent) {
	switch e := ev.(type) {
	case tls.CFEventTLS13HRR:
		c.hrr = true
	case tls.CFEventTLS13NegotiatedKEX:
		c.kex = e.KEX
	}
}

func errResp(w http.ResponseWriter, status int, msg string, args ...any) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	fmt.Fprintf(w, msg, args...)
}

func handler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	if req.Method == "POST" {
		err := req.ParseForm()
		if err != nil {
			errResp(w, 400, "can't parse form: %v", err)
			return
		}
		newConn := &Conn{}
		remote := req.PostFormValue("remote")
		newCtx := context.WithValue(
			ctx,
			tls.CFEventHandlerContextKey{},
			newConn.eventHandler,
		)
		remoteHost, _, err := net.SplitHostPort(remote)
		if err != nil {
			errResp(w, 400, "can't parse remote: %v", err)
			return
		}
		tcpConn, err := (&net.Dialer{}).DialContext(
			newCtx,
			"tcp",
			remote,
		)
		if err != nil {
			errResp(w, 400, "can't dial: %v", err)
			return
		}
		defer tcpConn.Close()
		method := req.PostFormValue("method")

		curves := []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.X25519Kyber768Draft00,
			tls.X25519MLKEM768,
		}

		if method == "supported" {
		} else if method == "preferred" || method == "" {
			curves = []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519Kyber768Draft00,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}
		} else {
			errResp(w, 400, "unknown method")
			return
		}
		serverName := remoteHost
		if req.PostFormValue("servername") != "" {
			serverName = req.PostFormValue("servername")
		}

		insecure := req.PostFormValue("insecure") != ""

		conn := tls.Client(tcpConn, &tls.Config{
			CurvePreferences:   curves,
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
		})

		defer conn.Close()
		err = conn.HandshakeContext(newCtx)
		if err != nil {
			errResp(w, 400, "handshake: %v", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		ret := struct {
			Kex    tls.CurveID
			HRR    bool
			Remote string
		}{
			Kex:    newConn.kex,
			HRR:    newConn.hrr,
			Remote: remote,
		}
		json.NewEncoder(w).Encode(&ret)

		return
	}
	conn := ctx.Value(ConnContextKey{}).(*Conn)
	w.Header().Set("Content-Type", "application/json")
	ret := struct {
		Kex tls.CurveID
		HRR bool
	}{
		Kex: conn.kex,
		HRR: conn.hrr,
	}
	json.NewEncoder(w).Encode(&ret)
}

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Address to bind to")

	flag.Parse()

	http.HandleFunc("/", handler)

	log.Printf("Listening on %s", *addr)
	srv := http.Server{
		Addr: *addr,
		TLSConfig: &tls.Config{
			CurvePreferences: []tls.CurveID{
				tls.X25519Kyber768Draft00,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			conn := &Conn{}
			return context.WithValue(
				context.WithValue(
					ctx,
					tls.CFEventHandlerContextKey{},
					conn.eventHandler,
				),
				ConnContextKey{},
				conn,
			)
		},
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
