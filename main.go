package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/caddyserver/certmagic"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

var (
	listenAddr = flag.String("l", ":443", "listen address")
	domain     = flag.String("d", "", "TLS domain name")
	email      = flag.String("e", "", "TLS email address")
	staging    = flag.Bool("s", false, "use staging CA")
)

func attestationReport(certFP string) (*attestation.Document, error) {
	var userData [64]byte
	copy(userData[:], certFP)

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}
	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	if len(report) > abi.ReportSize {
		report = report[:abi.ReportSize]
	}

	return &attestation.Document{
		Format: attestation.SevGuestV1,
		Body:   base64.StdEncoding.EncodeToString(report),
	}, nil
}

func main() {
	flag.Parse()
	if *domain == "" {
		log.Fatal("domain is required")
	}
	if *email == "" {
		log.Fatal("email is required")
	}

	mux := http.NewServeMux()

	certmagic.DefaultACME.Email = *email
	if *staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	} else {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	}
	tlsConfig, err := certmagic.TLS([]string{*domain})
	if err != nil {
		log.Fatalf("Failed to get TLS config: %v", err)
	}

	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
		ServerName: *domain,
	})
	if err != nil {
		log.Fatalf("Failed to get certificate: %v", err)
	}
	certFP := sha256.Sum256(cert.Leaf.Raw)
	certFPHex := hex.EncodeToString(certFP[:])

	log.Printf("Fetching attestation over %s", certFPHex)
	att, err := attestationReport(certFPHex)
	if err != nil {
		log.Fatal(err)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})

	httpServer := &http.Server{
		Addr:      *listenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
