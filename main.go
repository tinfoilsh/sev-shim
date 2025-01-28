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
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

var version = "dev"

var (
	listenAddr = flag.String("l", ":443", "listen address")
	staging    = flag.Bool("s", false, "use staging CA")
	upstream   = flag.Int("u", 8080, "upstream port")

	email = "tls@tinfoil.sh"
)

// cmdlineParam returns the value of a parameter from the kernel command line
func cmdlineParam(key string) (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}

	for _, p := range strings.Split(string(cmdline), " ") {
		if strings.HasPrefix(p, key+"=") {
			return strings.TrimPrefix(p, key+"="), nil
		}
	}

	return "", fmt.Errorf("missing %s", key)
}

// attestationReport gets a SEV-SNP signed attestation report over a TLS certificate fingerprint
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

func cors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
}

func main() {
	flag.Parse()

	domain, err := cmdlineParam("tinfoil-domain")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting SEV-SNP attestation shim %s domain %s", version, domain)

	mux := http.NewServeMux()

	// Request TLS certificate
	certmagic.DefaultACME.Email = email
	if *staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	} else {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	}
	tlsConfig, err := certmagic.TLS([]string{domain})
	if err != nil {
		log.Fatalf("Failed to get TLS config: %v", err)
	}

	// Get certificate from TLS config
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
		ServerName: domain,
	})
	if err != nil {
		log.Fatalf("Failed to get certificate: %v", err)
	}
	certFP := sha256.Sum256(cert.Leaf.Raw)
	certFPHex := hex.EncodeToString(certFP[:])

	// Request SEV-SNP attestation
	log.Printf("Fetching attestation over %s", certFPHex)
	att, err := attestationReport(certFPHex)
	if err != nil {
		log.Fatal(err)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
		proxy := httputil.NewSingleHostReverseProxy(&url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("localhost:%d", *upstream),
		})
		proxy.ServeHTTP(w, r)
	})

	mux.HandleFunc("/.well-known/tinfoil-attestation", func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
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
