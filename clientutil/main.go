package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"flag"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/tfshim/dcode"
	tlsutil "github.com/tinfoilsh/tfshim/tls"
)

var (
	server   = flag.String("s", "localhost", "Server to connect to")
	insecure = flag.Bool("i", false, "Skip TLS certificate verification")
)

func main() {
	flag.Parse()
	if *server == "" {
		log.Fatal("Server address is required")
	}
	if !strings.Contains(*server, ":") {
		*server += ":443"
	}

	conn, err := tls.Dial("tcp", *server, &tls.Config{
		InsecureSkipVerify: *insecure,
	})
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	cert := conn.ConnectionState().PeerCertificates[0]
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		fmt.Println(tlsutil.KeyFP(cert.PublicKey.(*ecdsa.PublicKey)))
	default:
		fmt.Println("Public key is not an ECDSA key")
	}

	// Extract domains from certificate
	domainSet := make(map[string]bool)
	for _, name := range cert.DNSNames {
		domainSet[name] = true
	}

	baseDomains := make(map[string]bool)
	for domain := range domainSet {
		for otherDomain := range domainSet {
			if otherDomain != domain && strings.HasSuffix(otherDomain, "."+domain) {
				baseDomains[domain] = true
				break
			}
		}
	}

	var domains []string
	for domain := range domainSet {
		if !baseDomains[domain] {
			domains = append(domains, domain)
			log.Printf("Domain: %s", domain)
		}
	}

	att, err := dcode.Decode(domains)
	if err != nil {
		log.Fatalf("Failed to decode attestation: %v", err)
	}
	log.Debugf("Attestation: %+v\n", att)

	// Verify the attestation
	measurement, err := att.Verify()
	if err != nil {
		log.Fatalf("Failed to verify attestation: %v", err)
	}
	log.Infof("Attestation verified successfully. Measurement: %+v", measurement)
}
