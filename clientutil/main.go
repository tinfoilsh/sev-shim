package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/tinfoilsh/sev-shim/dcode"
	tlsutil "github.com/tinfoilsh/sev-shim/tls"
)

var (
	server   = flag.String("s", "localhost:443", "Server to connect to")
	insecure = flag.Bool("i", false, "Skip TLS certificate verification")
)

func main() {
	flag.Parse()

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
	fmt.Printf("Attestation: %+v\n", att)
}
