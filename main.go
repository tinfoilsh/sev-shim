package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

var (
	listenAddr = flag.String("listen", ":6000", "listen address")
)

func ownFP() ([]byte, error) {
	resp, err := http.Get("https://inf.delta.tinfoil.sh")
	if err != nil {
		return nil, err
	}

	return attestation.CertFP(*resp.TLS), nil
}

func attestationReport() (*attestation.Document, error) {
	fp, err := ownFP()
	if err != nil {
		return nil, err
	}
	var userData [64]byte
	copy(userData[:], fp)

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

	log.Print("Fetching attestation")
	att, err := attestationReport()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
