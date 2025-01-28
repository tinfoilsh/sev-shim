package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/google/go-sev-guest/client"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

func ownFP() ([]byte, error) {
	resp, err := http.Get("https://inf.delta.tinfoil.sh")
	if err != nil {
		return nil, err
	}

	return attestation.CertFP(*resp.TLS), nil
}

func getAttestation() ([]byte, error) {
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
	att, err := client.GetQuoteProto(qp, userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}
	return []byte(att.String()), nil
}

func main() {
	att, err := getAttestation()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body := attestation.Document{
			Format: attestation.SevGuestV1,
			Body:   base64.StdEncoding.EncodeToString(att),
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})

	log.Fatal(http.ListenAndServe(":6000", nil))
}
