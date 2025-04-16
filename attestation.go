package main

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/tinfoilsh/verifier/attestation"
)

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
