package main

import (
	"encoding/base64"
	"fmt"

	sevabi "github.com/google/go-sev-guest/abi"
	sevclient "github.com/google/go-sev-guest/client"
	tdxclient "github.com/google/go-tdx-guest/client"
	"github.com/klauspost/cpuid/v2"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/verifier/attestation"
)

// sevAttestationReport gets a SEV-SNP signed attestation report over a TLS certificate fingerprint
func sevAttestationReport(certFP string) (*attestation.Document, error) {
	var userData [64]byte
	copy(userData[:], certFP)

	qp, err := sevclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}
	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	if len(report) > sevabi.ReportSize {
		report = report[:sevabi.ReportSize]
	}

	return &attestation.Document{
		Format: attestation.SevGuestV1,
		Body:   base64.StdEncoding.EncodeToString(report),
	}, nil
}

// tdxAttestationReport gets a TDX signed attestation report over a TLS certificate fingerprint
func tdxAttestationReport(certFP string) (*attestation.Document, error) {
	var userData [64]byte
	copy(userData[:], certFP)

	qp, err := tdxclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}

	if err := qp.IsSupported(); err != nil {
		return nil, fmt.Errorf("TDX is not supported: %v", err)
	}

	report, err := qp.GetRawQuote(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to get quote: %v", err)
	}

	return &attestation.Document{
		Format: "https://tinfoil.sh/predicate/tdx-guest/v1",
		Body:   base64.StdEncoding.EncodeToString(report),
	}, nil
}

func attestationReport(certFP string) (*attestation.Document, error) {
	if cpuid.CPU.IsVendor(cpuid.AMD) {
		log.Info("Requesting AMD SEV-SNP quote")
		return sevAttestationReport(certFP)
	} else if cpuid.CPU.IsVendor(cpuid.Intel) {
		log.Info("Requesting Intel TDX quote")
		return tdxAttestationReport(certFP)
	} else {
		return nil, fmt.Errorf("attestation report for vendor %s not supported", cpuid.CPU.VendorString)
	}
}
