package dcode

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/martinlindhe/base36"

	"github.com/tinfoilsh/verifier/attestation"
)

func gzCompress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %v", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing reader: %v", err)
	}
	return b.Bytes(), nil
}

func gzDecompress(data []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	return io.ReadAll(gzReader)
}

// Encode encodes an attestation document into a string of domains
func Encode(att *attestation.Document, domain string) ([]string, error) {
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %v", err)
	}
	compressed, err := gzCompress(attJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to compress attestation: %v", err)
	}

	// Encode the entire compressed data using base36
	encoded := base36.EncodeBytes(compressed)
	encoded = strings.ToLower(encoded) // Make it lowercase for better readability in domains

	// Chunk
	domainSuffix := "." + domain
	maxLength := 63 - len(domainSuffix) - 2 // Reserve space for NN prefix
	var domains []string
	for i := 0; i < len(encoded); i += maxLength {
		end := min(i+maxLength, len(encoded))
		chunk := encoded[i:end]
		index := len(domains)
		domains = append(domains, fmt.Sprintf("%02d%s%s", index, chunk, domainSuffix))
	}

	return domains, nil
}

// Decode decodes a string of domains into an attestation document
func Decode(domains []string) (*attestation.Document, error) {
	// Sort domains by their NN prefix
	sort.Slice(domains, func(i, j int) bool {
		return domains[i][:2] < domains[j][:2]
	})

	// Extract encoded data from the domains
	var encodedData string
	for _, domain := range domains {
		domain = strings.Split(domain, ".")[0]
		// Remove the 2-digit prefix
		encodedData += domain[2:]
	}

	// Decode base36
	compressed := base36.DecodeToBytes(strings.ToUpper(encodedData))

	// Decompress
	attJSON, err := gzDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress attestation: %v", err)
	}

	// Unmarshal
	var att attestation.Document
	if err := json.Unmarshal(attJSON, &att); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %v", err)
	}
	return &att, nil
}
