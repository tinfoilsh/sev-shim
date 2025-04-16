package dcode

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/tinfoilsh/verifier/attestation"
)

func gzCompress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write data: %v", err)
	}
	if err := gz.Close(); err != nil {
		log.Fatal(err)
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

	// Encode the entire compressed data using base32
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := encoder.EncodeToString(compressed)
	encoded = strings.ToLower(encoded) // Make it lowercase for better readability in domains

	// Chunk
	domainSuffix := "." + domain
	maxLength := 63 - len(domainSuffix)
	var domains []string
	for i := 0; i < len(encoded); i += maxLength {
		end := min(i+maxLength, len(encoded))
		chunk := encoded[i:end]
		domains = append(domains, chunk+domainSuffix)
	}

	return domains, nil
}

// Decode decodes a string of domains into an attestation document
func Decode(domains []string) (*attestation.Document, error) {
	var encodedData string
	for _, domain := range domains {
		domain = strings.Split(domain, ".")[0]
		encodedData += domain
	}

	// Decode base32
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	gzJSON, err := encoder.DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base32: %v", err)
	}

	// Decompress
	attJSON, err := gzDecompress(gzJSON)
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
