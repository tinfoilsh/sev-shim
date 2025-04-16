package dcode

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
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

	// Encode the entire compressed data
	encoded := base64.StdEncoding.EncodeToString(compressed)
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.ReplaceAll(encoded, "=", "")

	// Chunk
	domainSuffix := "." + domain
	maxLength := 253 - len(domainSuffix)
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
	var b64GzJSON []byte
	for _, domain := range domains {
		domain = strings.Split(domain, ".")[0]
		domain = strings.ReplaceAll(domain, "-", "+")
		domain = strings.ReplaceAll(domain, "_", "/")
		b64GzJSON = append(b64GzJSON, domain...)
	}

	// Add padding
	padding := len(b64GzJSON) % 4
	if padding > 0 {
		b64GzJSON = append(b64GzJSON, bytes.Repeat([]byte("="), 4-padding)...)
	}

	// Decode base64
	gzJSON, err := base64.StdEncoding.DecodeString(string(b64GzJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
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
