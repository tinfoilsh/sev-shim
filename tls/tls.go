package tls

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// KeyFP returns the fingerprint of a given ECDSA public key
func KeyFP(publicKey *ecdsa.PublicKey) string {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}
