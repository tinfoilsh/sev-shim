package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Signer struct {
	PrivateKey ed25519.PrivateKey `json:"private"`
	PublicKey  ed25519.PublicKey  `json:"public"`
	Validity   time.Duration      `json:"validity"`
}

func ImportSigner(signerFile string) (*Signer, error) {
	file, err := os.Open(signerFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open signer file: %w", err)
	}
	defer file.Close()

	var s Signer
	if err := json.NewDecoder(file).Decode(&s); err != nil {
		return nil, fmt.Errorf("failed to decode signer file: %w", err)
	}
	return &s, nil
}

func NewSigner(validity time.Duration) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Signer{
		PrivateKey: priv,
		PublicKey:  pub,
		Validity:   validity,
	}, nil
}

func (s *Signer) Save(filename string) error {
	signerFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create signer file: %w", err)
	}
	defer signerFile.Close()

	return json.NewEncoder(signerFile).Encode(s)
}

// PubKey returns the public key in base64 format
func (s *Signer) PubKey() string {
	return base64.RawURLEncoding.EncodeToString(s.PublicKey)
}

// NewAPIKey generates a new random API key
func (s *Signer) NewAPIKey() (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().Unix()))

	validityBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(validityBytes, uint64(s.Validity.Seconds()))

	message := make([]byte, 0, nonceSize+timestampSize+validitySize)
	message = append(message, nonce...)
	message = append(message, timeBytes...)
	message = append(message, validityBytes...)

	signature := ed25519.Sign(s.PrivateKey, message)

	finalKey := make([]byte, 0, totalSize)
	finalKey = append(finalKey, message...)
	finalKey = append(finalKey, signature...)

	return base64.RawURLEncoding.EncodeToString(finalKey), nil
}
