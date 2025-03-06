package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tinfoilsh/sev-shim/key"
)

var (
	signer   = flag.String("s", "signer.json", "Signer file, generate new if empty")
	validity = flag.Duration("v", 24*time.Hour, "Key validity duration")
	keys     = flag.Int("n", 0, "Number of keys to generate")
)

func main() {
	flag.Parse()

	var keySigner *key.Signer
	if _, err := os.Stat(*signer); err == nil {
		keySigner, err = key.ImportSigner(*signer)
		if err != nil {
			log.Fatalf("Failed to load signer: %v", err)
		}
		log.Printf("Imported key pair with pubkey %s", keySigner.PubKey())
	} else {
		keySigner, err = key.NewSigner(*validity)
		if err != nil {
			log.Fatalf("Failed to create key signer: %v", err)
		}
		if err := keySigner.Save(*signer); err != nil {
			log.Fatalf("Failed to save signer: %v", err)
		}
		log.Printf("Generated key pair with pubkey %s", keySigner.PubKey())
	}

	for i := 0; i < *keys; i++ {
		k, err := keySigner.NewAPIKey()
		if err != nil {
			log.Fatalf("Failed to generate API key: %v", err)
		}
		fmt.Println(k)
	}
}
