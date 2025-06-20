package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/tinfoilsh/tfshim/key/offline"
)

var (
	validity = flag.Duration("v", 24*time.Hour, "Key validity duration")
	keys     = flag.Int("n", 10, "Number of keys to generate")
)

func main() {
	flag.Parse()

	keySigner, err := offline.NewSigner(*validity)
	if err != nil {
		log.Fatalf("Failed to create key signer: %v", err)
	}

	log.Printf("Generated key pair with pubkey %s", keySigner.PubKey())

	for i := 0; i < *keys; i++ {
		k, err := keySigner.NewAPIKey()
		if err != nil {
			log.Fatalf("Failed to generate API key: %v", err)
		}
		fmt.Println(k)
	}
}
