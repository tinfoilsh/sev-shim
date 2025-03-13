package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"io"
	"log"
	"math/big"
	"net/http"
)

var (
	listenAddr = flag.String("l", ":8087", "Listen address")

	apiKeys map[string]map[string]int
)

func generateAPIKey() (string, error) {
	const (
		alphanumeric = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		keyLength    = 32
	)

	key := make([]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		if err != nil {
			return "", err
		}
		key[i] = alphanumeric[n.Int64()]
	}
	return string(key), nil
}

func main() {
	flag.Parse()

	apiKeys = make(map[string]map[string]int)

	http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiKeys)
	})

	http.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		k, err := generateAPIKey()
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		apiKeys[k] = make(map[string]int)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(k)
	})

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		apiKey, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if _, ok := apiKeys[string(apiKey)]; !ok {
			log.Printf("Rejected request with API key: %s", apiKey)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("Accepted request with API key: %s", apiKey)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			APIKey string `json:"api_key"`
			Tokens int    `json:"tokens"`
			Model  string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		apiKeys[b.APIKey][b.Model] += b.Tokens

		log.Printf("Collected %d tokens for API key: %s", b.Tokens, b.APIKey)
		w.Write([]byte("OK"))
	})

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
