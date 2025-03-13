package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
)

var (
	listenAddr = flag.String("l", ":8087", "Listen address")
	validKeys  = flag.String("k", "key1,key2,key3", "Valid API keys")
)

func main() {
	flag.Parse()

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

		if !slices.Contains(strings.Split(*validKeys, ","), string(apiKey)) {
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
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		log.Printf("Received %d tokens for API key: %s", b.Tokens, b.APIKey)

		w.Write([]byte("OK"))
	})

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
