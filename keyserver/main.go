package main

import (
	"flag"
	"log"
	"net/http"
	"slices"
	"strings"
)

var (
	listenAddr = flag.String("l", ":8080", "Listen address")
	allowed    = flag.String("a", "", "Allowed API keys")
)

func main() {
	flag.Parse()

	good := strings.Split(*allowed, ",")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if slices.Contains(good, apiKey) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			log.Printf("Accepting key %s", apiKey)
			return
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			log.Printf("Rejecting key %s", apiKey)
		}
	})

	log.Printf("Listening on %s", *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
