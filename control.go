package main

import (
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

type ControlServer struct {
	kv sync.Map
}

func newControlServer() *ControlServer {
	return &ControlServer{
		kv: sync.Map{},
	}
}

func (s *ControlServer) Start(listenPort int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", listenPort), mux))
}
