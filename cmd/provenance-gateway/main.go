package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Dev-31/provenance-layer2/internal/webhook"
)

const version = "2.0.0"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhooks/github", webhook.Handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	addr := ":" + port
	log.Printf("provenance-gateway %s listening on %s", version, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
