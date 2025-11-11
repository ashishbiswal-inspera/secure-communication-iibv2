package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"backend/certs"
)

//go:embed dist
var distFS embed.FS

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RequestData represents incoming POST request data
type RequestData struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// enableCors sets the necessary headers for CORS
func enableCors(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	// Allow common local dev origins (both HTTP for dev and HTTPS for production)
	switch origin {
	case "http://127.0.0.1:5173", "http://localhost:5173", "http://[::1]:5173",
		"https://127.0.0.1:9000", "https://localhost:9000":
		w.Header().Set("Access-Control-Allow-Origin", origin)
	default:
		// For same-origin requests (embedded frontend), allow the request
		// This is more secure than allowing "*"
		if origin == "" {
			// Same-origin request (no Origin header)
			w.Header().Set("Access-Control-Allow-Origin", "https://127.0.0.1:9000")
		}
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Timestamp, X-Signature")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// withCors wraps handlers to support CORS and preflight OPTIONS
func withCors(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		handler(w, r)
	}
}

// handleGet is a simple GET endpoint that sends JSON
func handleGet(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "GET request successful",
		Data: map[string]interface{}{
			"timestamp": "2025-11-05",
			"status":    "running",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePost is a POST endpoint that receives and responds with JSON
func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response := Response{
			Success: false,
			Message: "Method not allowed",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestData RequestData
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		log.Println("Decode error:", err)
		response := Response{
			Success: false,
			Message: "Invalid JSON data",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf("Received data: %+v\n", requestData)

	response := Response{
		Success: true,
		Message: "Data received successfully",
		Data:    requestData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePing is a simple ping endpoint to check server health
func handlePing(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "pong pong",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Initialize certificate manager (stores certs in user's AppData directory)
	certManager, err := certs.NewCertificateManager()
	if err != nil {
		log.Fatal("Failed to create certificate manager:", err)
	}

	// Ensure certificates exist (generate on first run, load on subsequent runs)
	if err := certManager.EnsureCertificates(); err != nil {
		log.Fatal("Failed to setup certificates:", err)
	}

	log.Printf("Certificates stored in: %s\n", certManager.CertDir)

	// API routes
	http.HandleFunc("/api/get", withCors(handleGet))
	http.HandleFunc("/api/post", withCors(handlePost))
	http.HandleFunc("/api/ping", withCors(handlePing))

	// Serve embedded frontend files
	distFSStripped, err := fs.Sub(distFS, "dist")
	if err != nil {
		log.Fatal("Failed to access embedded dist folder:", err)
	}

	// Handle all non-API routes by serving the React app
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If the path starts with /api, it will be handled by the API handlers above
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		// Try to open the file from embedded FS
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		file, err := distFSStripped.Open(path)
		if err != nil {
			// If file not found, serve index.html for client-side routing
			file, err = distFSStripped.Open("index.html")
			if err != nil {
				http.Error(w, "Could not open index.html", http.StatusInternalServerError)
				return
			}
		}
		defer file.Close()

		// Serve the file
		http.FileServer(http.FS(distFSStripped)).ServeHTTP(w, r)
	})

	// Configure TLS with mutual authentication
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certManager.GetCertPool(),
		MinVersion: tls.VersionTLS13, // Use TLS 1.3 for best security
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	// Create HTTPS server with mTLS
	server := &http.Server{
		Addr:      "127.0.0.1:9000", // Bind to localhost only
		TLSConfig: tlsConfig,
	}

	log.Println("🔒 Server running with mTLS on https://127.0.0.1:9000")
	log.Printf("📁 Certificates location: %s\n", certManager.CertDir)
	log.Println("⚠️  Client certificate required for all connections")

	// Start HTTPS server
	if err := server.ListenAndServeTLS(
		certManager.GetServerCertPath(),
		certManager.GetServerKeyPath(),
	); err != nil {
		log.Fatal("Failed to start HTTPS server:", err)
	}
}
