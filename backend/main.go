package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"
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
	// Allow common local dev origins
	switch origin {
	case "http://127.0.0.1:5173", "http://localhost:5173", "http://[::1]:5173":
		w.Header().Set("Access-Control-Allow-Origin", origin)
	default:
		// For quick dev testing you can allow everything
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
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

	log.Println("Server running on http://localhost:9000")
	log.Fatal(http.ListenAndServe(":9000", nil))
}
