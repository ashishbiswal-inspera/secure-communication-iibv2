package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
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

// IIWConfig represents the Iceworm browser configuration
type IIWConfig struct {
	AllowCapture       bool                    `json:"allowCapture"`
	AllowedUrlRegexps  []string                `json:"allowedUrlRegexps"`
	AllowedUrls        []string                `json:"allowedUrls"`
	CefArgs            map[string]string       `json:"cefArgs"`
	DownloadCmdDir     string                  `json:"downloadCmdDir"`
	DownloadCmds       interface{}             `json:"downloadCmds"`
	DownloadDir        string                  `json:"downloadDir"`
	DownloadRegexpCmds interface{}             `json:"downloadRegexpCmds"`
	Headless           bool                    `json:"headless"`
	KeepAppOnTop       bool                    `json:"keepAppOnTop"`
	KioskMode          bool                    `json:"kioskMode"`
	NoDefaultCefArgs   bool                    `json:"noDefaultCefArgs"`
	NoToolbar          bool                    `json:"noToolbar"`
	QuitPasswordHash   string                  `json:"quitPasswordHash"`
	QuitUrl            string                  `json:"quitUrl"`
	ShareContent       bool                    `json:"shareContent"`
	StartUrls          []string                `json:"startUrls"`
	UrlRegexpWindows   map[string]WindowConfig `json:"urlRegexpWindows"`
	UserAgent          string                  `json:"userAgent"`
}

// WindowConfig represents window configuration for URL patterns
type WindowConfig struct {
	Height           int         `json:"height"`
	Left             int         `json:"left"`
	LoadedTimeout    int         `json:"loadedTimeout"`
	LoadedUrlRegexps interface{} `json:"loadedUrlRegexps"`
	LoadedUrls       interface{} `json:"loadedUrls"`
	NoClose          bool        `json:"noClose"`
	NoResize         bool        `json:"noResize"`
	NoTitleBar       bool        `json:"noTitleBar"`
	Title            string      `json:"title"`
	Top              int         `json:"top"`
	Width            int         `json:"width"`
}

// Global variable to track generated config file
var generatedConfigFile string

// getFreePort asks the OS for a free open port that is ready to use
func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// generateIIWConfig creates an Iceworm config file with the dynamic port
func generateIIWConfig(port int) (string, error) {
	// Generate unique filename
	uniqueNumber := time.Now().UTC().Unix()
	configFileName := fmt.Sprintf("iceworm-config-%d.json", uniqueNumber)

	serverURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Create config structure
	config := IIWConfig{
		AllowCapture:      false,
		AllowedUrlRegexps: []string{".*"},
		AllowedUrls: []string{
			serverURL,
			"http://127.0.0.1:5173",
			"http://localhost:5173",
		},
		CefArgs: map[string]string{
			"remote-debugging-port": "9222",
		},
		DownloadCmdDir:     "",
		DownloadCmds:       nil,
		DownloadDir:        "",
		DownloadRegexpCmds: nil,
		Headless:           false,
		KeepAppOnTop:       false,
		KioskMode:          false,
		NoDefaultCefArgs:   false,
		NoToolbar:          false,
		QuitPasswordHash:   "",
		QuitUrl:            "",
		ShareContent:       false,
		StartUrls:          []string{serverURL},
		UrlRegexpWindows: map[string]WindowConfig{
			".*": {
				Height:           1,
				Left:             0,
				LoadedTimeout:    0,
				LoadedUrlRegexps: nil,
				LoadedUrls:       nil,
				NoClose:          false,
				NoResize:         false,
				NoTitleBar:       false,
				Title:            "Iceworm Dev",
				Top:              0,
				Width:            1,
			},
		},
		UserAgent: "IcewormDebug/1.0",
	}

	// Marshal to JSON with indentation
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configFileName, configJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("Generated Iceworm config: %s", configFileName)
	return configFileName, nil
}

// cleanupConfigFile removes the generated config file
func cleanupConfigFile(configFile string) {
	if configFile != "" {
		if err := os.Remove(configFile); err != nil {
			log.Printf("Warning: failed to remove config file %s: %v", configFile, err)
		} else {
			log.Printf("Cleaned up config file: %s", configFile)
		}
	}
}

// enableCors sets the necessary headers for CORS
func enableCors(w http.ResponseWriter, r *http.Request, serverOrigin string) {
	origin := r.Header.Get("Origin")
	// Allow common local dev origins (both HTTP for dev and HTTPS for production)
	switch origin {
	case "http://127.0.0.1:5173", "http://localhost:5173", "http://[::1]:5173",
		serverOrigin, "https://localhost:" + serverOrigin[len("https://127.0.0.1:"):]:
		w.Header().Set("Access-Control-Allow-Origin", origin)
	default:
		// For same-origin requests (embedded frontend), allow the request
		// This is more secure than allowing "*"
		if origin == "" {
			// Same-origin request (no Origin header)
			w.Header().Set("Access-Control-Allow-Origin", serverOrigin)
		}
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Timestamp, X-Signature")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// withCors wraps handlers to support CORS and preflight OPTIONS
func withCors(handler http.HandlerFunc, serverOrigin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(w, r, serverOrigin)
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
	// Get a free port from the OS
	port, err := getFreePort()
	if err != nil {
		log.Fatal("Failed to get free port:", err)
	}

	// Generate Iceworm config file
	configFile, err := generateIIWConfig(port)
	if err != nil {
		log.Fatal("Failed to generate IIW config:", err)
	}
	generatedConfigFile = configFile

	// Setup cleanup on exit
	defer cleanupConfigFile(generatedConfigFile)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal...")
		cleanupConfigFile(generatedConfigFile)
		os.Exit(0)
	}()

	serverOrigin := fmt.Sprintf("https://127.0.0.1:%d", port)
	serverAddr := fmt.Sprintf(":%d", port)

	log.Printf("Server starting on port %d", port)
	log.Printf("Server URL: %s", serverOrigin)
	log.Printf("Iceworm config: %s", configFile)

	// API routes
	http.HandleFunc("/api/get", withCors(handleGet, serverOrigin))
	http.HandleFunc("/api/post", withCors(handlePost, serverOrigin))
	http.HandleFunc("/api/ping", withCors(handlePing, serverOrigin))
	http.HandleFunc("/api/config", withCors(func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Success: true,
			Message: "Config information",
			Data: map[string]interface{}{
				"port":       port,
				"configFile": configFile,
				"serverUrl":  serverOrigin,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}, serverOrigin))

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

	log.Fatal(http.ListenAndServe(serverAddr, nil))
}
