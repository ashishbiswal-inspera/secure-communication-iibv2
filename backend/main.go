package main

import (
	constants "backend/pkg/const"
	"backend/pkg/encryption"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
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
	NoProxyServer      bool                    `json:"noProxyServer"`
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

const (
	contentTypeKey  = "Content-Type"
	jsonContentType = "application/json"
)

// Global variables
var generatedConfigFile string
var securityMgr *encryption.Manager

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

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Create config structure
	config := IIWConfig{
		AllowCapture:      false,
		AllowedUrlRegexps: []string{".*"},
		AllowedUrls: []string{
			serverURL,
			constants.DEFAULT_VITE_URL,
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
		NoProxyServer:      true,
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

// launchIceworm starts the Iceworm browser with the generated config file
// Returns the command object so the caller can monitor the process
func launchIceworm(configFile string) (*exec.Cmd, error) {
	icewormPath := filepath.Join("..", "Inspera Browser", "iceworm.exe")

	// Check if iceworm.exe exists
	if _, err := os.Stat(icewormPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("iceworm.exe not found at %s", icewormPath)
	}

	// Get absolute path for config file
	absConfigPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for config: %w", err)
	}

	log.Printf("Launching Iceworm browser...")
	log.Printf("Iceworm path: %s", icewormPath)
	log.Printf("Config file: %s", absConfigPath)

	// Launch Iceworm with the config file
	cmd := exec.Command(icewormPath, absConfigPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to launch Iceworm: %w", err)
	}

	log.Printf("Iceworm browser launched with PID: %d", cmd.Process.Pid)
	return cmd, nil
}

// watchIcewormProcess monitors the Iceworm process and exits when it closes
func watchIcewormProcess(cmd *exec.Cmd, configFile string) {
	// Wait for the Iceworm process to exit
	err := cmd.Wait()

	if err != nil {
		log.Printf("Iceworm process exited with error: %v", err)
	} else {
		log.Printf("Iceworm process closed (PID: %d)", cmd.Process.Pid)
	}

	// Cleanup config file
	cleanupConfigFile(configFile)

	// Exit the backend
	log.Println("Shutting down backend server...")
	os.Exit(0)
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

	w.Header().Set(contentTypeKey, jsonContentType)
	json.NewEncoder(w).Encode(response)
}

// handlePost is a POST endpoint that receives and responds with JSON
func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response := Response{
			Success: false,
			Message: "Method not allowed",
		}
		w.Header().Set(contentTypeKey, jsonContentType)
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
		w.Header().Set(contentTypeKey, jsonContentType)
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

	w.Header().Set(contentTypeKey, jsonContentType)
	json.NewEncoder(w).Encode(response)
}

// handlePing is a simple ping endpoint to check server health
func handlePing(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "pong pong",
	}

	w.Header().Set(contentTypeKey, jsonContentType)
	json.NewEncoder(w).Encode(response)
}

// SecureContext holds decrypted request data passed to secure handlers
type SecureContext struct {
	Payload   interface{}
	Nonce     string
	Timestamp int64
}

// SecureHandler is a handler function that receives decrypted payload and returns response
type SecureHandler func(ctx *SecureContext) (interface{}, error)

// withSecure is a decorator/middleware that wraps any handler with encryption/decryption
// It handles: decryption, nonce validation, timestamp check, and response encryption
func withSecure(handler SecureHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Decode encrypted payload from request body
		var encryptedPayload encryption.EncryptedPayload
		if err := json.NewDecoder(r.Body).Decode(&encryptedPayload); err != nil {
			log.Printf("Failed to decode encrypted payload: %v", err)
			sendSecureError(w, "Invalid encrypted payload", http.StatusBadRequest)
			return
		}

		// Decrypt payload
		plaintext, err := securityMgr.Decrypt(&encryptedPayload)
		if err != nil {
			log.Printf("Decryption failed: %v", err)
			sendSecureError(w, "Decryption failed", http.StatusUnauthorized)
			return
		}

		// Decode secure request (with timestamp and nonce)
		var secureReq encryption.SecureRequest
		if err := json.Unmarshal(plaintext, &secureReq); err != nil {
			log.Printf("Failed to unmarshal secure request: %v", err)
			sendSecureError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Validate timestamp and check for replay attacks
		if err := securityMgr.ValidateAndTrackNonce(&secureReq); err != nil {
			log.Printf("Security validation failed: %v", err)
			sendSecureError(w, "Security validation failed", http.StatusForbidden)
			return
		}

		log.Printf("Secure request received (nonce: %s, timestamp: %d)", secureReq.Nonce, secureReq.Timestamp)

		// Create secure context for the handler
		ctx := &SecureContext{
			Payload:   secureReq.Payload,
			Nonce:     secureReq.Nonce,
			Timestamp: secureReq.Timestamp,
		}

		// Call the actual handler
		response, err := handler(ctx)
		if err != nil {
			log.Printf("Handler error: %v", err)
			sendSecureError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Encrypt response
		responseBytes, _ := json.Marshal(response)
		encryptedResponse, err := securityMgr.Encrypt(responseBytes)
		if err != nil {
			log.Printf("Failed to encrypt response: %v", err)
			sendSecureError(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set(contentTypeKey, jsonContentType)
		json.NewEncoder(w).Encode(encryptedResponse)
	}
}

// sendSecureError sends an encrypted error response
func sendSecureError(w http.ResponseWriter, message string, statusCode int) {
	response := Response{
		Success: false,
		Message: message,
	}

	// Try to encrypt the error response
	responseBytes, _ := json.Marshal(response)
	encryptedResponse, err := securityMgr.Encrypt(responseBytes)
	if err != nil {
		// If encryption fails, send plain error
		http.Error(w, message, statusCode)
		return
	}

	w.Header().Set(contentTypeKey, jsonContentType)
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(encryptedResponse)
}

// Helper to decode payload into a specific type
func decodePayload[T any](ctx *SecureContext) (T, error) {
	var result T
	payloadBytes, err := json.Marshal(ctx.Payload)
	if err != nil {
		return result, fmt.Errorf("failed to marshal payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &result); err != nil {
		return result, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return result, nil
}

// ============ Secure Handlers (use with withSecure decorator) ============

// secureGetHandler - secure version of GET
func secureGetHandler(ctx *SecureContext) (interface{}, error) {
	return Response{
		Success: true,
		Message: "Secure GET request successful",
		Data: map[string]interface{}{
			"timestamp": "2025-11-05",
			"status":    "running",
			"secure":    true,
		},
	}, nil
}

// securePostHandler - secure version of POST
func securePostHandler(ctx *SecureContext) (interface{}, error) {
	requestData, err := decodePayload[RequestData](ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid payload format: %w", err)
	}

	log.Printf("Secure POST data: %+v", requestData)

	return Response{
		Success: true,
		Message: "Secure data received successfully",
		Data:    requestData,
	}, nil
}

func main() {
	// Initialize security manager with pre-shared key
	var err error
	securityMgr, err = encryption.NewManagerWithKey(constants.GetEncryptionKey())
	if err != nil {
		log.Fatal("Failed to initialize security manager:", err)
	}
	log.Printf("Security initialized with AES-256-GCM encryption (pre-shared key)")

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

	serverOrigin := fmt.Sprintf("http://127.0.0.1:%d", port)
	serverAddr := fmt.Sprintf(":%d", port)

	log.Printf("Server starting on port %d", port)
	log.Printf("Server URL: %s", serverOrigin)
	log.Printf("Iceworm config: %s", configFile)

	// Create chi router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	// CORS middleware
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{serverOrigin, constants.DEFAULT_VITE_URL, "http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", contentTypeKey, "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/get", handleGet)
		r.Post("/post", handlePost)
		r.Get("/ping", handlePing)

		r.Get("/config", func(w http.ResponseWriter, r *http.Request) {
			response := Response{
				Success: true,
				Message: "Config information",
				Data: map[string]interface{}{
					"port":       port,
					"configFile": configFile,
					"serverUrl":  serverOrigin,
				},
			}
			w.Header().Set(contentTypeKey, jsonContentType)
			json.NewEncoder(w).Encode(response)
		})

		// Secure endpoints using withSecure decorator
		// All secure endpoints use POST method since encrypted requests need a body
		r.Post("/secure/post", withSecure(securePostHandler))
		r.Post("/secure/get", withSecure(secureGetHandler))
	})

	// Serve embedded frontend files
	distFSStripped, err := fs.Sub(distFS, "dist")
	if err != nil {
		log.Fatal("Failed to access embedded dist folder:", err)
	}

	// Static file server for React app
	fileServer := http.FileServer(http.FS(distFSStripped))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to open the file
		if _, err := distFSStripped.Open(path); err != nil {
			// If file not found, serve index.html for client-side routing
			req.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, req)
	})

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on %s with Chi router", serverAddr)
		if err := http.ListenAndServe(serverAddr, r); err != nil {
			log.Fatal("Server failed:", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(500 * time.Millisecond)

	// Launch Iceworm browser
	icewormCmd, err := launchIceworm(configFile)
	if err != nil {
		log.Printf("Warning: Failed to launch Iceworm: %v", err)
		log.Printf("Server is still running. You can manually launch Iceworm with: %s", configFile)
		// Block forever since Iceworm didn't launch
		select {}
	}

	// Watch Iceworm process - will exit backend when Iceworm closes
	log.Println("Monitoring Iceworm process...")
	watchIcewormProcess(icewormCmd, configFile)
}
