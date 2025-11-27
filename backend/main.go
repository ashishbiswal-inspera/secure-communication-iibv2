package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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

// EncryptedPayload represents an encrypted request/response
type EncryptedPayload struct {
	Ciphertext string `json:"ciphertext"` // Base64 encoded
	Nonce      string `json:"nonce"`      // Base64 encoded GCM nonce
}

// SecureRequest represents decrypted request with timestamp and nonce for replay protection
type SecureRequest struct {
	Timestamp int64       `json:"timestamp"` // Unix timestamp in milliseconds
	Nonce     string      `json:"nonce"`     // Unique request identifier
	Payload   interface{} `json:"payload"`   // Actual request data
}

// SecurityManager handles encryption keys and nonce tracking
type SecurityManager struct {
	aesKey       []byte
	gcm          cipher.AEAD
	seenNonces   map[string]time.Time
	nonceMutex   sync.RWMutex
	nonceTimeout time.Duration
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

// Global variables
var generatedConfigFile string
var securityMgr *SecurityManager

// NewSecurityManager creates a new security manager with AES-GCM encryption
func NewSecurityManager() (*SecurityManager, error) {
	// Generate random 32-byte AES-256 key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	sm := &SecurityManager{
		aesKey:       key,
		gcm:          gcm,
		seenNonces:   make(map[string]time.Time),
		nonceTimeout: 5 * time.Second,
	}

	// Start nonce cleanup goroutine
	go sm.cleanupExpiredNonces()

	return sm, nil
}

// GetKeyHex returns the AES key as hex string for passing to frontend
func (sm *SecurityManager) GetKeyHex() string {
	return hex.EncodeToString(sm.aesKey)
}

// Encrypt encrypts data using AES-GCM
func (sm *SecurityManager) Encrypt(plaintext []byte) (*EncryptedPayload, error) {
	// Generate random nonce
	nonce := make([]byte, sm.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := sm.gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedPayload{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// Decrypt decrypts data using AES-GCM
func (sm *SecurityManager) Decrypt(payload *EncryptedPayload) ([]byte, error) {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt
	plaintext, err := sm.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ValidateAndTrackNonce checks timestamp and prevents replay attacks
func (sm *SecurityManager) ValidateAndTrackNonce(secureReq *SecureRequest) error {
	// Check timestamp (within 5 seconds)
	now := time.Now().UnixMilli()
	timeDiff := now - secureReq.Timestamp
	if timeDiff < 0 || timeDiff > 5000 {
		return fmt.Errorf("request timestamp expired or invalid (diff: %dms)", timeDiff)
	}

	// Check if nonce was already used
	sm.nonceMutex.Lock()
	defer sm.nonceMutex.Unlock()

	if _, exists := sm.seenNonces[secureReq.Nonce]; exists {
		return fmt.Errorf("nonce already used (replay attack detected)")
	}

	// Track this nonce
	sm.seenNonces[secureReq.Nonce] = time.Now()
	return nil
}

// cleanupExpiredNonces periodically removes old nonces to prevent memory leak
func (sm *SecurityManager) cleanupExpiredNonces() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sm.nonceMutex.Lock()
		cutoff := time.Now().Add(-sm.nonceTimeout)
		for nonce, timestamp := range sm.seenNonces {
			if timestamp.Before(cutoff) {
				delete(sm.seenNonces, nonce)
			}
		}
		sm.nonceMutex.Unlock()
	}
}

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

// handleSecurePost handles encrypted POST requests with replay protection
func handleSecurePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode encrypted payload
	var encryptedPayload EncryptedPayload
	if err := json.NewDecoder(r.Body).Decode(&encryptedPayload); err != nil {
		log.Printf("Failed to decode encrypted payload: %v", err)
		http.Error(w, "Invalid encrypted payload", http.StatusBadRequest)
		return
	}

	// Decrypt payload
	plaintext, err := securityMgr.Decrypt(&encryptedPayload)
	if err != nil {
		log.Printf("Decryption failed: %v", err)
		http.Error(w, "Decryption failed", http.StatusUnauthorized)
		return
	}

	// Decode secure request (with timestamp and nonce)
	var secureReq SecureRequest
	if err := json.Unmarshal(plaintext, &secureReq); err != nil {
		log.Printf("Failed to unmarshal secure request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate timestamp and check for replay attacks
	if err := securityMgr.ValidateAndTrackNonce(&secureReq); err != nil {
		log.Printf("Security validation failed: %v", err)
		http.Error(w, "Security validation failed", http.StatusForbidden)
		return
	}

	// Extract actual payload
	var requestData RequestData
	payloadBytes, _ := json.Marshal(secureReq.Payload)
	if err := json.Unmarshal(payloadBytes, &requestData); err != nil {
		log.Printf("Failed to unmarshal payload: %v", err)
		http.Error(w, "Invalid payload format", http.StatusBadRequest)
		return
	}

	log.Printf("Secure request received: %+v (nonce: %s, timestamp: %d)", requestData, secureReq.Nonce, secureReq.Timestamp)

	// Process request
	response := Response{
		Success: true,
		Message: "Secure data received successfully",
		Data:    requestData,
	}

	// Encrypt response
	responseBytes, _ := json.Marshal(response)
	encryptedResponse, err := securityMgr.Encrypt(responseBytes)
	if err != nil {
		log.Printf("Failed to encrypt response: %v", err)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(encryptedResponse)
}

func main() {
	// Initialize security manager with AES-GCM encryption
	var err error
	securityMgr, err = NewSecurityManager()
	if err != nil {
		log.Fatal("Failed to initialize security manager:", err)
	}
	log.Printf("Security initialized with AES-256-GCM encryption")
	log.Printf("Encryption key (hex): %s", securityMgr.GetKeyHex())

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

	// Security key endpoint - provides encryption key to frontend
	http.HandleFunc("/api/security/key", withCors(func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Success: true,
			Message: "Encryption key",
			Data: map[string]interface{}{
				"key": securityMgr.GetKeyHex(),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}, serverOrigin))

	// Secure POST endpoint with encryption and replay protection
	http.HandleFunc("/api/secure/post", withCors(handleSecurePost, serverOrigin))

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

	// Start server in a goroutine
	go func() {
		log.Printf("Starting HTTP server on %s", serverAddr)
		if err := http.ListenAndServe(serverAddr, nil); err != nil {
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
