package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

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

// Manager handles encryption keys and nonce tracking
type Manager struct {
	aesKey       []byte
	gcm          cipher.AEAD
	seenNonces   map[string]time.Time
	nonceMutex   sync.RWMutex
	nonceTimeout time.Duration
}

// NewManager creates a new security manager with AES-GCM encryption using random key
func NewManager() (*Manager, error) {
	// Generate random 32-byte AES-256 key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return NewManagerWithKey(hex.EncodeToString(key))
}

// NewManagerWithKey creates a security manager with a pre-shared key (hex encoded)
func NewManagerWithKey(keyHex string) (*Manager, error) {
	// Decode hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(key))
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

	m := &Manager{
		aesKey:       key,
		gcm:          gcm,
		seenNonces:   make(map[string]time.Time),
		nonceTimeout: 5 * time.Second,
	}

	// Start nonce cleanup goroutine
	go m.cleanupExpiredNonces()

	return m, nil
}

// GetKeyHex returns the AES key as hex string for passing to frontend
func (m *Manager) GetKeyHex() string {
	return hex.EncodeToString(m.aesKey)
}

// Encrypt encrypts data using AES-GCM
func (m *Manager) Encrypt(plaintext []byte) (*EncryptedPayload, error) {
	// Generate random nonce
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := m.gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedPayload{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// Decrypt decrypts data using AES-GCM
func (m *Manager) Decrypt(payload *EncryptedPayload) ([]byte, error) {
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
	plaintext, err := m.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ValidateAndTrackNonce checks timestamp and prevents replay attacks
func (m *Manager) ValidateAndTrackNonce(secureReq *SecureRequest) error {
	// Check timestamp (within 5 seconds)
	now := time.Now().UnixMilli()
	timeDiff := now - secureReq.Timestamp
	if timeDiff < 0 || timeDiff > 5000 {
		return fmt.Errorf("request timestamp expired or invalid (diff: %dms)", timeDiff)
	}

	// Check if nonce was already used
	m.nonceMutex.Lock()
	defer m.nonceMutex.Unlock()

	if _, exists := m.seenNonces[secureReq.Nonce]; exists {
		return fmt.Errorf("nonce already used (replay attack detected)")
	}

	// Track this nonce
	m.seenNonces[secureReq.Nonce] = time.Now()
	return nil
}

// cleanupExpiredNonces periodically removes old nonces to prevent memory leak
func (m *Manager) cleanupExpiredNonces() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.nonceMutex.Lock()
		cutoff := time.Now().Add(-m.nonceTimeout)
		for nonce, timestamp := range m.seenNonces {
			if timestamp.Before(cutoff) {
				delete(m.seenNonces, nonce)
			}
		}
		m.nonceMutex.Unlock()
	}
}
