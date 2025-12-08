package constants

import "os"

const DEFAULT_VITE_URL = "http://localhost:5173"

// Pre-shared encryption key (32 bytes = 256 bits for AES-256)
// In production, this should be set via environment variable
// Default key for development (DO NOT use in production!)
const DEFAULT_ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// GetEncryptionKey returns the encryption key from environment or default
func GetEncryptionKey() string {
	if key := os.Getenv("IIW_ENCRYPTION_KEY"); key != "" {
		return key
	}
	return DEFAULT_ENCRYPTION_KEY
}
