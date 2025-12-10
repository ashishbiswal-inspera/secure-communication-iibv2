package encryption

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ECDHManager handles ECDH key exchange using P-256 curve
type ECDHManager struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

// NewECDHManager creates a new ECDH manager with a generated P-256 keypair
func NewECDHManager() (*ECDHManager, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH keypair: %w", err)
	}

	return &ECDHManager{
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
	}, nil
}

// GetPublicKeyBase64 returns the public key as a base64-encoded string
func (e *ECDHManager) GetPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(e.publicKey.Bytes())
}

// ComputeSharedSecret computes the shared secret from the peer's public key
func (e *ECDHManager) ComputeSharedSecret(peerPublicKeyBase64 string) ([]byte, error) {
	// Decode peer's public key from base64
	peerPubBytes, err := base64.StdEncoding.DecodeString(peerPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer public key: %w", err)
	}

	// Parse public key
	curve := ecdh.P256()
	peerPublicKey, err := curve.NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedSecret, err := e.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	return sharedSecret, nil
}

// DeriveAESKey derives a 32-byte AES-256 key from the shared secret using HKDF-SHA256
func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	// Use HKDF with SHA-256 to derive the AES key
	// Info string helps bind the key to its purpose
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))

	aesKey := make([]byte, 32) // 256 bits for AES-256
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	return aesKey, nil
}
