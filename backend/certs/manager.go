package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	appName        = "Iceworm"
	certSubDir     = "certs"
	caCertFile     = "ca-cert.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server-cert.pem"
	serverKeyFile  = "server-key.pem"
	clientCertFile = "client-cert.pem"
	clientKeyFile  = "client-key.pem"
)

// CertificateManager handles certificate generation and loading
type CertificateManager struct {
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	ServerCert *x509.Certificate
	ServerKey  *ecdsa.PrivateKey
	ClientCert *x509.Certificate
	ClientKey  *ecdsa.PrivateKey
	CertDir    string
}

// getUserAppDataDir returns the OS-specific user application data directory
func getUserAppDataDir() (string, error) {
	var baseDir string
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: %APPDATA%\Iceworm
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		baseDir = filepath.Join(appData, appName)
	case "darwin":
		// macOS: ~/Library/Application Support/Iceworm
		baseDir = filepath.Join(homeDir, "Library", "Application Support", appName)
	default:
		// Linux: ~/.local/share/Iceworm
		xdgDataHome := os.Getenv("XDG_DATA_HOME")
		if xdgDataHome == "" {
			xdgDataHome = filepath.Join(homeDir, ".local", "share")
		}
		baseDir = filepath.Join(xdgDataHome, appName)
	}

	return baseDir, nil
}

// NewCertificateManager creates a new certificate manager with OS-specific storage
func NewCertificateManager() (*CertificateManager, error) {
	appDataDir, err := getUserAppDataDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get app data directory: %w", err)
	}

	certPath := filepath.Join(appDataDir, certSubDir)
	return &CertificateManager{
		CertDir: certPath,
	}, nil
}

// EnsureCertificates checks if certificates exist, if not generates them
func (cm *CertificateManager) EnsureCertificates() error {
	// Create certs directory if it doesn't exist
	if err := os.MkdirAll(cm.CertDir, 0700); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	// Check if all certificates exist
	if cm.certificatesExist() {
		// Load existing certificates
		return cm.LoadCertificates()
	}

	// Generate new certificates
	return cm.GenerateAll()
}

// certificatesExist checks if all required certificate files exist
func (cm *CertificateManager) certificatesExist() bool {
	requiredFiles := []string{
		caCertFile, caKeyFile,
		serverCertFile, serverKeyFile,
		clientCertFile, clientKeyFile,
	}

	for _, file := range requiredFiles {
		path := filepath.Join(cm.CertDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// GenerateAll generates CA, server, and client certificates
func (cm *CertificateManager) GenerateAll() error {
	fmt.Println("Generating new certificates...")

	// 1. Generate CA certificate
	if err := cm.generateCA(); err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	fmt.Println("✓ CA certificate generated")

	// 2. Generate server certificate
	if err := cm.generateServerCert(); err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}
	fmt.Println("✓ Server certificate generated")

	// 3. Generate client certificate
	if err := cm.generateClientCert(); err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}
	fmt.Println("✓ Client certificate generated")

	fmt.Printf("\nCertificates stored in: %s\n", cm.CertDir)
	return nil
}

// generateCA generates a self-signed CA certificate
func (cm *CertificateManager) generateCA() error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Iceworm Desktop App"},
			CommonName:   "Iceworm Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	// Create self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	cm.CACert = cert
	cm.CAKey = privateKey

	// Save to files
	if err := cm.saveCertificate(caCertFile, certBytes); err != nil {
		return err
	}
	if err := cm.savePrivateKey(caKeyFile, privateKey); err != nil {
		return err
	}

	return nil
}

// generateServerCert generates a server certificate signed by the CA
func (cm *CertificateManager) generateServerCert() error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Iceworm Desktop App"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 0, 0), // 5 years
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", "127.0.0.1", "::1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Sign with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, cm.CACert, &privateKey.PublicKey, cm.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}

	cm.ServerCert = cert
	cm.ServerKey = privateKey

	// Save to files
	if err := cm.saveCertificate(serverCertFile, certBytes); err != nil {
		return err
	}
	if err := cm.savePrivateKey(serverKeyFile, privateKey); err != nil {
		return err
	}

	return nil
}

// generateClientCert generates a client certificate signed by the CA
func (cm *CertificateManager) generateClientCert() error {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create client certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Iceworm Desktop App"},
			CommonName:   "Iceworm Client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(5, 0, 0), // 5 years
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Sign with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, cm.CACert, &privateKey.PublicKey, cm.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	cm.ClientCert = cert
	cm.ClientKey = privateKey

	// Save to files
	if err := cm.saveCertificate(clientCertFile, certBytes); err != nil {
		return err
	}
	if err := cm.savePrivateKey(clientKeyFile, privateKey); err != nil {
		return err
	}

	return nil
}

// LoadCertificates loads existing certificates from disk
func (cm *CertificateManager) LoadCertificates() error {
	var err error

	// Load CA certificate and key
	cm.CACert, err = cm.loadCertificate(caCertFile)
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}
	cm.CAKey, err = cm.loadPrivateKey(caKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load CA private key: %w", err)
	}

	// Load server certificate and key
	cm.ServerCert, err = cm.loadCertificate(serverCertFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}
	cm.ServerKey, err = cm.loadPrivateKey(serverKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server private key: %w", err)
	}

	// Load client certificate and key
	cm.ClientCert, err = cm.loadCertificate(clientCertFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}
	cm.ClientKey, err = cm.loadPrivateKey(clientKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load client private key: %w", err)
	}

	fmt.Println("✓ Certificates loaded from disk")
	return nil
}

// saveCertificate saves a certificate to a PEM file
func (cm *CertificateManager) saveCertificate(filename string, certBytes []byte) error {
	path := filepath.Join(cm.CertDir, filename)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return os.WriteFile(path, certPEM, 0600)
}

// savePrivateKey saves a private key to a PEM file
func (cm *CertificateManager) savePrivateKey(filename string, key *ecdsa.PrivateKey) error {
	path := filepath.Join(cm.CertDir, filename)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	return os.WriteFile(path, keyPEM, 0600)
}

// loadCertificate loads a certificate from a PEM file
func (cm *CertificateManager) loadCertificate(filename string) (*x509.Certificate, error) {
	path := filepath.Join(cm.CertDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

// loadPrivateKey loads a private key from a PEM file
func (cm *CertificateManager) loadPrivateKey(filename string) (*ecdsa.PrivateKey, error) {
	path := filepath.Join(cm.CertDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// GetServerCertPath returns the path to the server certificate
func (cm *CertificateManager) GetServerCertPath() string {
	return filepath.Join(cm.CertDir, serverCertFile)
}

// GetServerKeyPath returns the path to the server private key
func (cm *CertificateManager) GetServerKeyPath() string {
	return filepath.Join(cm.CertDir, serverKeyFile)
}

// GetClientCertPath returns the path to the client certificate
func (cm *CertificateManager) GetClientCertPath() string {
	return filepath.Join(cm.CertDir, clientCertFile)
}

// GetClientKeyPath returns the path to the client private key
func (cm *CertificateManager) GetClientKeyPath() string {
	return filepath.Join(cm.CertDir, clientKeyFile)
}

// GetCACertPath returns the path to the CA certificate
func (cm *CertificateManager) GetCACertPath() string {
	return filepath.Join(cm.CertDir, caCertFile)
}

// GetCertPool returns a certificate pool containing the CA certificate
func (cm *CertificateManager) GetCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cm.CACert)
	return pool
}
