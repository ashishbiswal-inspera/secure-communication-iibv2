// =============================================================================
// SECURITY BENCHMARKS - Backend (Go)
// =============================================================================
// This file contains comprehensive benchmarks for:
// 1. ECDH Key Generation & Exchange
// 2. AES-256-GCM Encryption/Decryption
// 3. End-to-End Request/Response cycles
//
// Run with: go test -bench=. -benchmem -run=^$ ./pkg/encryption/...
// =============================================================================

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// =============================================================================
// SECTION 1: TEST DATA STRUCTURES
// Complex nested objects matching your production data (depth 5)
// =============================================================================

// Address represents a location with nested coordinates (depth 2)
type BenchAddress struct {
	Street     string            `json:"street"`
	City       string            `json:"city"`
	Country    string            `json:"country"`
	PostalCode string            `json:"postalCode"`
	Coords     *BenchCoordinates `json:"coords,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Coordinates with extra nested data (depth 3)
type BenchCoordinates struct {
	Lat      float64                `json:"lat"`
	Lng      float64                `json:"lng"`
	Altitude float64                `json:"altitude"`
	Accuracy float64                `json:"accuracy"`
	Extra    *BenchCoordinatesExtra `json:"extra,omitempty"`
}

// CoordinatesExtra with region (depth 4)
type BenchCoordinatesExtra struct {
	Timezone    string       `json:"timezone"`
	UTCOffset   int          `json:"utcOffset"`
	DaylightSav bool         `json:"daylightSav"`
	Region      *BenchRegion `json:"region,omitempty"`
}

// Region with parent region (depth 5)
type BenchRegion struct {
	Name     string       `json:"name"`
	Code     string       `json:"code"`
	SubCodes []string     `json:"subCodes"`
	Parent   *BenchRegion `json:"parent,omitempty"` // Depth 5
}

// ComplexItem represents your production response object with 20 properties
type BenchComplexItem struct {
	ID             int64                   `json:"id"`
	UUID           string                  `json:"uuid"`
	Name           string                  `json:"name"`
	Description    string                  `json:"description"`
	Price          float64                 `json:"price"`
	Quantity       int                     `json:"quantity"`
	IsActive       bool                    `json:"isActive"`
	CreatedAt      time.Time               `json:"createdAt"`
	UpdatedAt      time.Time               `json:"updatedAt"`
	Tags           []string                `json:"tags"`
	Ratings        []float64               `json:"ratings"`
	Address        *BenchAddress           `json:"address"`
	Attributes     map[string]interface{}  `json:"attributes"`
	RelatedIDs     []int64                 `json:"relatedIds"`
	Score          float32                 `json:"score"`
	Priority       int8                    `json:"priority"`
	Flags          uint64                  `json:"flags"`
	RawData        []byte                  `json:"rawData"`
	NullableField  *string                 `json:"nullableField"`
	NestedMetadata map[string]*BenchRegion `json:"nestedMetadata"`
}

// =============================================================================
// SECTION 2: TEST DATA GENERATORS
// =============================================================================

// generateBenchComplexItem creates a single complex item with depth 5 nesting
func generateBenchComplexItem(index int) BenchComplexItem {
	nullable := fmt.Sprintf("nullable_%d", index)
	return BenchComplexItem{
		ID:          int64(index),
		UUID:        fmt.Sprintf("uuid-%d-abcd-efgh-ijkl-%d", index, index*1000),
		Name:        fmt.Sprintf("Item Name %d with some extra text", index),
		Description: fmt.Sprintf("This is a detailed description for item %d that contains multiple sentences and various information about the product.", index),
		Price:       float64(index) * 19.99,
		Quantity:    index * 10,
		IsActive:    index%2 == 0,
		CreatedAt:   time.Now().Add(-time.Hour * time.Duration(index)),
		UpdatedAt:   time.Now(),
		Tags:        []string{"tag1", "tag2", "tag3", fmt.Sprintf("custom_%d", index)},
		Ratings:     []float64{4.5, 3.8, 4.9, 5.0, 4.2},
		Address: &BenchAddress{
			Street:     fmt.Sprintf("%d Main Street", index*100),
			City:       "Test City",
			Country:    "Test Country",
			PostalCode: fmt.Sprintf("%05d", index),
			Coords: &BenchCoordinates{
				Lat:      40.7128 + float64(index)*0.001,
				Lng:      -74.0060 + float64(index)*0.001,
				Altitude: 10.5,
				Accuracy: 5.0,
				Extra: &BenchCoordinatesExtra{
					Timezone:    "America/New_York",
					UTCOffset:   -5,
					DaylightSav: true,
					Region: &BenchRegion{
						Name:     "Northeast",
						Code:     "NE",
						SubCodes: []string{"NY", "NJ", "CT"},
						Parent: &BenchRegion{ // Depth 5
							Name:     "United States",
							Code:     "US",
							SubCodes: []string{"NE", "SE", "MW", "SW", "W"},
							Parent:   nil,
						},
					},
				},
			},
			Metadata: map[string]string{
				"verified": "true",
				"source":   "api",
			},
		},
		Attributes: map[string]interface{}{
			"color":    "blue",
			"size":     "large",
			"weight":   2.5,
			"inStock":  true,
			"variants": []string{"A", "B", "C"},
		},
		RelatedIDs:    []int64{int64(index + 1), int64(index + 2), int64(index + 3)},
		Score:         float32(index) * 0.85,
		Priority:      int8(index % 10),
		Flags:         uint64(index * 12345),
		RawData:       []byte(fmt.Sprintf("raw_data_%d", index)),
		NullableField: &nullable,
		NestedMetadata: map[string]*BenchRegion{
			"primary": {
				Name:     "Primary Region",
				Code:     "PR",
				SubCodes: []string{"P1", "P2"},
			},
		},
	}
}

// generateBenchComplexResponse creates an array of complex items
func generateBenchComplexResponse(count int) []BenchComplexItem {
	items := make([]BenchComplexItem, count)
	for i := 0; i < count; i++ {
		items[i] = generateBenchComplexItem(i)
	}
	return items
}

// =============================================================================
// SECTION 3: KEY GENERATION BENCHMARKS
// Measures: CPU time, memory allocations
// =============================================================================

// BenchmarkECDHKeyGeneration measures P-256 keypair generation
// Label: KEY-GEN-001
func BenchmarkECDHKeyGeneration(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		curve := ecdh.P256()
		_, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkECDHKeyExchange measures shared secret computation
// Label: KEY-GEN-002
func BenchmarkECDHKeyExchange(b *testing.B) {
	// Setup: Generate two keypairs (client and server)
	curve := ecdh.P256()
	clientPrivate, _ := curve.GenerateKey(rand.Reader)
	serverPrivate, _ := curve.GenerateKey(rand.Reader)
	serverPublic := serverPrivate.PublicKey()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := clientPrivate.ECDH(serverPublic)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHKDFKeyDerivation measures AES key derivation from shared secret
// Label: KEY-GEN-003
func BenchmarkHKDFKeyDerivation(b *testing.B) {
	// Setup: Generate shared secret
	curve := ecdh.P256()
	clientPrivate, _ := curve.GenerateKey(rand.Reader)
	serverPrivate, _ := curve.GenerateKey(rand.Reader)
	sharedSecret, _ := clientPrivate.ECDH(serverPrivate.PublicKey())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
		aesKey := make([]byte, 32)
		io.ReadFull(hkdfReader, aesKey)
	}
}

// BenchmarkFullKeyExchange measures complete key exchange flow
// Label: KEY-GEN-004
func BenchmarkFullKeyExchange(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 1. Both sides generate keypairs
		curve := ecdh.P256()
		clientPrivate, _ := curve.GenerateKey(rand.Reader)
		serverPrivate, _ := curve.GenerateKey(rand.Reader)

		// 2. Exchange public keys and compute shared secret
		sharedSecret, _ := clientPrivate.ECDH(serverPrivate.PublicKey())

		// 3. Derive AES key
		hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
		aesKey := make([]byte, 32)
		io.ReadFull(hkdfReader, aesKey)
	}
}

// =============================================================================
// SECTION 4: ENCRYPTION BENCHMARKS
// Measures: CPU time, memory allocations, throughput
// =============================================================================

// BenchmarkAESGCMEncryption measures encryption at various data sizes
// Label: ENC-001
func BenchmarkAESGCMEncryption(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4096},
		{"16KB", 16384},
		{"64KB", 65536},
		{"256KB", 262144},
	}

	for _, s := range sizes {
		b.Run(s.name, func(b *testing.B) {
			// Setup
			key := make([]byte, 32)
			rand.Read(key)
			plaintext := make([]byte, s.size)
			rand.Read(plaintext)

			block, _ := aes.NewCipher(key)
			gcm, _ := cipher.NewGCM(block)
			nonce := make([]byte, gcm.NonceSize())

			b.ReportAllocs()
			b.SetBytes(int64(s.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				rand.Read(nonce)
				_ = gcm.Seal(nil, nonce, plaintext, nil)
			}
		})
	}
}

// BenchmarkAESGCMDecryption measures decryption at various data sizes
// Label: ENC-002
func BenchmarkAESGCMDecryption(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"256B", 256},
		{"1KB", 1024},
		{"4KB", 4096},
		{"16KB", 16384},
		{"64KB", 65536},
	}

	for _, s := range sizes {
		b.Run(s.name, func(b *testing.B) {
			// Setup
			key := make([]byte, 32)
			rand.Read(key)
			plaintext := make([]byte, s.size)
			rand.Read(plaintext)

			block, _ := aes.NewCipher(key)
			gcm, _ := cipher.NewGCM(block)
			nonce := make([]byte, gcm.NonceSize())
			rand.Read(nonce)
			ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

			b.ReportAllocs()
			b.SetBytes(int64(s.size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := gcm.Open(nil, nonce, ciphertext, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncryptionOverhead measures size increase due to encryption
// Label: ENC-003
func BenchmarkEncryptionOverhead(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	// Test with realistic JSON data sizes
	itemCounts := []int{1, 5, 10, 20}

	for _, count := range itemCounts {
		b.Run(fmt.Sprintf("%d_items", count), func(b *testing.B) {
			data := generateBenchComplexResponse(count)
			jsonData, _ := json.Marshal(data)
			originalSize := len(jsonData)

			nonce := make([]byte, gcm.NonceSize())

			b.ReportAllocs()
			b.ResetTimer()

			var encryptedSize int
			for i := 0; i < b.N; i++ {
				rand.Read(nonce)
				encrypted := gcm.Seal(nil, nonce, jsonData, nil)
				encryptedSize = len(encrypted)
			}

			// Report custom metrics
			b.ReportMetric(float64(originalSize), "original_bytes")
			b.ReportMetric(float64(encryptedSize), "encrypted_bytes")
			overhead := float64(encryptedSize-originalSize) / float64(originalSize) * 100
			b.ReportMetric(overhead, "overhead_%")
		})
	}
}

// =============================================================================
// SECTION 5: JSON SERIALIZATION BENCHMARKS
// Measures: Serialization/Deserialization performance for complex objects
// =============================================================================

// BenchmarkJSONMarshal measures JSON serialization
// Label: JSON-001
func BenchmarkJSONMarshal(b *testing.B) {
	itemCounts := []int{1, 5, 10, 20, 50}

	for _, count := range itemCounts {
		b.Run(fmt.Sprintf("%d_items_depth5", count), func(b *testing.B) {
			data := generateBenchComplexResponse(count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := json.Marshal(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONUnmarshal measures JSON deserialization
// Label: JSON-002
func BenchmarkJSONUnmarshal(b *testing.B) {
	itemCounts := []int{1, 5, 10, 20, 50}

	for _, count := range itemCounts {
		b.Run(fmt.Sprintf("%d_items_depth5", count), func(b *testing.B) {
			data := generateBenchComplexResponse(count)
			jsonData, _ := json.Marshal(data)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var result []BenchComplexItem
				err := json.Unmarshal(jsonData, &result)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// =============================================================================
// SECTION 6: END-TO-END BENCHMARKS
// Measures: Complete request/response cycle including encryption
// =============================================================================

// BenchmarkEndToEndSecureRequest measures full secure request cycle
// Label: E2E-001
func BenchmarkEndToEndSecureRequest(b *testing.B) {
	// Setup: Perform key exchange once
	curve := ecdh.P256()
	clientPrivate, _ := curve.GenerateKey(rand.Reader)
	serverPrivate, _ := curve.GenerateKey(rand.Reader)
	sharedSecret, _ := clientPrivate.ECDH(serverPrivate.PublicKey())

	// Derive AES key
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
	aesKey := make([]byte, 32)
	io.ReadFull(hkdfReader, aesKey)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	itemCounts := []int{1, 10, 20}

	for _, count := range itemCounts {
		b.Run(fmt.Sprintf("%d_items_depth5", count), func(b *testing.B) {
			requestData := generateBenchComplexResponse(count)
			nonce := make([]byte, gcm.NonceSize())

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// 1. CLIENT: Serialize request
				jsonData, _ := json.Marshal(requestData)

				// 2. CLIENT: Encrypt request
				rand.Read(nonce)
				encrypted := gcm.Seal(nil, nonce, jsonData, nil)

				// 3. NETWORK: Transmit (simulated - just use the data)
				_ = len(encrypted)

				// 4. SERVER: Decrypt request
				decrypted, _ := gcm.Open(nil, nonce, encrypted, nil)

				// 5. SERVER: Deserialize request
				var receivedData []BenchComplexItem
				json.Unmarshal(decrypted, &receivedData)

				// 6. SERVER: Process and serialize response
				responseJSON, _ := json.Marshal(receivedData)

				// 7. SERVER: Encrypt response
				rand.Read(nonce)
				encryptedResponse := gcm.Seal(nil, nonce, responseJSON, nil)

				// 8. NETWORK: Transmit response (simulated)
				_ = len(encryptedResponse)

				// 9. CLIENT: Decrypt response
				decryptedResponse, _ := gcm.Open(nil, nonce, encryptedResponse, nil)

				// 10. CLIENT: Deserialize response
				var finalResponse []BenchComplexItem
				json.Unmarshal(decryptedResponse, &finalResponse)
			}
		})
	}
}

// BenchmarkEndToEndWithKeyExchange measures E2E including key exchange
// Label: E2E-002
func BenchmarkEndToEndWithKeyExchange(b *testing.B) {
	itemCounts := []int{1, 10, 20}

	for _, count := range itemCounts {
		b.Run(fmt.Sprintf("%d_items_depth5", count), func(b *testing.B) {
			requestData := generateBenchComplexResponse(count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// === KEY EXCHANGE PHASE ===
				curve := ecdh.P256()
				clientPrivate, _ := curve.GenerateKey(rand.Reader)
				serverPrivate, _ := curve.GenerateKey(rand.Reader)
				sharedSecret, _ := clientPrivate.ECDH(serverPrivate.PublicKey())

				hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
				aesKey := make([]byte, 32)
				io.ReadFull(hkdfReader, aesKey)

				block, _ := aes.NewCipher(aesKey)
				gcm, _ := cipher.NewGCM(block)
				nonce := make([]byte, gcm.NonceSize())

				// === REQUEST/RESPONSE PHASE ===
				// Serialize
				jsonData, _ := json.Marshal(requestData)

				// Encrypt
				rand.Read(nonce)
				encrypted := gcm.Seal(nil, nonce, jsonData, nil)

				// Decrypt
				decrypted, _ := gcm.Open(nil, nonce, encrypted, nil)

				// Deserialize
				var result []BenchComplexItem
				json.Unmarshal(decrypted, &result)
			}
		})
	}
}

// =============================================================================
// SECTION 7: MEMORY PROFILING HELPERS
// =============================================================================

// BenchmarkMemoryAllocation tracks memory for various operations
// Label: MEM-001
func BenchmarkMemoryAllocation(b *testing.B) {
	b.Run("ECDH_KeyPair", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			curve := ecdh.P256()
			curve.GenerateKey(rand.Reader)
		}
	})

	b.Run("AES_GCM_Setup", func(b *testing.B) {
		key := make([]byte, 32)
		rand.Read(key)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			block, _ := aes.NewCipher(key)
			cipher.NewGCM(block)
		}
	})

	b.Run("ComplexItem_20_Marshal", func(b *testing.B) {
		data := generateBenchComplexResponse(20)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			json.Marshal(data)
		}
	})
}
