// =============================================================================
// SECURITY BENCHMARKS - Standalone Runner
// =============================================================================
// This is a standalone benchmark runner that outputs detailed results.
// Run with: go run benchmark_runner.go
// =============================================================================

//go:build ignore

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// =============================================================================
// DATA STRUCTURES (same as benchmark_test.go)
// =============================================================================

type Address struct {
	Street     string            `json:"street"`
	City       string            `json:"city"`
	Country    string            `json:"country"`
	PostalCode string            `json:"postalCode"`
	Coords     *Coordinates      `json:"coords,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type Coordinates struct {
	Lat      float64           `json:"lat"`
	Lng      float64           `json:"lng"`
	Altitude float64           `json:"altitude"`
	Accuracy float64           `json:"accuracy"`
	Extra    *CoordinatesExtra `json:"extra,omitempty"`
}

type CoordinatesExtra struct {
	Timezone    string  `json:"timezone"`
	UTCOffset   int     `json:"utcOffset"`
	DaylightSav bool    `json:"daylightSav"`
	Region      *Region `json:"region,omitempty"`
}

type Region struct {
	Name     string   `json:"name"`
	Code     string   `json:"code"`
	SubCodes []string `json:"subCodes"`
	Parent   *Region  `json:"parent,omitempty"`
}

type ComplexItem struct {
	ID             int64                  `json:"id"`
	UUID           string                 `json:"uuid"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Price          float64                `json:"price"`
	Quantity       int                    `json:"quantity"`
	IsActive       bool                   `json:"isActive"`
	CreatedAt      time.Time              `json:"createdAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
	Tags           []string               `json:"tags"`
	Ratings        []float64              `json:"ratings"`
	Address        *Address               `json:"address"`
	Attributes     map[string]interface{} `json:"attributes"`
	RelatedIDs     []int64                `json:"relatedIds"`
	Score          float32                `json:"score"`
	Priority       int8                   `json:"priority"`
	Flags          uint64                 `json:"flags"`
	RawData        []byte                 `json:"rawData"`
	NullableField  *string                `json:"nullableField"`
	NestedMetadata map[string]*Region     `json:"nestedMetadata"`
}

func generateComplexItem(index int) ComplexItem {
	nullable := fmt.Sprintf("nullable_%d", index)
	return ComplexItem{
		ID:          int64(index),
		UUID:        fmt.Sprintf("uuid-%d-abcd-efgh-ijkl-%d", index, index*1000),
		Name:        fmt.Sprintf("Item Name %d with some extra text", index),
		Description: fmt.Sprintf("This is a detailed description for item %d.", index),
		Price:       float64(index) * 19.99,
		Quantity:    index * 10,
		IsActive:    index%2 == 0,
		CreatedAt:   time.Now().Add(-time.Hour * time.Duration(index)),
		UpdatedAt:   time.Now(),
		Tags:        []string{"tag1", "tag2", "tag3", fmt.Sprintf("custom_%d", index)},
		Ratings:     []float64{4.5, 3.8, 4.9, 5.0, 4.2},
		Address: &Address{
			Street:     fmt.Sprintf("%d Main Street", index*100),
			City:       "Test City",
			Country:    "Test Country",
			PostalCode: fmt.Sprintf("%05d", index),
			Coords: &Coordinates{
				Lat:      40.7128 + float64(index)*0.001,
				Lng:      -74.0060 + float64(index)*0.001,
				Altitude: 10.5,
				Accuracy: 5.0,
				Extra: &CoordinatesExtra{
					Timezone:    "America/New_York",
					UTCOffset:   -5,
					DaylightSav: true,
					Region: &Region{
						Name:     "Northeast",
						Code:     "NE",
						SubCodes: []string{"NY", "NJ", "CT"},
						Parent: &Region{
							Name:     "United States",
							Code:     "US",
							SubCodes: []string{"NE", "SE", "MW", "SW", "W"},
						},
					},
				},
			},
			Metadata: map[string]string{"verified": "true", "source": "api"},
		},
		Attributes: map[string]interface{}{
			"color": "blue", "size": "large", "weight": 2.5,
		},
		RelatedIDs:    []int64{int64(index + 1), int64(index + 2)},
		Score:         float32(index) * 0.85,
		Priority:      int8(index % 10),
		Flags:         uint64(index * 12345),
		RawData:       []byte(fmt.Sprintf("raw_%d", index)),
		NullableField: &nullable,
		NestedMetadata: map[string]*Region{
			"primary": {Name: "Primary", Code: "PR", SubCodes: []string{"P1"}},
		},
	}
}

func generateComplexResponse(count int) []ComplexItem {
	items := make([]ComplexItem, count)
	for i := 0; i < count; i++ {
		items[i] = generateComplexItem(i)
	}
	return items
}

// =============================================================================
// BENCHMARK UTILITIES
// =============================================================================

type BenchResult struct {
	Name       string
	Iterations int
	AvgTime    time.Duration
	MinTime    time.Duration
	MaxTime    time.Duration
	MemAlloc   uint64
	SizeBefore int
	SizeAfter  int
}

func measureMemory() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

func runBench(name string, iterations int, fn func()) BenchResult {
	runtime.GC()
	startMem := measureMemory()

	var minTime, maxTime time.Duration
	minTime = time.Hour

	start := time.Now()
	for i := 0; i < iterations; i++ {
		iterStart := time.Now()
		fn()
		elapsed := time.Since(iterStart)
		if elapsed < minTime {
			minTime = elapsed
		}
		if elapsed > maxTime {
			maxTime = elapsed
		}
	}
	totalTime := time.Since(start)

	endMem := measureMemory()

	return BenchResult{
		Name:       name,
		Iterations: iterations,
		AvgTime:    totalTime / time.Duration(iterations),
		MinTime:    minTime,
		MaxTime:    maxTime,
		MemAlloc:   (endMem - startMem) / uint64(iterations),
	}
}

func printResult(r BenchResult) {
	fmt.Printf("  %-45s | Avg: %12v | Min: %10v | Max: %10v | Mem: %8d B/op\n",
		r.Name, r.AvgTime, r.MinTime, r.MaxTime, r.MemAlloc)
}

func printSizeResult(r BenchResult) {
	overhead := float64(r.SizeAfter-r.SizeBefore) / float64(r.SizeBefore) * 100
	fmt.Printf("  %-45s | Avg: %12v | Size: %6d → %6d bytes (+%.1f%%)\n",
		r.Name, r.AvgTime, r.SizeBefore, r.SizeAfter, overhead)
}

// =============================================================================
// MAIN BENCHMARK RUNNER
// =============================================================================

func main() {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println("                        🔐 SECURITY BENCHMARKS - DETAILED REPORT")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Date: %s | Go Version: %s | OS: %s/%s\n",
		time.Now().Format("2006-01-02 15:04:05"), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Println(strings.Repeat("=", 100))

	// =========================================================================
	// SECTION 1: KEY GENERATION BENCHMARKS
	// =========================================================================
	fmt.Println("\n📊 SECTION 1: KEY GENERATION & EXCHANGE")
	fmt.Println(strings.Repeat("-", 100))

	// KEY-GEN-001: ECDH Key Generation
	r := runBench("KEY-GEN-001: ECDH P-256 KeyPair Generation", 1000, func() {
		curve := ecdh.P256()
		curve.GenerateKey(rand.Reader)
	})
	printResult(r)

	// KEY-GEN-002: ECDH Shared Secret
	curve := ecdh.P256()
	clientKey, _ := curve.GenerateKey(rand.Reader)
	serverKey, _ := curve.GenerateKey(rand.Reader)

	r = runBench("KEY-GEN-002: ECDH Shared Secret Computation", 1000, func() {
		clientKey.ECDH(serverKey.PublicKey())
	})
	printResult(r)

	// KEY-GEN-003: HKDF Key Derivation
	sharedSecret, _ := clientKey.ECDH(serverKey.PublicKey())
	r = runBench("KEY-GEN-003: HKDF-SHA256 Key Derivation", 10000, func() {
		hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
		aesKey := make([]byte, 32)
		io.ReadFull(hkdfReader, aesKey)
	})
	printResult(r)

	// KEY-GEN-004: Full Key Exchange
	r = runBench("KEY-GEN-004: Full ECDH Key Exchange Flow", 500, func() {
		c := ecdh.P256()
		ck, _ := c.GenerateKey(rand.Reader)
		sk, _ := c.GenerateKey(rand.Reader)
		ss, _ := ck.ECDH(sk.PublicKey())
		hr := hkdf.New(sha256.New, ss, nil, []byte("ecdh-aes-key"))
		ak := make([]byte, 32)
		io.ReadFull(hr, ak)
	})
	printResult(r)

	// =========================================================================
	// SECTION 2: ENCRYPTION BENCHMARKS
	// =========================================================================
	fmt.Println("\n📊 SECTION 2: AES-256-GCM ENCRYPTION")
	fmt.Println(strings.Repeat("-", 100))

	// Setup AES-GCM
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("ecdh-aes-key"))
	aesKey := make([]byte, 32)
	io.ReadFull(hkdfReader, aesKey)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	dataSizes := []struct {
		name string
		size int
	}{
		{"64B", 64},
		{"1KB", 1024},
		{"10KB", 10240},
		{"100KB", 102400},
	}

	for _, ds := range dataSizes {
		plaintext := make([]byte, ds.size)
		rand.Read(plaintext)
		nonce := make([]byte, gcm.NonceSize())

		var encSize int
		r = runBench(fmt.Sprintf("ENC-001: Encrypt %s", ds.name), 1000, func() {
			rand.Read(nonce)
			enc := gcm.Seal(nil, nonce, plaintext, nil)
			encSize = len(enc)
		})
		r.SizeBefore = ds.size
		r.SizeAfter = encSize + gcm.NonceSize() // Include nonce in overhead
		printSizeResult(r)
	}

	fmt.Println()
	for _, ds := range dataSizes {
		plaintext := make([]byte, ds.size)
		rand.Read(plaintext)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

		r = runBench(fmt.Sprintf("ENC-002: Decrypt %s", ds.name), 1000, func() {
			gcm.Open(nil, nonce, ciphertext, nil)
		})
		printResult(r)
	}

	// =========================================================================
	// SECTION 3: JSON SERIALIZATION
	// =========================================================================
	fmt.Println("\n📊 SECTION 3: JSON SERIALIZATION (Complex Objects, Depth 5)")
	fmt.Println(strings.Repeat("-", 100))

	itemCounts := []int{1, 5, 10, 20}

	for _, count := range itemCounts {
		data := generateComplexResponse(count)
		jsonData, _ := json.Marshal(data)
		fmt.Printf("\n  📦 %d items → JSON size: %d bytes\n", count, len(jsonData))

		r = runBench(fmt.Sprintf("JSON-001: Marshal %d items", count), 500, func() {
			json.Marshal(data)
		})
		printResult(r)

		r = runBench(fmt.Sprintf("JSON-002: Unmarshal %d items", count), 500, func() {
			var out []ComplexItem
			json.Unmarshal(jsonData, &out)
		})
		printResult(r)
	}

	// =========================================================================
	// SECTION 4: END-TO-END BENCHMARKS
	// =========================================================================
	fmt.Println("\n📊 SECTION 4: END-TO-END SECURE REQUEST/RESPONSE")
	fmt.Println(strings.Repeat("-", 100))

	for _, count := range itemCounts {
		data := generateComplexResponse(count)
		jsonData, _ := json.Marshal(data)
		nonce := make([]byte, gcm.NonceSize())

		fmt.Printf("\n  🔄 %d items (depth 5) - Payload: %d bytes\n", count, len(jsonData))

		// E2E without key exchange (reuse existing key)
		var finalEncSize int
		r = runBench(fmt.Sprintf("E2E-001: Full Cycle %d items (key reused)", count), 200, func() {
			// Serialize
			j, _ := json.Marshal(data)
			// Encrypt
			rand.Read(nonce)
			enc := gcm.Seal(nil, nonce, j, nil)
			finalEncSize = len(enc)
			// Decrypt
			dec, _ := gcm.Open(nil, nonce, enc, nil)
			// Deserialize
			var out []ComplexItem
			json.Unmarshal(dec, &out)
		})
		r.SizeBefore = len(jsonData)
		r.SizeAfter = finalEncSize + gcm.NonceSize()
		printSizeResult(r)

		// E2E with key exchange
		r = runBench(fmt.Sprintf("E2E-002: Full Cycle %d items (with key exchange)", count), 100, func() {
			// Key exchange
			c := ecdh.P256()
			ck, _ := c.GenerateKey(rand.Reader)
			sk, _ := c.GenerateKey(rand.Reader)
			ss, _ := ck.ECDH(sk.PublicKey())
			hr := hkdf.New(sha256.New, ss, nil, []byte("ecdh-aes-key"))
			ak := make([]byte, 32)
			io.ReadFull(hr, ak)
			blk, _ := aes.NewCipher(ak)
			g, _ := cipher.NewGCM(blk)
			n := make([]byte, g.NonceSize())

			// Serialize + Encrypt
			j, _ := json.Marshal(data)
			rand.Read(n)
			enc := g.Seal(nil, n, j, nil)
			// Decrypt + Deserialize
			dec, _ := g.Open(nil, n, enc, nil)
			var out []ComplexItem
			json.Unmarshal(dec, &out)
		})
		printResult(r)
	}

	// =========================================================================
	// SUMMARY
	// =========================================================================
	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("                                    ✅ BENCHMARK COMPLETE")
	fmt.Println(strings.Repeat("=", 100))
	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  - KEY-GEN: Key generation and exchange operations")
	fmt.Println("  - ENC: Encryption/Decryption operations")
	fmt.Println("  - JSON: Serialization/Deserialization operations")
	fmt.Println("  - E2E: End-to-end request/response cycles")
	fmt.Println()
}
