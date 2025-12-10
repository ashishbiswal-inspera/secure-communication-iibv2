// =============================================================================
// FRONTEND SECURITY BENCHMARKS
// =============================================================================
// Benchmarks for Web Crypto API operations (ECDH, AES-GCM)
// =============================================================================

// Data structures matching Go backend (20 properties, depth 5)
export interface Coordinates {
  lat: number;
  lng: number;
  altitude: number;
  accuracy: number;
  extra?: CoordinatesExtra;
}

export interface CoordinatesExtra {
  timezone: string;
  utcOffset: number;
  daylightSav: boolean;
  region?: Region;
}

export interface Region {
  name: string;
  code: string;
  subCodes: string[];
  parent?: Region; // Depth 5 achieved here
}

export interface Address {
  street: string;
  city: string;
  country: string;
  postalCode: string;
  coords?: Coordinates;
  metadata?: Record<string, string>;
}

export interface ComplexItem {
  id: number;
  uuid: string;
  name: string;
  description: string;
  price: number;
  quantity: number;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  tags: string[];
  ratings: number[];
  address: Address;
  attributes: Record<string, unknown>;
  relatedIds: number[];
  score: number;
  priority: number;
  flags: number;
  rawData: string;
  nullableField: string | null;
  nestedMetadata: Record<string, Region>;
}

// =============================================================================
// DATA GENERATORS
// =============================================================================

export function generateComplexItem(index: number): ComplexItem {
  return {
    id: index,
    uuid: `uuid-${index}-abcd-efgh-ijkl-${index * 1000}`,
    name: `Item Name ${index} with some extra text`,
    description: `This is a detailed description for item ${index}.`,
    price: index * 19.99,
    quantity: index * 10,
    isActive: index % 2 === 0,
    createdAt: new Date(Date.now() - index * 3600000).toISOString(),
    updatedAt: new Date().toISOString(),
    tags: ["tag1", "tag2", "tag3", `custom_${index}`],
    ratings: [4.5, 3.8, 4.9, 5.0, 4.2],
    address: {
      street: `${index * 100} Main Street`,
      city: "Test City",
      country: "Test Country",
      postalCode: String(index).padStart(5, "0"),
      coords: {
        lat: 40.7128 + index * 0.001,
        lng: -74.006 + index * 0.001,
        altitude: 10.5,
        accuracy: 5.0,
        extra: {
          timezone: "America/New_York",
          utcOffset: -5,
          daylightSav: true,
          region: {
            name: "Northeast",
            code: "NE",
            subCodes: ["NY", "NJ", "CT"],
            parent: {
              name: "United States",
              code: "US",
              subCodes: ["NE", "SE", "MW", "SW", "W"],
            },
          },
        },
      },
      metadata: { verified: "true", source: "api" },
    },
    attributes: { color: "blue", size: "large", weight: 2.5 },
    relatedIds: [index + 1, index + 2],
    score: index * 0.85,
    priority: index % 10,
    flags: index * 12345,
    rawData: `raw_${index}`,
    nullableField: `nullable_${index}`,
    nestedMetadata: {
      primary: { name: "Primary", code: "PR", subCodes: ["P1"] },
    },
  };
}

export function generateComplexResponse(count: number): ComplexItem[] {
  return Array.from({ length: count }, (_, i) => generateComplexItem(i));
}

// =============================================================================
// BENCHMARK RESULT TYPES
// =============================================================================

export interface BenchmarkResult {
  name: string;
  category: string;
  iterations: number;
  avgTimeMs: number;
  minTimeMs: number;
  maxTimeMs: number;
  sizeBefore?: number;
  sizeAfter?: number;
  overheadPercent?: number;
}

export interface BenchmarkSuite {
  timestamp: string;
  browser: string;
  results: BenchmarkResult[];
}

// =============================================================================
// BENCHMARK UTILITIES
// =============================================================================

/**
 * Fill a Uint8Array with random values, handling the 65536-byte limit
 * of crypto.getRandomValues()
 */
function fillRandomValues(array: Uint8Array): void {
  const MAX_CHUNK = 65536; // Web Crypto API limit
  for (let offset = 0; offset < array.length; offset += MAX_CHUNK) {
    const chunk = array.subarray(
      offset,
      Math.min(offset + MAX_CHUNK, array.length)
    );
    crypto.getRandomValues(chunk);
  }
}

async function runBenchmark(
  name: string,
  category: string,
  iterations: number,
  fn: () => Promise<void> | void
): Promise<BenchmarkResult> {
  const times: number[] = [];

  // Warmup
  for (let i = 0; i < 5; i++) {
    await fn();
  }

  // Actual benchmark
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    times.push(performance.now() - start);
  }

  const avgTimeMs = times.reduce((a, b) => a + b, 0) / times.length;
  const minTimeMs = Math.min(...times);
  const maxTimeMs = Math.max(...times);

  return {
    name,
    category,
    iterations,
    avgTimeMs,
    minTimeMs,
    maxTimeMs,
  };
}

// =============================================================================
// KEY GENERATION BENCHMARKS
// =============================================================================

async function benchmarkECDHKeyGeneration(
  iterations: number
): Promise<BenchmarkResult> {
  return runBenchmark(
    "ECDH P-256 KeyPair Generation",
    "Key Generation",
    iterations,
    async () => {
      await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
    }
  );
}

async function benchmarkECDHSharedSecret(
  iterations: number
): Promise<BenchmarkResult> {
  const clientKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const serverKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  return runBenchmark(
    "ECDH Shared Secret Computation",
    "Key Generation",
    iterations,
    async () => {
      await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverKeyPair.publicKey },
        clientKeyPair.privateKey,
        256
      );
    }
  );
}

async function benchmarkHKDF(iterations: number): Promise<BenchmarkResult> {
  const keyPair1 = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const keyPair2 = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: keyPair2.publicKey },
    keyPair1.privateKey,
    256
  );

  return runBenchmark(
    "HKDF-SHA256 Key Derivation",
    "Key Generation",
    iterations,
    async () => {
      const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedBits,
        { name: "HKDF" },
        false,
        ["deriveKey"]
      );
      await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode("ecdh-aes-key"),
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    }
  );
}

async function benchmarkFullKeyExchange(
  iterations: number
): Promise<BenchmarkResult> {
  return runBenchmark(
    "Full ECDH Key Exchange Flow",
    "Key Generation",
    iterations,
    async () => {
      // Generate client key pair
      const clientKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      // Generate server key pair
      const serverKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      // Derive shared secret
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverKeyPair.publicKey },
        clientKeyPair.privateKey,
        256
      );
      // Derive AES key via HKDF
      const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedBits,
        { name: "HKDF" },
        false,
        ["deriveKey"]
      );
      await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode("ecdh-aes-key"),
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );
    }
  );
}

// =============================================================================
// ENCRYPTION BENCHMARKS
// =============================================================================

async function benchmarkAESEncryption(
  iterations: number,
  dataSize: number,
  label: string
): Promise<BenchmarkResult> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const data = new Uint8Array(dataSize);
  fillRandomValues(data);

  let encryptedSize = 0;

  const result = await runBenchmark(
    `Encrypt ${label}`,
    "Encryption",
    iterations,
    async () => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        keyPair,
        data
      );
      encryptedSize = encrypted.byteLength + 12; // Include IV
    }
  );

  result.sizeBefore = dataSize;
  result.sizeAfter = encryptedSize;
  result.overheadPercent = ((encryptedSize - dataSize) / dataSize) * 100;

  return result;
}

async function benchmarkAESDecryption(
  iterations: number,
  dataSize: number,
  label: string
): Promise<BenchmarkResult> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const data = new Uint8Array(dataSize);
  fillRandomValues(data);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return runBenchmark(
    `Decrypt ${label}`,
    "Encryption",
    iterations,
    async () => {
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    }
  );
}

// =============================================================================
// JSON SERIALIZATION BENCHMARKS
// =============================================================================

async function benchmarkJSONMarshal(
  iterations: number,
  itemCount: number
): Promise<BenchmarkResult> {
  const data = generateComplexResponse(itemCount);

  const result = await runBenchmark(
    `JSON.stringify ${itemCount} items`,
    "Serialization",
    iterations,
    () => {
      JSON.stringify(data);
    }
  );

  const jsonStr = JSON.stringify(data);
  result.sizeBefore = itemCount;
  result.sizeAfter = new TextEncoder().encode(jsonStr).length;

  return result;
}

async function benchmarkJSONUnmarshal(
  iterations: number,
  itemCount: number
): Promise<BenchmarkResult> {
  const data = generateComplexResponse(itemCount);
  const jsonStr = JSON.stringify(data);

  return runBenchmark(
    `JSON.parse ${itemCount} items`,
    "Serialization",
    iterations,
    () => {
      JSON.parse(jsonStr);
    }
  );
}

// =============================================================================
// END-TO-END BENCHMARKS
// =============================================================================

async function benchmarkE2EKeyReused(
  iterations: number,
  itemCount: number
): Promise<BenchmarkResult> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const data = generateComplexResponse(itemCount);

  let encryptedSize = 0;
  const jsonStr = JSON.stringify(data);
  const plainSize = new TextEncoder().encode(jsonStr).length;

  const result = await runBenchmark(
    `E2E Cycle ${itemCount} items (key reused)`,
    "End-to-End",
    iterations,
    async () => {
      // Serialize
      const json = JSON.stringify(data);
      const encoded = new TextEncoder().encode(json);

      // Encrypt
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
      );
      encryptedSize = encrypted.byteLength + 12;

      // Decrypt
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encrypted
      );

      // Deserialize
      const decoded = new TextDecoder().decode(decrypted);
      JSON.parse(decoded);
    }
  );

  result.sizeBefore = plainSize;
  result.sizeAfter = encryptedSize;
  result.overheadPercent = ((encryptedSize - plainSize) / plainSize) * 100;

  return result;
}

async function benchmarkE2EWithKeyExchange(
  iterations: number,
  itemCount: number
): Promise<BenchmarkResult> {
  const data = generateComplexResponse(itemCount);

  return runBenchmark(
    `E2E Cycle ${itemCount} items (with key exchange)`,
    "End-to-End",
    iterations,
    async () => {
      // Key Exchange
      const clientKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      const serverKeyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverKeyPair.publicKey },
        clientKeyPair.privateKey,
        256
      );
      const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedBits,
        { name: "HKDF" },
        false,
        ["deriveKey"]
      );
      const aesKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0),
          info: new TextEncoder().encode("ecdh-aes-key"),
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      // Serialize + Encrypt
      const json = JSON.stringify(data);
      const encoded = new TextEncoder().encode(json);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encoded
      );

      // Decrypt + Deserialize
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encrypted
      );
      const decoded = new TextDecoder().decode(decrypted);
      JSON.parse(decoded);
    }
  );
}

// =============================================================================
// MAIN BENCHMARK RUNNER
// =============================================================================

export interface BenchmarkProgress {
  current: number;
  total: number;
  currentBenchmark: string;
}

export type ProgressCallback = (progress: BenchmarkProgress) => void;

export async function runAllBenchmarks(
  onProgress?: ProgressCallback
): Promise<BenchmarkSuite> {
  const results: BenchmarkResult[] = [];
  const benchmarks: Array<() => Promise<BenchmarkResult>> = [];

  // Key Generation benchmarks
  benchmarks.push(() => benchmarkECDHKeyGeneration(100));
  benchmarks.push(() => benchmarkECDHSharedSecret(100));
  benchmarks.push(() => benchmarkHKDF(500));
  benchmarks.push(() => benchmarkFullKeyExchange(50));

  // Encryption benchmarks
  const sizes = [
    { size: 64, label: "64B" },
    { size: 1024, label: "1KB" },
    { size: 10240, label: "10KB" },
    { size: 65536, label: "64KB" },
  ];
  for (const { size, label } of sizes) {
    benchmarks.push(() => benchmarkAESEncryption(200, size, label));
    benchmarks.push(() => benchmarkAESDecryption(200, size, label));
  }

  // JSON benchmarks
  const itemCounts = [1, 5, 10, 20];
  for (const count of itemCounts) {
    benchmarks.push(() => benchmarkJSONMarshal(100, count));
    benchmarks.push(() => benchmarkJSONUnmarshal(100, count));
  }

  // E2E benchmarks
  for (const count of itemCounts) {
    benchmarks.push(() => benchmarkE2EKeyReused(50, count));
    benchmarks.push(() => benchmarkE2EWithKeyExchange(20, count));
  }

  const total = benchmarks.length;
  for (let i = 0; i < benchmarks.length; i++) {
    if (onProgress) {
      onProgress({
        current: i + 1,
        total,
        currentBenchmark: `Running benchmark ${i + 1}/${total}`,
      });
    }
    const result = await benchmarks[i]();
    results.push(result);
  }

  return {
    timestamp: new Date().toISOString(),
    browser: navigator.userAgent,
    results,
  };
}

// =============================================================================
// CONSOLE REPORTER
// =============================================================================

export function printBenchmarkResults(suite: BenchmarkSuite): void {
  console.log("=".repeat(80));
  console.log("🔐 SECURITY BENCHMARKS - FRONTEND REPORT");
  console.log("=".repeat(80));
  console.log(`Timestamp: ${suite.timestamp}`);
  console.log(`Browser: ${suite.browser}`);
  console.log("=".repeat(80));

  const categories = [
    "Key Generation",
    "Encryption",
    "Serialization",
    "End-to-End",
  ];

  for (const category of categories) {
    const categoryResults = suite.results.filter(
      (r) => r.category === category
    );
    if (categoryResults.length === 0) continue;

    console.log(`\n📊 ${category.toUpperCase()}`);
    console.log("-".repeat(80));

    for (const r of categoryResults) {
      let line = `  ${r.name.padEnd(45)} | Avg: ${r.avgTimeMs.toFixed(3)}ms`;
      if (r.sizeBefore !== undefined && r.sizeAfter !== undefined) {
        line += ` | Size: ${r.sizeBefore} → ${r.sizeAfter} bytes`;
        if (r.overheadPercent !== undefined) {
          line += ` (+${r.overheadPercent.toFixed(1)}%)`;
        }
      }
      console.log(line);
    }
  }

  console.log("\n" + "=".repeat(80));
  console.log("✅ BENCHMARK COMPLETE");
  console.log("=".repeat(80));
}
