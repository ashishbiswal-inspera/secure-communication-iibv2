/**
 * Encryption utilities using Web Crypto API
 * Implements AES-256-GCM encryption with ECDH key exchange and replay protection
 */

import { ECDHKeyExchange } from "./crypto/ecdh";

// Encrypted payload structure matching backend
interface EncryptedPayload {
  ciphertext: string; // Base64 encoded
  nonce: string; // Base64 encoded GCM nonce
}

// Secure request with timestamp and nonce for replay protection
interface SecureRequest {
  timestamp: number; // Unix timestamp in milliseconds
  nonce: string; // Unique request identifier (UUID)
  payload: unknown; // Actual request data
}

// Key exchange response from backend
interface KeyExchangeResponse {
  success: boolean;
  publicKey: string; // Base64 encoded P-256 public key
}

/**
 * Encryption Manager using Web Crypto API with ECDH key exchange
 */
export class EncryptionManager {
  private cryptoKey: CryptoKey | null = null;
  private ecdh: ECDHKeyExchange;

  constructor() {
    this.ecdh = new ECDHKeyExchange();
  }

  /**
   * Perform ECDH key exchange with backend to establish shared secret
   * This replaces the old fetchKeyFromBackend method
   */
  async performKeyExchange(serverUrl: string): Promise<void> {
    console.log("🔐 Starting ECDH key exchange...");

    // 1. Generate our ECDH keypair
    await this.ecdh.generateKeyPair();
    console.log("   ✓ Generated ECDH P-256 keypair");

    // 2. Get our public key
    const ourPublicKey = await this.ecdh.getPublicKeyBase64();

    // 3. Send our public key to backend and receive theirs
    const response = await fetch(`${serverUrl}/api/key-exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ publicKey: ourPublicKey }),
    });

    if (!response.ok) {
      throw new Error(`Key exchange failed: ${response.status}`);
    }

    const data: KeyExchangeResponse = await response.json();

    if (!data.success || !data.publicKey) {
      throw new Error("Key exchange failed: invalid response from server");
    }

    console.log("   ✓ Received backend's public key");

    // 4. Compute shared secret
    const sharedSecret = await this.ecdh.computeSharedSecret(data.publicKey);
    console.log("   ✓ Computed shared secret");

    // 5. Derive AES-256-GCM key from shared secret
    this.cryptoKey = await this.ecdh.deriveAESKey(sharedSecret);
    console.log("   ✓ Derived AES-256-GCM key");

    console.log("✅ ECDH key exchange complete - encryption ready");
  }

  /**
   * Initialize with AES key (hex format) - for backward compatibility
   * @deprecated Use performKeyExchange() instead for better security
   */
  async initialize(keyHex: string): Promise<void> {
    console.warn(
      "⚠️ Using deprecated initialize() method. Consider using performKeyExchange() for better security."
    );
    // Convert hex string to Uint8Array
    const keyBytes = this.hexToBytes(keyHex);

    // Import key for AES-GCM
    this.cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      this.toArrayBuffer(keyBytes),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    console.log("Encryption initialized with AES-256-GCM");
  }

  /**
   * Check if encryption is ready
   */
  isReady(): boolean {
    return this.cryptoKey !== null;
  }

  /**
   * Encrypt data with AES-GCM
   */
  async encrypt(data: unknown): Promise<EncryptedPayload> {
    if (!this.cryptoKey) {
      throw new Error("Encryption manager not initialized");
    }

    // Generate random nonce (UUID v4)
    const requestNonce = crypto.randomUUID();

    // Create secure request with timestamp and nonce
    const secureRequest: SecureRequest = {
      timestamp: Date.now(),
      nonce: requestNonce,
      payload: data,
    };

    // Convert to JSON string then to bytes
    const plaintext = new TextEncoder().encode(JSON.stringify(secureRequest));

    // Generate random 12-byte nonce for GCM
    const gcmNonce = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: gcmNonce,
      },
      this.cryptoKey,
      plaintext
    );

    // Convert to base64
    return {
      ciphertext: this.arrayBufferToBase64(ciphertext),
      nonce: this.arrayBufferToBase64(this.toArrayBuffer(gcmNonce)),
    };
  }

  /**
   * Decrypt data with AES-GCM
   */
  async decrypt(payload: EncryptedPayload): Promise<unknown> {
    if (!this.cryptoKey) {
      throw new Error("Encryption manager not initialized");
    }

    // Decode base64
    const ciphertext = this.base64ToArrayBuffer(payload.ciphertext);
    const gcmNonce = this.base64ToArrayBuffer(payload.nonce);

    // Decrypt
    const plaintext = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(gcmNonce),
      },
      this.cryptoKey,
      ciphertext
    );

    // Convert bytes to string and parse JSON
    const json = new TextDecoder().decode(plaintext);
    return JSON.parse(json);
  }

  /**
   * @deprecated Key exchange is now done via ECDH - use performKeyExchange() instead
   * This method is kept for backward compatibility but should not be used
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  static async fetchKeyFromBackend(_serverUrl: string): Promise<string> {
    throw new Error(
      "fetchKeyFromBackend is deprecated. Use encryptionManager.performKeyExchange() instead for secure ECDH key exchange."
    );
  }

  // Helper: Convert hex string to Uint8Array
  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  // Helper: Convert Uint8Array to ArrayBuffer (properly sliced)
  private toArrayBuffer(uint8Array: Uint8Array): ArrayBuffer {
    const sliced = uint8Array.buffer.slice(
      uint8Array.byteOffset,
      uint8Array.byteOffset + uint8Array.byteLength
    );
    return sliced as ArrayBuffer;
  }

  // Helper: Convert ArrayBuffer to base64
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  // Helper: Convert base64 to ArrayBuffer
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// Export singleton instance
export const encryptionManager = new EncryptionManager();

// Export types
export type { EncryptedPayload, SecureRequest };
