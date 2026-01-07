/**
 * ECDH Key Exchange using Web Crypto API
 * Implements Elliptic Curve Diffie-Hellman for secure key establishment
 */

export class ECDHKeyExchange {
  private keyPair: CryptoKeyPair | null = null;

  /**
   * Generate ECDH P-256 keypair
   */
  async generateKeyPair(): Promise<void> {
    this.keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true, // extractable (needed to export public key)
      ["deriveBits"]
    );
  }

  /**
   * Get public key as base64 string (raw format)
   */
  async getPublicKeyBase64(): Promise<string> {
    if (!this.keyPair) {
      throw new Error("Key pair not generated. Call generateKeyPair() first.");
    }

    // Export as raw bytes (uncompressed point format)
    const publicKeyBuffer = await window.crypto.subtle.exportKey(
      "raw",
      this.keyPair.publicKey
    );

    // Convert to base64
    return this.arrayBufferToBase64(publicKeyBuffer);
  }

  /**
   * Compute shared secret from peer's public key
   */
  async computeSharedSecret(peerPublicKeyBase64: string): Promise<ArrayBuffer> {
    if (!this.keyPair) {
      throw new Error("Key pair not generated. Call generateKeyPair() first.");
    }

    // Decode base64 public key
    const peerPublicKeyBytes = this.base64ToArrayBuffer(peerPublicKeyBase64);

    // Import peer's public key
    const peerPublicKey = await window.crypto.subtle.importKey(
      "raw",
      peerPublicKeyBytes,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      false,
      []
    );

    // Derive shared secret (256 bits for P-256)
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: peerPublicKey,
      },
      this.keyPair.privateKey,
      256 // 256 bits
    );

    return sharedSecret;
  }

  /**
   * Derive AES-256-GCM key from shared secret using HKDF-SHA256
   */
  async deriveAESKey(sharedSecret: ArrayBuffer): Promise<CryptoKey> {
    // Import shared secret as HKDF key material
    const hkdfKey = await window.crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveKey"]
    );

    // Derive AES-GCM key using HKDF
    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0), // No salt (matches backend)
        info: new TextEncoder().encode("ecdh-aes-key"), // Must match backend
      },
      hkdfKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false, // not extractable
      ["encrypt", "decrypt"]
    );

    return aesKey;
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
