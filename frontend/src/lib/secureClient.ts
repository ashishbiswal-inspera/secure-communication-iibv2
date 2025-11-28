/**
 * Secure API Client with AES-GCM Encryption and Replay Protection
 *
 * This client handles all API communication with the Go backend using:
 * - Application-level encryption (AES-256-GCM)
 * - Timestamp validation (5 second window)
 * - Nonce-based replay protection
 * - Proxy bypass (--no-proxy-server flag in Iceworm)
 */

import {
  encryptionManager,
  EncryptionManager,
  type EncryptedPayload,
} from "./crypto/encryption";

// Get port and server URL directly from window.location (running in Iceworm browser)
export function getServerInfoFromLocation(): {
  port: number;
  serverUrl: string;
} {
  const port = parseInt(window.location.port || "443", 10);
  const serverUrl = `${window.location.protocol}//${window.location.hostname}:${port}`;
  return { port, serverUrl };
}

// Initialize API base URL directly from window.location
const { serverUrl } = getServerInfoFromLocation();
const API_BASE_URL = `${serverUrl}/api`;

interface RequestOptions extends RequestInit {
  timeout?: number;
}

interface ApiResponse<T = unknown> {
  success: boolean;
  message: string;
  data?: T;
}

/**
 * Secure API Client Class
 * Encapsulates all API communication logic
 */
class SecureApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  /**
   * Makes a secure GET request
   */
  async get<T = unknown>(
    endpoint: string,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: "GET",
    });
  }

  /**
   * Makes a secure POST request (unencrypted)
   */
  async post<T = unknown>(
    endpoint: string,
    data?: unknown,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      ...options,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  /**
   * Makes an ENCRYPTED POST request with replay protection
   * Uses AES-256-GCM encryption with timestamp and nonce
   */
  async securePost<T = unknown>(
    endpoint: string,
    data: unknown,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    // Ensure encryption is initialized
    if (!encryptionManager["cryptoKey"]) {
      throw new Error(
        "Encryption not initialized. Call initializeEncryption() first."
      );
    }

    // Encrypt the payload
    const encryptedPayload = await encryptionManager.encrypt(data);

    // Send encrypted request - backend returns EncryptedPayload directly, not wrapped
    const url = `${this.baseUrl}${endpoint}`;
    const { timeout = 10000 } = options;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      body: JSON.stringify(encryptedPayload),
      signal: controller.signal,
      credentials: "include",
    });

    clearTimeout(timeoutId);

    // Backend returns EncryptedPayload directly
    const encryptedResponse: EncryptedPayload = await response.json();

    // Decrypt the response
    const decrypted = await encryptionManager.decrypt(encryptedResponse);
    return decrypted as ApiResponse<T>;
  }

  /**
   * Initialize encryption with key from backend
   */
  async initializeEncryption(): Promise<void> {
    const key = await EncryptionManager.fetchKeyFromBackend(serverUrl);
    await encryptionManager.initialize(key);
    console.log("✅ End-to-end encryption enabled");
  }

  /**
   * Core request method with timeout and error handling
   */
  private async request<T = unknown>(
    endpoint: string,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const { timeout = 10000, ...fetchOptions } = options;
    const url = `${this.baseUrl}${endpoint}`;

    try {
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        ...fetchOptions,
        signal: controller.signal,
        credentials: "include", // Important for sending client certificates
      });

      clearTimeout(timeoutId);

      // Parse JSON response
      const data: ApiResponse<T> = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || `HTTP ${response.status}: ${response.statusText}`
        );
      }

      return data;
    } catch (error) {
      console.error(`API Request failed: ${endpoint}`, error);

      if (error instanceof Error) {
        if (error.name === "AbortError") {
          throw new Error("Request timeout");
        }
        throw error;
      }

      throw new Error("An unknown error occurred");
    }
  }

  /**
   * Health check endpoint
   */
  async ping(): Promise<ApiResponse> {
    return this.get("/ping");
  }
}

// Export singleton instance
export const apiClient = new SecureApiClient();

// Export class for custom instances if needed
export { SecureApiClient };

// Export types
export type { ApiResponse, RequestOptions };
