/**
 * Unified API Client with Axios
 * Uses Axios-based HTTP interceptor with encryption support
 * All methods (GET, POST, PUT, DELETE, PATCH) can be encrypted by setting { encrypted: true }
 */

import { httpClient, getServerInfo } from "./http/axiosInterceptor";
import { encryptionManager, EncryptionManager } from "./encryption";
import type { ApiResponse } from "./http/axiosInterceptor";

export { getServerInfo };
export type { ApiResponse };

/**
 * API Client Class
 */
class ApiClient {
  /**
   * Initialize encryption with key from backend
   */
  async initializeEncryption(): Promise<void> {
    const { serverUrl } = getServerInfo();
    const key = await EncryptionManager.fetchKeyFromBackend(serverUrl);
    await encryptionManager.initialize(key);
    console.log("✅ End-to-end encryption enabled (Axios)");
  }

  /**
   * Check if encryption is ready
   */
  isEncryptionReady(): boolean {
    return encryptionManager.isReady();
  }

  // ============ Regular Methods (Unencrypted) ============

  /**
   * GET request (unencrypted)
   */
  async get<T = unknown>(endpoint: string): Promise<ApiResponse<T>> {
    return httpClient.get<T>(endpoint);
  }

  /**
   * POST request (unencrypted)
   */
  async post<T = unknown>(
    endpoint: string,
    data?: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.post<T>(endpoint, data);
  }

  /**
   * PUT request (unencrypted)
   */
  async put<T = unknown>(
    endpoint: string,
    data?: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.put<T>(endpoint, data);
  }

  /**
   * PATCH request (unencrypted)
   */
  async patch<T = unknown>(
    endpoint: string,
    data?: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.patch<T>(endpoint, data);
  }

  /**
   * DELETE request (unencrypted)
   */
  async delete<T = unknown>(
    endpoint: string,
    data?: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.delete<T>(endpoint, data);
  }

  // ============ Secure Methods (Encrypted) ============

  /**
   * GET request with encryption
   */
  async secureGet<T = unknown>(endpoint: string): Promise<ApiResponse<T>> {
    return httpClient.get<T>(endpoint, { encrypted: true });
  }

  /**
   * POST request with encryption
   */
  async securePost<T = unknown>(
    endpoint: string,
    data: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.post<T>(endpoint, data, { encrypted: true });
  }

  /**
   * PUT request with encryption
   */
  async securePut<T = unknown>(
    endpoint: string,
    data: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.put<T>(endpoint, data, { encrypted: true });
  }

  /**
   * PATCH request with encryption
   */
  async securePatch<T = unknown>(
    endpoint: string,
    data: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.patch<T>(endpoint, data, { encrypted: true });
  }

  /**
   * DELETE request with encryption
   */
  async secureDelete<T = unknown>(
    endpoint: string,
    data?: unknown
  ): Promise<ApiResponse<T>> {
    return httpClient.delete<T>(endpoint, data, { encrypted: true });
  }

  /**
   * Health check endpoint
   */
  async ping(): Promise<ApiResponse> {
    return this.get("/ping");
  }
}

// Export singleton instance
export const apiClient = new ApiClient();
