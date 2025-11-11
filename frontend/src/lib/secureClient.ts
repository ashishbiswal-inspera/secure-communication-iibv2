/**
 * Secure API Client for mTLS Communication
 *
 * This client handles all API communication with the Go backend.
 * In Phase 1: Works with mTLS (certificate-based authentication)
 * In Phase 2: Will add HMAC request signing for additional security
 */

const API_BASE_URL = "https://127.0.0.1:9000/api";

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
   * Makes a secure POST request
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
