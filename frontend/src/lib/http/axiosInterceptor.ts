/**
 * Axios-based HTTP Interceptor with Encryption Support
 * Unified decorator pattern for all HTTP methods (GET, POST, PUT, DELETE, PATCH)
 */

import axios, {
  type AxiosInstance,
  type AxiosRequestConfig,
  type AxiosResponse,
} from "axios";
import { encryptionManager, type EncryptedPayload } from "../crypto/encryption";

export interface RequestConfig extends AxiosRequestConfig {
  encrypted?: boolean; // Flag to enable encryption for this request
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  message: string;
  data?: T;
}

/**
 * HTTP Client with automatic encryption/decryption using Axios
 */
export class HttpClient {
  private axiosInstance: AxiosInstance;

  constructor(baseURL: string) {
    this.axiosInstance = axios.create({
      baseURL,
      timeout: 10000,
      withCredentials: true,
      headers: {
        "Content-Type": "application/json",
      },
    });

    // Request interceptor for encryption
    this.axiosInstance.interceptors.request.use(
      async (config) => {
        const encrypted = (config as RequestConfig).encrypted;

        // If encryption is enabled and there's data, encrypt it
        if (encrypted && config.data !== undefined) {
          if (!encryptionManager.isReady()) {
            throw new Error(
              "Encryption not initialized. Call initializeEncryption() first."
            );
          }
          const encryptedPayload = await encryptionManager.encrypt(config.data);
          config.data = encryptedPayload;
        }

        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor for decryption
    this.axiosInstance.interceptors.response.use(
      async (response: AxiosResponse) => {
        const encrypted = (response.config as RequestConfig).encrypted;

        // If encryption is enabled, decrypt the response
        if (encrypted) {
          const encryptedResponse: EncryptedPayload = response.data;
          const decrypted = await encryptionManager.decrypt(encryptedResponse);
          response.data = decrypted;
        }

        return response;
      },
      (error) => {
        return Promise.reject(error);
      }
    );
  }

  /**
   * Generic request method that handles all HTTP methods
   * Automatically encrypts/decrypts if config.encrypted = true
   */
  async request<T = unknown>(
    method: string,
    url: string,
    data?: unknown,
    config: RequestConfig = {}
  ): Promise<ApiResponse<T>> {
    try {
      const response: AxiosResponse<ApiResponse<T>> =
        await this.axiosInstance.request({
          method: method.toUpperCase(),
          url,
          data,
          ...config,
        });

      return response.data;
    } catch (error) {
      console.error(
        `HTTP ${method.toUpperCase()} request failed: ${url}`,
        error
      );

      if (axios.isAxiosError(error)) {
        if (error.code === "ECONNABORTED") {
          throw new Error("Request timeout");
        }
        throw new Error(error.response?.data?.message || error.message);
      }

      throw new Error("An unknown error occurred");
    }
  }

  /**
   * GET request
   */
  async get<T = unknown>(
    url: string,
    config?: RequestConfig
  ): Promise<ApiResponse<T>> {
    return this.request<T>("GET", url, undefined, config);
  }

  /**
   * POST request
   */
  async post<T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ApiResponse<T>> {
    return this.request<T>("POST", url, data, config);
  }

  /**
   * PUT request
   */
  async put<T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ApiResponse<T>> {
    return this.request<T>("PUT", url, data, config);
  }

  /**
   * PATCH request
   */
  async patch<T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ApiResponse<T>> {
    return this.request<T>("PATCH", url, data, config);
  }

  /**
   * DELETE request
   */
  async delete<T = unknown>(
    url: string,
    data?: unknown,
    config?: RequestConfig
  ): Promise<ApiResponse<T>> {
    return this.request<T>("DELETE", url, data, config);
  }
}

/**
 * Get server info from window.location
 */
export function getServerInfo(): { port: number; serverUrl: string } {
  const port = parseInt(window.location.port || "443", 10);
  const serverUrl = `${window.location.protocol}//${window.location.hostname}:${port}`;
  return { port, serverUrl };
}

// Create default client instance
const { serverUrl } = getServerInfo();
export const httpClient = new HttpClient(`${serverUrl}/api`);
