// Copyright (c) 2024 Second Star Cavalier, LLC.

import https from "https";
import http from "http";
import {
  ValidationError,
  newErrMissingInvalidData,
  newErrNotFound,
  newErrUnauthorized,
  newErrGeneral,
} from "johnnycash-tacplus-spec/errors.js";

/**
 * HTTP client configuration interface.
 * Matches the protobuf HttpClientConfig structure.
 */
export interface HttpClientConfig {
  timeoutSeconds?: number;
  retryConfig?: RetryConfig;
  disableValidation?: boolean;
  clientCert?: X509CertPair;
  rootCerts?: X509Cert[];
  insecureSkipVerify?: boolean;
  idleConnTimeoutSeconds?: number;
  tlsHandshakeTimeoutSeconds?: number;
  responseHeaderTimeoutSeconds?: number;
  expectContinueTimeoutSeconds?: number;
}

export interface RetryConfig {
  maxRetries?: number;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
  backoffMultiplier?: number;
  retryableStatusCodes?: number[];
}

export interface X509Cert {
  base64: string;
}

export interface X509CertPair {
  cert: X509Cert;
  key: { base64: string };
}

/**
 * TypedClient wraps the base HTTP client and provides type-safe methods with retry logic.
 * Each method accepts full URLs, allowing the client to be reused for any endpoint.
 *
 * This class serves as the static library infrastructure for compiler-generated
 * typed HTTP client methods.
 */
export class TypedClient {
  private readonly httpAgent: http.Agent;
  private readonly httpsAgent: https.Agent;
  private readonly retryConfig: RetryConfig;
  private readonly disableValidation: boolean;
  private readonly timeoutMs: number;

  /**
   * Creates a new typed HTTP client from the provided HttpClientConfig.
   * If config is null, a default configuration is used.
   * The retry configuration is taken from config.retryConfig; if null, a default is used.
   *
   * @param config the HTTP client configuration
   * @throws Error if TLS configuration fails
   */
  constructor(config?: HttpClientConfig) {
    config = config || {};

    this.retryConfig = config.retryConfig || this.defaultRetryConfig();
    this.disableValidation = config.disableValidation || false;
    // A timeoutSeconds of 0 or undefined means no timeout is applied.
    this.timeoutMs = (config.timeoutSeconds || 0) * 1000;

    // Configure HTTP agent
    this.httpAgent = new http.Agent({
      keepAlive: true,
      timeout: this.timeoutMs || undefined,
    });

    // Configure HTTPS agent with TLS settings
    const httpsOptions: https.AgentOptions = {
      keepAlive: true,
      timeout: this.timeoutMs || undefined,
      rejectUnauthorized: !config.insecureSkipVerify,
    };

    // Configure client certificate for mTLS
    if (config.clientCert) {
      httpsOptions.cert = Buffer.from(config.clientCert.cert.base64, "base64");
      httpsOptions.key = Buffer.from(config.clientCert.key.base64, "base64");
    }

    // Configure custom root CAs
    if (config.rootCerts && config.rootCerts.length > 0) {
      httpsOptions.ca = config.rootCerts.map((cert) =>
        Buffer.from(cert.base64, "base64"),
      );
    }

    this.httpsAgent = new https.Agent(httpsOptions);
  }

  /**
   * Returns the retry configuration for this client.
   */
  getRetryConfig(): RetryConfig {
    return this.retryConfig;
  }

  /**
   * Returns whether validation is disabled for this client.
   */
  isValidationDisabled(): boolean {
    return this.disableValidation;
  }

  /**
   * Performs a GET request with retry logic and deserializes using the provided function.
   *
   * @param url the URL to request
   * @param fromBytes function to deserialize response bytes
   * @returns the deserialized response
   * @throws ValidationError if the request fails
   */
  async doGet<T>(url: string, fromBytes: (bytes: Buffer) => T): Promise<T> {
    const maxAttempts =
      this.retryConfig && this.retryConfig.maxRetries
        ? this.retryConfig.maxRetries + 1
        : 1;

    let lastError: ValidationError | null = null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (attempt > 0) {
        // Calculate backoff and wait
        const backoffMs = this.calculateBackoffMs(attempt - 1);
        await this.sleep(backoffMs);
      }

      try {
        const response = await this.request("GET", url, null);

        // Check for error status codes
        if (response.statusCode >= 400) {
          const shouldRetry =
            this.retryConfig && this.isRetryableStatus(response.statusCode);
          lastError = this.statusCodeToException(response.statusCode);

          if (shouldRetry && attempt < maxAttempts - 1) {
            continue;
          }
          throw lastError;
        }

        // Success - deserialize and return
        return fromBytes(response.body);
      } catch (error) {
        if (error instanceof ValidationError) {
          lastError = error;
          if (attempt >= maxAttempts - 1) {
            throw error;
          }
        } else {
          // Network errors are retryable
          lastError = newErrGeneral(error as Error, "Request failed");
          if (attempt >= maxAttempts - 1) {
            throw lastError;
          }
        }
      }
    }

    throw lastError!;
  }

  /**
   * Performs a POST request with retry logic and deserializes the response.
   *
   * @param url the URL to request
   * @param dataBytes pre-serialized request body bytes
   * @param fromBytes function to deserialize response bytes
   * @returns the deserialized response
   * @throws ValidationError if the request fails
   */
  async doPostWithResponse<T>(
    url: string,
    dataBytes: Buffer,
    fromBytes: (bytes: Buffer) => T,
  ): Promise<T> {
    const maxAttempts =
      this.retryConfig && this.retryConfig.maxRetries
        ? this.retryConfig.maxRetries + 1
        : 1;

    let lastError: ValidationError | null = null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (attempt > 0) {
        const backoffMs = this.calculateBackoffMs(attempt - 1);
        await this.sleep(backoffMs);
      }

      try {
        const response = await this.request("POST", url, dataBytes);

        // Check for error status codes
        if (response.statusCode >= 400) {
          const shouldRetry =
            this.retryConfig && this.isRetryableStatus(response.statusCode);
          lastError = this.statusCodeToException(response.statusCode);

          if (shouldRetry && attempt < maxAttempts - 1) {
            continue;
          }
          throw lastError;
        }

        // Success - deserialize and return
        return fromBytes(response.body);
      } catch (error) {
        if (error instanceof ValidationError) {
          lastError = error;
          if (attempt >= maxAttempts - 1) {
            throw error;
          }
        } else {
          lastError = newErrGeneral(error as Error, "Request failed");
          if (attempt >= maxAttempts - 1) {
            throw lastError;
          }
        }
      }
    }

    throw lastError!;
  }

  /**
   * Performs PUT/PATCH/DELETE with retry logic and typed data, returns no body.
   *
   * @param method HTTP method (PUT, PATCH, DELETE)
   * @param url the URL to request
   * @param dataBytes pre-serialized request body bytes, can be null
   * @throws ValidationError if the request fails
   */
  async doMutation(
    method: string,
    url: string,
    dataBytes: Buffer | null,
  ): Promise<void> {
    const maxAttempts =
      this.retryConfig && this.retryConfig.maxRetries
        ? this.retryConfig.maxRetries + 1
        : 1;

    let lastError: ValidationError | null = null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      if (attempt > 0) {
        const backoffMs = this.calculateBackoffMs(attempt - 1);
        await this.sleep(backoffMs);
      }

      try {
        const response = await this.request(method, url, dataBytes);

        // Check for error status codes
        if (response.statusCode >= 400) {
          const shouldRetry =
            this.retryConfig && this.isRetryableStatus(response.statusCode);
          lastError = this.statusCodeToException(response.statusCode);

          if (shouldRetry && attempt < maxAttempts - 1) {
            continue;
          }
          throw lastError;
        }

        // Success
        return;
      } catch (error) {
        if (error instanceof ValidationError) {
          lastError = error;
          if (attempt >= maxAttempts - 1) {
            throw error;
          }
        } else {
          lastError = newErrGeneral(error as Error, "Request failed");
          if (attempt >= maxAttempts - 1) {
            throw lastError;
          }
        }
      }
    }

    throw lastError!;
  }

  // Helper methods

  /**
   * Returns a default retry configuration.
   */
  private defaultRetryConfig(): RetryConfig {
    return {
      maxRetries: 3,
      initialBackoffMs: 100,
      maxBackoffMs: 5000,
      backoffMultiplier: 2.0,
      retryableStatusCodes: [429, 500, 502, 503, 504],
    };
  }

  /**
   * Checks if a status code is in the retryable list.
   */
  private isRetryableStatus(statusCode: number): boolean {
    const retryableCodes = this.retryConfig.retryableStatusCodes;
    if (!retryableCodes || retryableCodes.length === 0) {
      // Default retryable codes
      return (
        statusCode === 429 ||
        statusCode === 500 ||
        statusCode === 502 ||
        statusCode === 503 ||
        statusCode === 504
      );
    }

    return retryableCodes.includes(statusCode);
  }

  /**
   * Calculates the backoff duration for a retry attempt.
   */
  private calculateBackoffMs(attempt: number): number {
    if (!this.retryConfig) {
      return 0;
    }
    let backoffMs =
      (this.retryConfig.initialBackoffMs || 100) *
      Math.pow(this.retryConfig.backoffMultiplier || 2.0, attempt);
    if (backoffMs > (this.retryConfig.maxBackoffMs || 5000)) {
      backoffMs = this.retryConfig.maxBackoffMs || 5000;
    }
    return backoffMs;
  }

  /**
   * Converts an HTTP status code to an appropriate ValidationError.
   * Maps HTTP status codes to gRPC status codes via helper functions:
   * - 401/403 -> newErrUnauthorized (UNAUTHENTICATED)
   * - 404 -> newErrNotFound (NOT_FOUND)
   * - 400-499 -> newErrMissingInvalidData (INVALID_ARGUMENT)
   * - 500+ -> newErrGeneral (INTERNAL)
   */
  private statusCodeToException(statusCode: number): ValidationError {
    const message = `HTTP ${statusCode}`;
    if (statusCode === 401 || statusCode === 403) {
      return newErrUnauthorized(undefined, message);
    }
    if (statusCode === 404) {
      return newErrNotFound(message);
    }
    if (statusCode >= 400 && statusCode < 500) {
      return newErrMissingInvalidData(undefined, message);
    }
    // 500+
    return newErrGeneral(undefined, message);
  }

  /**
   * Performs an HTTP request.
   */
  private async request(
    method: string,
    url: string,
    dataBytes: Buffer | null,
  ): Promise<{ statusCode: number; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const isHttps = urlObj.protocol === "https:";
      const client = isHttps ? https : http;
      const agent = isHttps ? this.httpsAgent : this.httpAgent;

      const headers: http.OutgoingHttpHeaders = {};

      if (dataBytes && dataBytes.length > 0) {
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = dataBytes.length;
      }

      const options: http.RequestOptions = {
        method,
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname + urlObj.search,
        headers,
        agent,
        timeout: this.timeoutMs || undefined,
      };

      const req = client.request(options, (res) => {
        const chunks: Buffer[] = [];

        res.on("data", (chunk) => {
          chunks.push(chunk);
        });

        res.on("end", () => {
          const body = Buffer.concat(chunks);
          resolve({
            statusCode: res.statusCode || 0,
            body,
          });
        });
      });

      req.on("error", (error) => {
        reject(error);
      });

      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Request timeout"));
      });

      if (dataBytes && dataBytes.length > 0) {
        req.write(dataBytes);
      }

      req.end();
    });
  }

  /**
   * Sleep for the specified number of milliseconds.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
