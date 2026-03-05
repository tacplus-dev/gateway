// Copyright (c) 2024 Second Star Cavalier, LLC.

import { TypedClient } from "./TypedClient.js";
import { ValidationError } from "johnnycash-tacplus-spec/errors.js";

/**
 * Adapter implements the HTTPClient interface by wrapping a TypedClient.
 * This adapter bridges the generic interface pattern used by generated code
 * with the concrete TypedClient implementation, preventing circular dependencies.
 *
 * Type parameter T represents the proto message type being operated on.
 *
 * Note: This class is designed to implement the generated HTTPClient<T> interface
 * from the proto interfaces. Once that interface is generated, add "implements HTTPClient<T>"
 * to the class signature.
 *
 * @template T the proto message type
 */
export class Adapter<T> {
  private readonly client: TypedClient;

  /**
   * Creates a new adapter that wraps the given TypedClient.
   *
   * Example usage:
   * ```typescript
   * const config = {
   *   timeoutSeconds: 30,
   * };
   * const baseClient = new TypedClient(config);
   * const adapter = new Adapter<LoggerConfig>(baseClient);
   * // Pass adapter to generated client constructor
   * ```
   *
   * @param client a configured TypedClient with retry logic and TLS settings
   */
  constructor(client: TypedClient) {
    this.client = client;
  }

  /**
   * Performs a GET request with retry logic and deserializes the response.
   *
   * @param url full URL for the GET request
   * @param fromBytes function to deserialize response bytes into type T
   * @returns the deserialized response
   * @throws ValidationError if the request fails
   */
  async doGet(url: string, fromBytes: (bytes: Buffer) => T): Promise<T> {
    return this.client.doGet(url, fromBytes);
  }

  /**
   * Performs a POST request with retry logic and deserializes the response.
   *
   * @param url full URL for the POST request
   * @param dataBytes pre-serialized request body bytes (from TypeToJSON)
   * @param fromBytes function to deserialize response bytes into type T
   * @returns the deserialized response
   * @throws ValidationError if the request fails
   */
  async doPostWithResponse(
    url: string,
    dataBytes: Buffer,
    fromBytes: (bytes: Buffer) => T,
  ): Promise<T> {
    return this.client.doPostWithResponse(url, dataBytes, fromBytes);
  }

  /**
   * Performs PUT/PATCH/DELETE requests with retry logic.
   *
   * @param method HTTP method (PUT, PATCH, DELETE)
   * @param url full URL for the request
   * @param dataBytes pre-serialized request body bytes (from TypeToJSON), can be null for DELETE
   * @throws ValidationError if the request fails
   */
  async doMutation(
    method: string,
    url: string,
    dataBytes: Buffer | null,
  ): Promise<void> {
    return this.client.doMutation(method, url, dataBytes);
  }

  /**
   * Returns whether response validation is disabled for this client.
   *
   * When validation is disabled, clients will skip calling Validate{Type} functions
   * on responses from Get and Create operations.
   *
   * @returns true if validation is disabled, false if validation is enabled
   */
  isValidationDisabled(): boolean {
    return this.client.isValidationDisabled();
  }
}
