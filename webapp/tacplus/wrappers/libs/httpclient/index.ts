// Copyright (c) 2024 Second Star Cavalier, LLC.

/**
 * HTTP Client Library
 *
 * A typed HTTP client library with retry logic, designed to serve as the static
 * infrastructure for compiler-generated HTTP client methods.
 */

export { TypedClient } from "./TypedClient.js";
export { Adapter } from "./Adapter.js";
export { ValidationError } from "johnnycash-tacplus-spec/errors.js";
export type {
  HttpClientConfig,
  RetryConfig,
  X509Cert,
  X509CertPair,
} from "./TypedClient.js";
