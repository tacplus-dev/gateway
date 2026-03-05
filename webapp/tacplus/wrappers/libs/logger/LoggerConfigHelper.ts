// Copyright (c) 2024 Second Star Cavalier, LLC.

import * as LogLevel from "./LogLevel.js";
import * as LogFormat from "./LogFormat.js";
import { LOG_LEVEL_ENV_VAR, LOG_FORMAT_ENV_VAR } from "./LoggerConstants.js";

/**
 * Logger configuration interface matching protobuf LoggerConfig.
 */
export interface LoggerConfig {
  name?: string;
  format?: LogFormat.Format;
  level?: LogLevel.Level;
  development?: boolean;
  prettyPrint?: boolean;
  outputPaths?: string[];
  errorOutputPaths?: string[];
  disableCaller?: boolean;
  disableStacktrace?: boolean;
  initialFields?: { [key: string]: string };
}

/**
 * Helper functions for working with LoggerConfig protobuf messages.
 *
 * This module provides utilities for loading configuration from
 * environment variables and converting to environment variable maps.
 */

/**
 * Loads logger configuration from environment variables into the provided config.
 *
 * Environment variables read:
 * - CavalierLogLevel: Log level (trace, debug, info, warn, error)
 * - CavalierLogFormat: Log format (json, console)
 *
 * This function does not check if fields are already set, so it will overwrite
 * existing values if the environment variables are present.
 *
 * @param config the LoggerConfig to populate
 * @throws Error if any environment variable has an invalid value
 */
export function loadFromEnv(config: LoggerConfig): void {
  // Load Level
  const levelValue = process.env[LOG_LEVEL_ENV_VAR];
  if (levelValue && levelValue !== "") {
    try {
      config.level = LogLevel.parse(levelValue);
    } catch (error) {
      throw new Error(
        `Invalid value for env var ${LOG_LEVEL_ENV_VAR}=${levelValue}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  // Load Format
  const formatValue = process.env[LOG_FORMAT_ENV_VAR];
  if (formatValue && formatValue !== "") {
    try {
      config.format = LogFormat.parse(formatValue);
    } catch (error) {
      throw new Error(
        `Invalid value for env var ${LOG_FORMAT_ENV_VAR}=${formatValue}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}

/**
 * Creates a new LoggerConfig with values loaded from environment variables.
 *
 * @returns a new LoggerConfig with environment values
 * @throws Error if any environment variable has an invalid value
 */
export function newConfigFromEnv(): LoggerConfig {
  const config: LoggerConfig = {};
  loadFromEnv(config);
  return config;
}

/**
 * Returns a map of environment variable names to their values based on the LoggerConfig.
 *
 * This is useful for passing logger configuration to child processes or for debugging.
 * Only non-default values are included in the returned map.
 *
 * @param config the LoggerConfig to convert
 * @returns a map of environment variable names to values
 */
export function toEnvVars(config: LoggerConfig): { [key: string]: string } {
  const envVars: { [key: string]: string } = {};

  if (
    config.format !== undefined &&
    config.format !== LogFormat.Format.FORMAT_UNDEFINED
  ) {
    envVars[LOG_FORMAT_ENV_VAR] = LogFormat.toString(config.format);
  }

  if (
    config.level !== undefined &&
    config.level !== LogLevel.Level.LEVEL_UNDEFINED
  ) {
    envVars[LOG_LEVEL_ENV_VAR] = LogLevel.toString(config.level);
  }

  return envVars;
}
