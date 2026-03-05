// Copyright (c) 2024 Second Star Cavalier, LLC.

/**
 * Constants used for logger configuration.
 *
 * This class defines environment variable names and default values
 * used throughout the logger library.
 */

const KIND_PREPEND = "Cavalier";

/**
 * Environment variable name for configuring the log level.
 * Set this to one of: trace, debug, info, warn, error.
 *
 * Example: export CavalierLogLevel=debug
 */
export const LOG_LEVEL_ENV_VAR = `${KIND_PREPEND}LogLevel`;

/**
 * Environment variable name for configuring the log format.
 * Set this to one of: json, console.
 *
 * Example: export CavalierLogFormat=console
 */
export const LOG_FORMAT_ENV_VAR = `${KIND_PREPEND}LogFormat`;

/**
 * Default time format used for formatting log timestamps.
 * Format: "YYYY-MM-DD HH:mm:ss"
 */
export const DEFAULT_TIME_FORMAT = "YYYY-MM-DD HH:mm:ss";
