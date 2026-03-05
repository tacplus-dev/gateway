// Copyright (c) 2024 Second Star Cavalier, LLC.

/**
 * Log level enum matching protobuf Level enum.
 */
export enum Level {
  LEVEL_UNDEFINED = 0,
  LEVEL_TRACE = 1,
  LEVEL_DEBUG = 2,
  LEVEL_INFO = 3,
  LEVEL_WARN = 4,
  LEVEL_ERROR = 5,
}

/**
 * Utility functions for working with log levels.
 *
 * This module provides conversion utilities between protobuf Level enums
 * and common logging library levels, as well as parsing from strings.
 */

/**
 * Parses a string to a protobuf Level enum.
 *
 * @param value the string to parse (case-insensitive)
 * @returns the corresponding Level
 * @throws Error if the string is not a valid level
 */
export function parse(value: string | null | undefined): Level {
  if (!value || value.trim() === "") {
    return Level.LEVEL_UNDEFINED;
  }

  const normalized = value.toUpperCase().trim();

  switch (normalized) {
    case "TRACE":
      return Level.LEVEL_TRACE;
    case "DEBUG":
      return Level.LEVEL_DEBUG;
    case "INFO":
      return Level.LEVEL_INFO;
    case "WARN":
    case "WARNING":
      return Level.LEVEL_WARN;
    case "ERROR":
      return Level.LEVEL_ERROR;
    default:
      throw new Error(`Invalid log level: ${value}`);
  }
}

/**
 * Converts a protobuf Level to a lowercase string representation.
 *
 * @param level the protobuf level
 * @returns the string representation (e.g., "debug", "info", "warn")
 */
export function toString(level: Level): string {
  switch (level) {
    case Level.LEVEL_TRACE:
      return "trace";
    case Level.LEVEL_DEBUG:
      return "debug";
    case Level.LEVEL_INFO:
      return "info";
    case Level.LEVEL_WARN:
      return "warn";
    case Level.LEVEL_ERROR:
      return "error";
    default:
      return "";
  }
}

/**
 * Converts a protobuf Level to Winston level string.
 *
 * @param level the protobuf level
 * @returns the Winston level string
 */
export function toWinstonLevel(level: Level): string {
  switch (level) {
    case Level.LEVEL_TRACE:
    case Level.LEVEL_DEBUG:
      return "debug";
    case Level.LEVEL_INFO:
      return "info";
    case Level.LEVEL_WARN:
      return "warn";
    case Level.LEVEL_ERROR:
      return "error";
    case Level.LEVEL_UNDEFINED:
    default:
      return "info";
  }
}
