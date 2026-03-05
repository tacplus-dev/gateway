// Copyright (c) 2024 Second Star Cavalier, LLC.

/**
 * Log format enum matching protobuf Format enum.
 */
export enum Format {
  FORMAT_UNDEFINED = 0,
  FORMAT_JSON = 1,
  FORMAT_CONSOLE = 2,
}

/**
 * Utility functions for working with log formats.
 *
 * This module provides parsing and conversion utilities for
 * protobuf Format enums.
 */

/**
 * Parses a string to a protobuf Format enum.
 *
 * @param value the string to parse (case-insensitive)
 * @returns the corresponding Format
 * @throws Error if the string is not a valid format
 */
export function parse(value: string | null | undefined): Format {
  if (!value || value.trim() === "") {
    return Format.FORMAT_UNDEFINED;
  }

  let normalized = value.toUpperCase().trim();

  // Handle shorthands
  switch (normalized) {
    case "JS":
      normalized = "JSON";
      break;
    case "CON":
      normalized = "CONSOLE";
      break;
  }

  switch (normalized) {
    case "JSON":
      return Format.FORMAT_JSON;
    case "CONSOLE":
      return Format.FORMAT_CONSOLE;
    default:
      throw new Error(`Invalid log format: ${value}`);
  }
}

/**
 * Converts a protobuf Format to a lowercase string representation.
 *
 * @param format the protobuf format
 * @returns the string representation (e.g., "json", "console")
 */
export function toString(format: Format): string {
  switch (format) {
    case Format.FORMAT_JSON:
      return "json";
    case Format.FORMAT_CONSOLE:
      return "console";
    default:
      return "";
  }
}
