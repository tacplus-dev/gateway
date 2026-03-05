// Copyright (c) 2024 Second Star Cavalier, LLC.

import winston from "winston";
import { LoggerConfig } from "./LoggerConfigHelper.js";
import * as LogLevel from "./LogLevel.js";
import * as LogFormat from "./LogFormat.js";

/**
 * Programmatic configurator for Winston.
 *
 * This module provides methods to configure Winston programmatically
 * based on a protobuf LoggerConfig message.
 */

/**
 * Installs a Winston logger configuration based on the provided LoggerConfig.
 *
 * This method configures Winston with:
 * - Log level from config
 * - Output format (JSON or console pattern)
 * - Output paths (stdout, stderr, or file paths)
 * - Initial fields as default metadata
 *
 * @param config the LoggerConfig configuration
 * @returns a configured Winston logger instance
 */
export function install(config?: LoggerConfig): winston.Logger {
  // Use default config if null
  if (!config) {
    config = {};
  }

  // Determine log level
  const level = config.level ? LogLevel.toWinstonLevel(config.level) : "info";

  // Create format based on configuration
  const format = createFormat(config);

  // Configure transports based on output paths
  const transports = createTransports(config, format);

  // Create logger with configuration
  const logger = winston.createLogger({
    level,
    format,
    transports,
    defaultMeta: config.initialFields || {},
  });

  return logger;
}

/**
 * Creates a Winston format based on the LoggerConfig.
 */
function createFormat(config: LoggerConfig): winston.Logform.Format {
  const formats: winston.Logform.Format[] = [];

  // Add timestamp
  formats.push(winston.format.timestamp());

  // Add errors format for stack traces
  if (!config.disableStacktrace) {
    formats.push(winston.format.errors({ stack: true }));
  }

  // Choose output format
  if (config.format === LogFormat.Format.FORMAT_CONSOLE) {
    // Console format: human-readable
    if (config.prettyPrint) {
      formats.push(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length
            ? ` ${JSON.stringify(meta)}`
            : "";
          return `${timestamp} [${level}]: ${message}${metaStr}`;
        }),
      );
    } else {
      formats.push(
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length
            ? ` ${JSON.stringify(meta)}`
            : "";
          return `${timestamp} ${level}: ${message}${metaStr}`;
        }),
      );
    }
  } else {
    // JSON format: structured
    if (config.prettyPrint) {
      formats.push(winston.format.json({ space: 2 }));
    } else {
      formats.push(winston.format.json());
    }
  }

  return winston.format.combine(...formats);
}

/**
 * Creates Winston transports based on the LoggerConfig output paths.
 */
function createTransports(
  config: LoggerConfig,
  format: winston.Logform.Format,
): winston.transport[] {
  const transports: winston.transport[] = [];

  // If no output paths specified, default to stderr
  const outputPaths = config.outputPaths || ["stderr"];

  // Configure transports for each output path
  for (const outputPath of outputPaths) {
    if (outputPath.toLowerCase() === "stdout") {
      transports.push(
        new winston.transports.Console({
          format,
          stderrLevels: [], // stdout only
        }),
      );
    } else if (outputPath.toLowerCase() === "stderr") {
      transports.push(
        new winston.transports.Console({
          format,
          stderrLevels: ["error", "warn", "info", "debug"], // all to stderr
        }),
      );
    } else {
      // File transport
      transports.push(
        new winston.transports.File({
          filename: outputPath,
          format,
        }),
      );
    }
  }

  // Configure error output paths if specified
  if (config.errorOutputPaths && config.errorOutputPaths.length > 0) {
    for (const errorPath of config.errorOutputPaths) {
      if (errorPath.toLowerCase() === "stderr") {
        // Already handled above
        continue;
      } else if (errorPath.toLowerCase() === "stdout") {
        transports.push(
          new winston.transports.Console({
            level: "error",
            format,
            stderrLevels: [],
          }),
        );
      } else {
        // Error file transport
        transports.push(
          new winston.transports.File({
            filename: errorPath,
            level: "error",
            format,
          }),
        );
      }
    }
  }

  return transports;
}

/**
 * Creates a default logger with console output.
 *
 * @returns a Winston logger instance with default configuration
 */
export function createDefaultLogger(): winston.Logger {
  return install({
    level: LogLevel.Level.LEVEL_INFO,
    format: LogFormat.Format.FORMAT_CONSOLE,
    outputPaths: ["stderr"],
  });
}
