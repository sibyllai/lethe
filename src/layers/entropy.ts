import ignore, { type Ignore } from 'ignore';
import type { Finding } from '../models.js';
import { Severity } from '../models.js';
import type { LetheConfig } from '../config.js';
import { shannonEntropy, detectCharset } from '../utils.js';

const createIgnore = ignore as unknown as () => Ignore;

/**
 * Extract potential secret strings from a line of code.
 * Looks for quoted strings and assignment values.
 */
function extractCandidates(line: string): Array<{ value: string; column: number }> {
  const candidates: Array<{ value: string; column: number }> = [];

  // Match double-quoted strings
  const doubleQuoted = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
  let regexMatch = doubleQuoted.exec(line);
  while (regexMatch !== null) {
    if (regexMatch[1]) {
      candidates.push({ value: regexMatch[1], column: regexMatch.index + 2 }); // +2 for opening quote + 1-based
    }
    regexMatch = doubleQuoted.exec(line);
  }

  // Match single-quoted strings
  const singleQuoted = /'([^'\\]*(?:\\.[^'\\]*)*)'/g;
  regexMatch = singleQuoted.exec(line);
  while (regexMatch !== null) {
    if (regexMatch[1]) {
      candidates.push({ value: regexMatch[1], column: regexMatch.index + 2 });
    }
    regexMatch = singleQuoted.exec(line);
  }

  // Match backtick strings (template literals without interpolation)
  const backtickQuoted = /`([^`\\]*(?:\\.[^`\\]*)*)`/g;
  regexMatch = backtickQuoted.exec(line);
  while (regexMatch !== null) {
    if (regexMatch[1]) {
      candidates.push({ value: regexMatch[1], column: regexMatch.index + 2 });
    }
    regexMatch = backtickQuoted.exec(line);
  }

  // Match unquoted assignment values: KEY=VALUE or KEY: VALUE (no quotes)
  const assignmentPattern = /(?:^|[\s;])(?:[\w.-]+)\s*[:=]\s*([^\s"';`#]+)/g;
  regexMatch = assignmentPattern.exec(line);
  while (regexMatch !== null) {
    if (regexMatch[1]) {
      candidates.push({ value: regexMatch[1], column: regexMatch.index + regexMatch[0].length - regexMatch[1].length + 1 });
    }
    regexMatch = assignmentPattern.exec(line);
  }

  return candidates;
}

/**
 * Determine the entropy threshold for a given string based on its character set.
 */
function getThreshold(value: string, config: LetheConfig): number {
  const charset = detectCharset(value);
  switch (charset) {
    case 'hex':
      return config.entropy.hex_threshold;
    case 'base64':
      return config.entropy.base64_threshold;
    case 'general':
      return Math.max(config.entropy.hex_threshold, config.entropy.base64_threshold);
  }
}

/**
 * Scan file content for high-entropy strings that may be secrets.
 * Skips files matching the entropy allowlist patterns.
 */
export function scanEntropy(
  rel: string,
  content: string,
  config: LetheConfig,
): Finding[] {
  if (!config.entropy.enabled) return [];

  // Check if file is in the entropy allowlist
  if (config.entropy.allowlist.length > 0) {
    const allowFilter = createIgnore().add(config.entropy.allowlist);
    const normalized = rel.replace(/^\/+/, '');
    if (normalized && allowFilter.ignores(normalized)) {
      return [];
    }
  }

  const findings: Finding[] = [];
  const lines = content.split('\n');
  const minLength = config.entropy.min_length;

  const MAX_LINE_LENGTH = 10240;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;
    if (line.length > MAX_LINE_LENGTH) continue;
    const lineCandidates = extractCandidates(line);

    for (const candidate of lineCandidates) {
      // Skip strings shorter than the minimum length
      if (candidate.value.length < minLength) continue;

      // Skip strings that are obviously not secrets (pure whitespace, common words, etc.)
      if (/^\s+$/.test(candidate.value)) continue;

      const entropy = shannonEntropy(candidate.value);
      const threshold = getThreshold(candidate.value, config);

      if (entropy >= threshold) {
        findings.push({
          file: rel,
          line: lineIdx + 1,
          column: candidate.column,
          endColumn: candidate.column + candidate.value.length,
          type: 'high-entropy-string',
          severity: Severity.MEDIUM,
          description: `High entropy string detected (${entropy.toFixed(2)} bits, charset: ${detectCharset(candidate.value)}, threshold: ${threshold})`,
          match: candidate.value,
          replacement: 'REDACTED_ENTROPY',
          layer: 'entropy',
        });
      }
    }
  }

  return findings;
}
