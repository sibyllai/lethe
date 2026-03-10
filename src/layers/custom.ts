import type { Finding } from '../models.js';
import type { LetheConfig } from '../config.js';
import { isRegexSafe } from '../utils.js';

/**
 * Scan file content against user-defined custom rules from the config.
 * Each rule specifies a regex pattern, replacement, and severity.
 */
export function scanCustomRules(
  rel: string,
  content: string,
  config: LetheConfig,
): Finding[] {
  if (config.custom_rules.length === 0) return [];

  // Pre-compile all custom rule regexes
  const compiled: Array<{
    name: string;
    regex: RegExp;
    replacement: string;
    severity: (typeof config.custom_rules)[number]['severity'];
    description: string | undefined;
  }> = [];

  for (const rule of config.custom_rules) {
    try {
      let flags = 'g';
      let patternStr = rule.pattern;

      // Handle (?i) case-insensitive inline flag
      if (patternStr.startsWith('(?i)')) {
        flags = 'gi';
        patternStr = patternStr.slice(4);
      }

      if (!isRegexSafe(patternStr, flags)) {
        console.warn(`Warning: custom rule "${rule.name}" rejected — regex may cause catastrophic backtracking`);
        continue;
      }

      compiled.push({
        name: rule.name,
        regex: new RegExp(patternStr, flags),
        replacement: rule.replacement,
        severity: rule.severity,
        description: rule.description,
      });
    } catch {
      console.warn(`Warning: custom rule "${rule.name}" has invalid regex syntax, skipping`);
    }
  }

  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;

    for (const rule of compiled) {
      // Reset lastIndex for each line
      rule.regex.lastIndex = 0;

      let regexMatch = rule.regex.exec(line);
      while (regexMatch !== null) {
        findings.push({
          file: rel,
          line: lineIdx + 1,
          column: regexMatch.index + 1,
          endColumn: regexMatch.index + regexMatch[0].length + 1,
          type: `custom:${rule.name}`,
          severity: rule.severity,
          description: rule.description,
          match: regexMatch[0],
          replacement: rule.replacement,
          layer: 'custom',
        });

        // Prevent infinite loop on zero-length matches
        if (regexMatch[0].length === 0) {
          rule.regex.lastIndex++;
        }

        regexMatch = rule.regex.exec(line);
      }
    }
  }

  return findings;
}
