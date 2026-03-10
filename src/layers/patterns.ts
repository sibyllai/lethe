import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import type { Finding, PatternDefinition } from '../models.js';
import { Severity } from '../models.js';
import type { LetheConfig } from '../config.js';

interface PatternCatalogFile {
  version: string;
  patterns: Array<{
    id: string;
    name: string;
    pattern: string;
    severity: string;
    replacement: string;
    description: string;
  }>;
}

/**
 * Load the built-in pattern catalog from the YAML file shipped with the package.
 */
export async function loadPatternCatalog(): Promise<PatternDefinition[]> {
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = path.dirname(thisFile);

  // Try sibling catalog/ first (works in src/), then fall back to src/catalog/
  // relative to the project root (works when running from dist/).
  let catalogPath = path.resolve(thisDir, '..', 'catalog', 'patterns.yaml');
  try {
    await fs.access(catalogPath);
  } catch {
    // Running from dist/ — resolve relative to project root
    const projectRoot = path.resolve(thisDir, '..', '..');
    catalogPath = path.resolve(projectRoot, 'src', 'catalog', 'patterns.yaml');
  }

  const raw = await fs.readFile(catalogPath, 'utf-8');
  const parsed = yaml.load(raw) as PatternCatalogFile;

  if (!parsed || !Array.isArray(parsed.patterns)) {
    return [];
  }

  return parsed.patterns.map((p) => ({
    id: p.id,
    name: p.name,
    pattern: p.pattern,
    severity: p.severity as Severity,
    replacement: p.replacement,
    description: p.description,
  }));
}

/**
 * Scan file content against the pattern catalog.
 * Returns findings for each line/pattern match.
 * Patterns listed in config.patterns.disable are skipped.
 */
export function scanPatterns(
  rel: string,
  content: string,
  config: LetheConfig,
  catalog: PatternDefinition[],
): Finding[] {
  if (!config.patterns.enabled) return [];

  const disabledSet = new Set(config.patterns.disable);
  const activePatterns = catalog.filter((p) => !disabledSet.has(p.id));

  // Pre-compile regexes. Patterns may use (?i) inline flag syntax —
  // JavaScript doesn't support inline flags, so we detect and convert them.
  const compiled: Array<{ def: PatternDefinition; regex: RegExp }> = [];
  for (const def of activePatterns) {
    try {
      let flags = 'g';
      let patternStr = def.pattern;

      // Handle (?i) case-insensitive inline flag
      if (patternStr.startsWith('(?i)')) {
        flags = 'gi';
        patternStr = patternStr.slice(4);
      }

      compiled.push({ def, regex: new RegExp(patternStr, flags) });
    } catch {
      // Skip patterns with invalid regex syntax
    }
  }

  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;

    for (const { def, regex } of compiled) {
      // Reset lastIndex for each line since we reuse the regex
      regex.lastIndex = 0;

      let regexMatch = regex.exec(line);
      while (regexMatch !== null) {
        // When a capture group exists, target only the captured secret value
        // so the surrounding assignment context (variable name, operator) is preserved.
        let matchColumn: number;
        let matchLength: number;
        let matchText: string;

        if (regexMatch[1] !== undefined) {
          const captureOffset = regexMatch[0].indexOf(regexMatch[1]);
          matchColumn = regexMatch.index + captureOffset + 1;
          matchLength = regexMatch[1].length;
          matchText = regexMatch[1];
        } else {
          matchColumn = regexMatch.index + 1;
          matchLength = regexMatch[0].length;
          matchText = regexMatch[0];
        }

        findings.push({
          file: rel,
          line: lineIdx + 1,
          column: matchColumn,
          endColumn: matchColumn + matchLength,
          type: def.id,
          severity: def.severity,
          description: def.description,
          match: matchText,
          replacement: def.replacement,
          layer: 'pattern',
        });

        // Prevent infinite loop on zero-length matches
        if (regexMatch[0].length === 0) {
          regex.lastIndex++;
        }

        regexMatch = regex.exec(line);
      }
    }
  }

  return findings;
}
