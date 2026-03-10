import * as path from 'node:path';
import fg from 'fast-glob';
import type { LetheConfig } from './config.js';
import {
  type Finding,
  type ScanResult,
  type ScanStats,
  FileAction,
  Severity,
  createEmptyStats,
  severityAtLeast,
} from './models.js';
import { readFileSafe, relPath, isSymlink } from './utils.js';
import {
  loadIgnoreRules,
  shouldIgnore,
  checkFileRules,
  loadPatternCatalog,
  scanPatterns,
  scanEntropy,
  scanCustomRules,
} from './layers/index.js';

export interface ScanOptions {
  noEntropy?: boolean;
  minSeverity?: Severity;
  verbose?: boolean;
  quiet?: boolean;
  onFileStart?: (file: string) => void;
  onFileComplete?: (file: string, findings: Finding[]) => void;
  onProgress?: (scanned: number, total: number) => void;
}

export async function scanRepo(
  root: string,
  config: LetheConfig,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const absRoot = path.resolve(root);
  const stats: ScanStats = createEmptyStats();
  const allFindings: Finding[] = [];

  // Load ignore rules once
  const ignoreFilter = await loadIgnoreRules(absRoot);

  // Load pattern catalog once
  const catalog = config.patterns.enabled ? await loadPatternCatalog() : [];

  // Gather all files using fast-glob
  const files = await fg('**/*', {
    cwd: absRoot,
    dot: true,
    absolute: true,
    onlyFiles: true,
    followSymbolicLinks: false,
  });

  const totalFiles = files.length;

  for (let i = 0; i < totalFiles; i++) {
    const filepath = files[i];
    if (!filepath) continue;
    const rel = relPath(absRoot, filepath);

    // Layer 1: Ignore (.gitignore, .letheignore)
    if (shouldIgnore(rel, ignoreFilter)) {
      stats.filesSkipped++;
      continue;
    }

    // Layer 2: File rules (exclude / passthrough / scan)
    const action = checkFileRules(rel, config);

    if (action === FileAction.EXCLUDE) {
      stats.filesExcluded++;
      continue;
    }

    if (action === FileAction.PASSTHROUGH) {
      stats.filesPassthrough++;
      continue;
    }

    // Skip symlinks to prevent escape attacks
    if (await isSymlink(filepath)) {
      stats.filesSkipped++;
      continue;
    }

    // This file should be scanned
    options.onFileStart?.(rel);

    const content = await readFileSafe(filepath, config.files.max_size);
    if (content === null) {
      stats.filesSkipped++;
      continue;
    }

    stats.filesScanned++;

    const fileFindings: Finding[] = [];

    // Layer 3: Pattern matching
    if (config.patterns.enabled && catalog.length > 0) {
      const patternFindings = scanPatterns(rel, content, config, catalog);
      fileFindings.push(...patternFindings);
    }

    // Layer 4: Entropy detection
    if (config.entropy.enabled && !options.noEntropy) {
      const entropyFindings = scanEntropy(rel, content, config);
      fileFindings.push(...entropyFindings);
    }

    // Layer 5: Custom rules
    if (config.custom_rules.length > 0) {
      const customFindings = scanCustomRules(rel, content, config);
      fileFindings.push(...customFindings);
    }

    // Filter by minimum severity
    const filtered = options.minSeverity
      ? fileFindings.filter((f) =>
          severityAtLeast(f.severity, options.minSeverity!),
        )
      : fileFindings;

    if (filtered.length > 0) {
      stats.filesRedacted++;
      for (const finding of filtered) {
        stats.findingsBySeverity[finding.severity]++;
      }
      allFindings.push(...filtered);
    } else {
      stats.filesClean++;
    }

    options.onFileComplete?.(rel, filtered);
    options.onProgress?.(i + 1, totalFiles);
  }

  return {
    root: absRoot,
    findings: allFindings,
    stats,
  };
}
