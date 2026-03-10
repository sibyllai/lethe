import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import fg from 'fast-glob';
import type { LetheConfig } from './config.js';
import { FileAction } from './models.js';
import type { Finding, ScanResult } from './models.js';
import { ensureDir, relPath, assertPathContained, isSymlink } from './utils.js';
import {
  loadIgnoreRules,
  shouldIgnore,
  checkFileRules,
} from './layers/index.js';

interface ResolvedFinding {
  line: number;
  column: number;
  endColumn: number;
  replacement: string;
}

/**
 * Redact content by applying findings in reverse order to preserve positions.
 * Handles overlapping findings by merging them.
 */
export function redactContent(content: string, findings: Finding[]): string {
  if (findings.length === 0) return content;

  // Build resolved findings with concrete positions
  const resolved: ResolvedFinding[] = [];
  for (const f of findings) {
    if (f.line === undefined || f.column === undefined) continue;
    resolved.push({
      line: f.line,
      column: f.column,
      endColumn: f.endColumn ?? f.column + (f.match?.length ?? 0),
      replacement: f.replacement ?? '***REDACTED***',
    });
  }

  if (resolved.length === 0) return content;

  // Sort by line desc, then column desc so we can apply in reverse
  resolved.sort((a, b) => {
    if (a.line !== b.line) return b.line - a.line;
    return b.column - a.column;
  });

  // Merge overlapping findings on the same line
  const merged: ResolvedFinding[] = [];
  let current = resolved[0];
  if (!current) return content;

  for (let i = 1; i < resolved.length; i++) {
    const next = resolved[i];
    if (!next) continue;

    if (next.line === current.line && next.endColumn >= current.column) {
      // Overlapping or adjacent on same line — merge
      current = {
        line: current.line,
        column: Math.min(current.column, next.column),
        endColumn: Math.max(current.endColumn, next.endColumn),
        replacement: current.replacement,
      };
    } else {
      merged.push(current);
      current = next;
    }
  }
  merged.push(current);

  // Apply replacements
  const lines = content.split('\n');

  for (const finding of merged) {
    const lineIdx = finding.line - 1;
    if (lineIdx < 0 || lineIdx >= lines.length) continue;

    const line = lines[lineIdx]!;
    const colStart = finding.column - 1;
    const colEnd = finding.endColumn - 1;

    if (colStart < 0 || colStart > line.length) continue;

    const before = line.slice(0, colStart);
    const after = line.slice(Math.min(colEnd, line.length));
    lines[lineIdx] = before + finding.replacement + after;
  }

  return lines.join('\n');
}

/**
 * Walk the input directory and write redacted output.
 * - Excluded files are omitted from output
 * - Passthrough files are copied as-is
 * - Scanned files have findings applied
 * - Clean files are copied as-is
 */
export async function writeRedactedOutput(
  scanResult: ScanResult,
  inputRoot: string,
  outputDir: string,
  config: LetheConfig,
): Promise<void> {
  const absInput = path.resolve(inputRoot);
  const absOutput = path.resolve(outputDir);

  await ensureDir(absOutput);

  // Group findings by file for quick lookup
  const findingsByFile = new Map<string, Finding[]>();
  for (const finding of scanResult.findings) {
    const existing = findingsByFile.get(finding.file);
    if (existing) {
      existing.push(finding);
    } else {
      findingsByFile.set(finding.file, [finding]);
    }
  }

  // Load ignore rules
  const ignoreFilter = await loadIgnoreRules(absInput);

  // Walk all files
  const files = await fg('**/*', {
    cwd: absInput,
    dot: true,
    absolute: true,
    onlyFiles: true,
    followSymbolicLinks: false,
  });

  for (const filepath of files) {
    const rel = relPath(absInput, filepath);

    // Skip ignored files
    if (shouldIgnore(rel, ignoreFilter)) continue;

    const action = checkFileRules(rel, config);

    // Excluded files are omitted entirely
    if (action === FileAction.EXCLUDE) continue;

    const outPath = path.join(absOutput, rel);

    // Verify output path stays within the output directory
    assertPathContained(outPath, absOutput);

    // Skip symlinks — do not follow them to prevent escape attacks
    if (await isSymlink(filepath)) continue;

    await ensureDir(path.dirname(outPath));

    if (action === FileAction.PASSTHROUGH) {
      // Copy as-is
      await fs.copyFile(filepath, outPath);
      continue;
    }

    // Scan action: check for findings and apply redaction
    const fileFindings = findingsByFile.get(rel);

    if (!fileFindings || fileFindings.length === 0) {
      // Clean file, copy as-is
      await fs.copyFile(filepath, outPath);
      continue;
    }

    // Read and redact
    const content = await fs.readFile(filepath, 'utf-8');
    const redacted = redactContent(content, fileFindings);
    await fs.writeFile(outPath, redacted, 'utf-8');
  }
}
