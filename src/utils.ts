import * as fs from 'node:fs/promises';
import * as path from 'node:path';

/**
 * Calculate Shannon entropy of a string.
 */
export function shannonEntropy(data: string): number {
  if (!data || data.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of data) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  const len = data.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Determine the character set of a string for entropy threshold selection.
 */
export function detectCharset(data: string): 'hex' | 'base64' | 'general' {
  if (/^[0-9a-fA-F]+$/.test(data)) return 'hex';
  if (/^[A-Za-z0-9+/=]+$/.test(data)) return 'base64';
  return 'general';
}

/**
 * Check if a file is likely binary by reading its first 8KB and checking for null bytes.
 */
export async function isBinaryFile(filepath: string): Promise<boolean> {
  const handle = await fs.open(filepath, 'r');
  try {
    const buf = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buf, 0, 8192, 0);
    for (let i = 0; i < bytesRead; i++) {
      if (buf[i] === 0) return true;
    }
    return false;
  } finally {
    await handle.close();
  }
}

/**
 * Read a file safely, returning null if it's binary or exceeds maxSize.
 */
export async function readFileSafe(
  filepath: string,
  maxSize: number,
): Promise<string | null> {
  const stat = await fs.stat(filepath);
  if (stat.size > maxSize) return null;
  if (await isBinaryFile(filepath)) return null;
  return fs.readFile(filepath, 'utf-8');
}

/**
 * Ensure a directory exists, creating it recursively if needed.
 */
export async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

/**
 * Get the relative path from root, normalized to forward slashes.
 */
export function relPath(root: string, filepath: string): string {
  return path.relative(root, filepath).split(path.sep).join('/');
}

/**
 * Mask a string for display in reports — show only a short prefix.
 * Never reveals trailing characters to avoid leaking key material.
 */
export function maskValue(value: string): string {
  if (value.length <= 8) return '****';
  return `${value.slice(0, 3)}...****`;
}

/**
 * Test a regex for catastrophic backtracking risk by running it against
 * a canary string with a short timeout. Returns true if the regex is safe.
 */
export function isRegexSafe(pattern: string, flags: string): boolean {
  try {
    const regex = new RegExp(pattern, flags);
    // Test against a string designed to trigger common backtracking patterns:
    // long repeated characters followed by a non-matching terminator
    const canary = 'a'.repeat(50) + '!';
    const start = performance.now();
    regex.test(canary);
    const elapsed = performance.now() - start;
    // If a simple 51-char string takes more than 50ms, the pattern is suspect
    if (elapsed > 50) return false;

    // Second canary: alternating characters
    const canary2 = 'aAbBcCdD'.repeat(25) + '!';
    const start2 = performance.now();
    regex.test(canary2);
    const elapsed2 = performance.now() - start2;
    return elapsed2 <= 50;
  } catch {
    return false;
  }
}

/**
 * Check that an output path is contained within the expected output directory.
 * Prevents path traversal via ../ segments in relative paths.
 */
export function assertPathContained(outPath: string, outputDir: string): void {
  const resolved = path.resolve(outPath);
  const container = path.resolve(outputDir) + path.sep;
  if (!resolved.startsWith(container) && resolved !== path.resolve(outputDir)) {
    throw new Error(
      `Path traversal detected: ${outPath} escapes output directory ${outputDir}`,
    );
  }
}

/**
 * Check if a path is a symlink. Returns true if it is.
 */
export async function isSymlink(filepath: string): Promise<boolean> {
  const stat = await fs.lstat(filepath);
  return stat.isSymbolicLink();
}
