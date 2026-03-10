import ignore, { type Ignore } from 'ignore';
import { FileAction } from '../models.js';
import type { LetheConfig } from '../config.js';

const createIgnore = ignore as unknown as () => Ignore;

/**
 * Check a file path against the config's exclude and passthrough patterns.
 * Returns the appropriate FileAction:
 *   - EXCLUDE: file matches an exclude pattern (will be blocked entirely)
 *   - PASSTHROUGH: file matches a passthrough pattern (copied without scanning)
 *   - SCAN: file should be scanned for secrets
 */
export function checkFileRules(rel: string, config: LetheConfig): FileAction {
  if (!rel) return FileAction.EXCLUDE;

  const normalized = rel.replace(/^\/+/, '');
  if (!normalized) return FileAction.EXCLUDE;

  // Check exclude patterns first — they take priority
  if (config.files.exclude.length > 0) {
    const excludeFilter = createIgnore().add(config.files.exclude);
    if (excludeFilter.ignores(normalized)) {
      return FileAction.EXCLUDE;
    }
  }

  // Check passthrough patterns
  if (config.files.passthrough.length > 0) {
    const passthroughFilter = createIgnore().add(config.files.passthrough);
    if (passthroughFilter.ignores(normalized)) {
      return FileAction.PASSTHROUGH;
    }
  }

  return FileAction.SCAN;
}
