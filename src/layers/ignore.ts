import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import ignore, { type Ignore } from 'ignore';

// Re-export the Ignore type for consumers
export type { Ignore };

/**
 * Load .gitignore and .letheignore rules from the scan root.
 * Returns an Ignore instance that can be used to test paths.
 */
export async function loadIgnoreRules(root: string): Promise<Ignore> {
  const filter = (ignore as unknown as () => Ignore)();

  // Always ignore .git directories
  filter.add('.git');
  filter.add('.git/**');

  const ignoreFiles = ['.gitignore', '.letheignore'];

  for (const name of ignoreFiles) {
    const filepath = path.join(root, name);
    try {
      const content = await fs.readFile(filepath, 'utf-8');
      filter.add(content);
    } catch {
      // File doesn't exist — skip silently
    }
  }

  return filter;
}

/**
 * Check whether a relative path should be ignored based on loaded ignore rules.
 * The path must be relative to the scan root and use forward slashes.
 */
export function shouldIgnore(rel: string, ignoreFilter: Ignore): boolean {
  // Never process empty paths
  if (!rel) return true;

  // The ignore package expects paths without leading slashes
  const normalized = rel.replace(/^\/+/, '');
  if (!normalized) return true;

  return ignoreFilter.ignores(normalized);
}
