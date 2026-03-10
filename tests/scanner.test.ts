import { describe, test, expect } from 'vitest';
import * as path from 'node:path';
import { scanRepo } from '../src/scanner.js';
import { loadConfig } from '../src/config.js';

const FIXTURES_DIR = path.resolve(__dirname, 'fixtures');
const REPO_BASIC = path.join(FIXTURES_DIR, 'repo-basic');
const REPO_CLEAN = path.join(FIXTURES_DIR, 'repo-clean');

describe('Integration: scanning repo-basic fixture', () => {
  test('finds expected secrets in repo-basic', async () => {
    const config = await loadConfig(REPO_BASIC);
    // Disable entropy to focus on pattern matching, and use default config
    const result = await scanRepo(REPO_BASIC, config, { noEntropy: true });

    expect(result.findings.length).toBeGreaterThan(0);

    // Should find AWS access key
    const awsKeyFindings = result.findings.filter((f) => f.type === 'aws-access-key-id');
    expect(awsKeyFindings.length).toBeGreaterThan(0);

    // Should find database connection string
    const dbFindings = result.findings.filter(
      (f) => f.type === 'postgres-connection-string' || f.type === 'basic-auth-url',
    );
    expect(dbFindings.length).toBeGreaterThan(0);

    // Should find Stripe key
    const stripeFindings = result.findings.filter((f) => f.type === 'stripe-secret-key');
    expect(stripeFindings.length).toBeGreaterThan(0);
  });

  test('secrets.txt is excluded (matches **/*secret* glob)', async () => {
    const config = await loadConfig(REPO_BASIC);
    const result = await scanRepo(REPO_BASIC, config, { noEntropy: true });

    // secrets.txt should not produce findings because it matches the default
    // exclude glob **/*secret* — simulates .env exclusion without using a real .env
    const secretsFindings = result.findings.filter((f) => f.file === 'secrets.txt');
    expect(secretsFindings.length).toBe(0);

    // Stats should reflect exclusion
    expect(result.stats.filesExcluded).toBeGreaterThan(0);
  });

  test('clean files have no findings', async () => {
    const config = await loadConfig(REPO_BASIC);
    const result = await scanRepo(REPO_BASIC, config, { noEntropy: true });

    // app.ts should be clean
    const appFindings = result.findings.filter((f) => f.file === 'src/app.ts');
    expect(appFindings.length).toBe(0);
  });
});

describe('Integration: scanning repo-clean fixture', () => {
  test('finds nothing in repo-clean', async () => {
    const config = await loadConfig(REPO_CLEAN);
    const result = await scanRepo(REPO_CLEAN, config, { noEntropy: true });

    expect(result.findings.length).toBe(0);
    expect(result.stats.filesClean).toBeGreaterThan(0);
  });
});

describe('Dry-run mode (scan only, no output)', () => {
  test('scanRepo returns findings without writing output', async () => {
    const config = await loadConfig(REPO_BASIC);
    // scanRepo itself is dry-run by nature -- it just returns findings
    // The writeRedactedOutput step is separate
    const result = await scanRepo(REPO_BASIC, config, { noEntropy: true });

    expect(result.root).toBe(path.resolve(REPO_BASIC));
    expect(result.findings).toBeInstanceOf(Array);
    expect(result.stats).toBeDefined();
    expect(result.stats.filesScanned).toBeGreaterThan(0);
  });
});

describe('Scan options', () => {
  test('minSeverity filters findings', async () => {
    const config = await loadConfig(REPO_BASIC);

    // With minimum severity HIGH, medium-severity findings should be excluded
    const resultHigh = await scanRepo(REPO_BASIC, config, {
      noEntropy: true,
      minSeverity: 'high' as any,
    });

    const resultAll = await scanRepo(REPO_BASIC, config, { noEntropy: true });

    // High-severity filter should have fewer or equal findings
    expect(resultHigh.findings.length).toBeLessThanOrEqual(resultAll.findings.length);
  });
});
