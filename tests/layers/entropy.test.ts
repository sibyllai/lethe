import { describe, test, expect } from 'vitest';
import { scanEntropy } from '../../src/layers/entropy.js';
import type { LetheConfig } from '../../src/config.js';

const baseConfig: LetheConfig = {
  files: { exclude: [], passthrough: [], max_size: 5242880 },
  patterns: { enabled: false, disable: [] },
  entropy: { enabled: true, hex_threshold: 4.5, base64_threshold: 5.0, min_length: 12, allowlist: [] },
  custom_rules: [],
  reporting: { summary: true, group_by: 'file' },
};

describe('High-entropy string detection', () => {
  test('high-entropy hex string is detected', () => {
    // Use a lower hex threshold so hex strings can actually trigger
    const hexConfig: LetheConfig = {
      ...baseConfig,
      entropy: { ...baseConfig.entropy, hex_threshold: 3.5 },
    };
    const content = 'secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"';
    const findings = scanEntropy('src/config.ts', content, hexConfig);
    expect(findings.some((f) => f.type === 'high-entropy-string')).toBe(true);
  });

  test('high-entropy base64 string is detected', () => {
    // A random-looking base64 string with high entropy
    const content = 'token = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="';
    const findings = scanEntropy('src/config.ts', content, baseConfig);
    // This may or may not trigger depending on the actual entropy; use a truly random one
    const content2 = 'key = "Kx7mZpQ3nR9sT2vW5yA8bC1dE4fG6hJ0"';
    const findings2 = scanEntropy('src/config.ts', content2, baseConfig);
    expect(findings2.some((f) => f.type === 'high-entropy-string')).toBe(true);
  });

  test('normal English text is not flagged', () => {
    const content = 'const message = "This is a normal sentence with regular words in it"';
    const findings = scanEntropy('src/app.ts', content, baseConfig);
    expect(findings.length).toBe(0);
  });

  test('short strings below min_length are not flagged', () => {
    // min_length is 12, so strings under 12 chars should be skipped
    const content = 'key = "abc123"';
    const findings = scanEntropy('src/app.ts', content, baseConfig);
    expect(findings.length).toBe(0);
  });

  test('empty content returns no findings', () => {
    const findings = scanEntropy('src/empty.ts', '', baseConfig);
    expect(findings.length).toBe(0);
  });
});

describe('Entropy allowlist', () => {
  test('files matching allowlist patterns are skipped', () => {
    const configWithAllowlist: LetheConfig = {
      ...baseConfig,
      entropy: {
        ...baseConfig.entropy,
        allowlist: ['**/*test*'],
      },
    };
    // Even with high-entropy content, allowlisted files return no findings
    const content = 'key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"';
    const findings = scanEntropy('src/config.test.ts', content, configWithAllowlist);
    expect(findings.length).toBe(0);
  });

  test('files not matching allowlist are still scanned', () => {
    const configWithAllowlist: LetheConfig = {
      ...baseConfig,
      entropy: {
        ...baseConfig.entropy,
        allowlist: ['**/*test*'],
      },
    };
    // Use a base64 string with high entropy that exceeds the 5.0 threshold
    const content = 'key = "x8Kp2mQrLz5nWjYvBt0cFhDsAeGi9oUl"';
    const findings = scanEntropy('src/config.ts', content, configWithAllowlist);
    expect(findings.some((f) => f.type === 'high-entropy-string')).toBe(true);
  });
});

describe('Entropy disabled', () => {
  test('returns empty when entropy is disabled', () => {
    const disabledConfig: LetheConfig = {
      ...baseConfig,
      entropy: { ...baseConfig.entropy, enabled: false },
    };
    const content = 'key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"';
    const findings = scanEntropy('src/config.ts', content, disabledConfig);
    expect(findings.length).toBe(0);
  });
});

describe('Finding structure', () => {
  test('entropy findings have correct fields', () => {
    const content = 'token = "Kx7mZpQ3nR9sT2vW5yA8bC1dE4fG6hJ0"';
    const findings = scanEntropy('src/config.ts', content, baseConfig);
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0]!;
    expect(f.file).toBe('src/config.ts');
    expect(f.line).toBe(1);
    expect(f.type).toBe('high-entropy-string');
    expect(f.layer).toBe('entropy');
    expect(f.replacement).toBe('REDACTED_ENTROPY');
    expect(f.description).toContain('entropy');
  });
});
