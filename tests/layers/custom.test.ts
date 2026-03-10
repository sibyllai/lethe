import { describe, test, expect } from 'vitest';
import { scanCustomRules } from '../../src/layers/custom.js';
import { Severity } from '../../src/models.js';
import type { LetheConfig } from '../../src/config.js';

const baseConfig: LetheConfig = {
  files: { exclude: [], passthrough: [], max_size: 5242880 },
  patterns: { enabled: false, disable: [] },
  entropy: { enabled: false, hex_threshold: 4.5, base64_threshold: 5.0, min_length: 12, allowlist: [] },
  custom_rules: [],
  reporting: { summary: true, group_by: 'file' },
};

describe('Custom rule matching', () => {
  test('matches internal hostnames', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'internal_host',
          pattern: '[a-zA-Z0-9-]+\\.internal\\.example\\.org',
          replacement: '[REDACTED:internal_host]',
          severity: Severity.HIGH,
          description: 'Internal hostnames',
        },
      ],
    };

    const content = 'const host = "api-server.internal.example.org";';
    const findings = scanCustomRules('src/config.ts', content, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.type).toBe('custom:internal_host');
    expect(findings[0]!.match).toBe('api-server.internal.example.org');
    expect(findings[0]!.replacement).toBe('[REDACTED:internal_host]');
  });

  test('matches organization email addresses', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'org_email',
          pattern: '[a-zA-Z0-9._%+-]+@acme\\.corp',
          replacement: '[REDACTED:email]',
          severity: Severity.MEDIUM,
          description: 'Organization email addresses',
        },
      ],
    };

    const content = 'contact: alice.smith@acme.corp';
    const findings = scanCustomRules('config.yaml', content, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.type).toBe('custom:org_email');
    expect(findings[0]!.match).toBe('alice.smith@acme.corp');
  });

  test('non-matching content returns no findings', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'internal_host',
          pattern: '[a-zA-Z0-9-]+\\.internal\\.example\\.org',
          replacement: '[REDACTED:internal_host]',
          severity: Severity.HIGH,
        },
      ],
    };

    const content = 'const host = "api.public.example.com";';
    const findings = scanCustomRules('src/config.ts', content, config);
    expect(findings.length).toBe(0);
  });

  test('no custom rules returns empty findings', () => {
    const findings = scanCustomRules('src/config.ts', 'any content', baseConfig);
    expect(findings.length).toBe(0);
  });

  test('multiple matches on same line', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'org_email',
          pattern: '[a-zA-Z0-9._%+-]+@acme\\.corp',
          replacement: '[REDACTED:email]',
          severity: Severity.MEDIUM,
        },
      ],
    };

    const content = 'cc: bob@acme.corp, alice@acme.corp';
    const findings = scanCustomRules('config.yaml', content, config);
    expect(findings.length).toBe(2);
  });

  test('findings have correct layer', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'test_rule',
          pattern: 'MATCH_ME',
          replacement: '[REDACTED]',
          severity: Severity.LOW,
        },
      ],
    };

    const findings = scanCustomRules('test.ts', 'MATCH_ME here', config);
    expect(findings.length).toBe(1);
    expect(findings[0]!.layer).toBe('custom');
    expect(findings[0]!.severity).toBe(Severity.LOW);
  });

  test('case-insensitive flag works', () => {
    const config: LetheConfig = {
      ...baseConfig,
      custom_rules: [
        {
          name: 'ci_rule',
          pattern: '(?i)secret_value',
          replacement: '[REDACTED]',
          severity: Severity.HIGH,
        },
      ],
    };

    const findings = scanCustomRules('test.ts', 'SECRET_VALUE here', config);
    expect(findings.length).toBe(1);
  });
});
