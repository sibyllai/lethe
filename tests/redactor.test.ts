import { describe, test, expect } from 'vitest';
import { redactContent } from '../src/redactor.js';
import { Severity } from '../src/models.js';
import type { Finding } from '../src/models.js';

function makeFinding(overrides: Partial<Finding> & { file: string }): Finding {
  return {
    type: 'test',
    severity: Severity.HIGH,
    layer: 'pattern',
    ...overrides,
  };
}

describe('redactContent', () => {
  test('findings are replaced with their replacement strings', () => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const findings: Finding[] = [
      makeFinding({
        file: 'test.ts',
        line: 1,
        column: 14,
        endColumn: 34,
        match: 'AKIAIOSFODNN7EXAMPLE',
        replacement: 'REDACTED_AWS_KEY',
      }),
    ];

    const result = redactContent(content, findings);
    expect(result).toContain('REDACTED_AWS_KEY');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  test('multiple findings on the same line work correctly', () => {
    const content = 'key=SECRET1 token=SECRET2';
    const findings: Finding[] = [
      makeFinding({
        file: 'test.ts',
        line: 1,
        column: 5,
        endColumn: 12,
        match: 'SECRET1',
        replacement: '[R1]',
      }),
      makeFinding({
        file: 'test.ts',
        line: 1,
        column: 19,
        endColumn: 26,
        match: 'SECRET2',
        replacement: '[R2]',
      }),
    ];

    const result = redactContent(content, findings);
    expect(result).toContain('[R1]');
    expect(result).toContain('[R2]');
    expect(result).not.toContain('SECRET1');
    expect(result).not.toContain('SECRET2');
  });

  test('findings on different lines work correctly', () => {
    const content = 'line1: SECRET_A\nline2: SECRET_B\nline3: clean';
    const findings: Finding[] = [
      makeFinding({
        file: 'test.ts',
        line: 1,
        column: 8,
        endColumn: 16,
        match: 'SECRET_A',
        replacement: '[REDACTED_A]',
      }),
      makeFinding({
        file: 'test.ts',
        line: 2,
        column: 8,
        endColumn: 16,
        match: 'SECRET_B',
        replacement: '[REDACTED_B]',
      }),
    ];

    const result = redactContent(content, findings);
    const lines = result.split('\n');
    expect(lines[0]).toContain('[REDACTED_A]');
    expect(lines[1]).toContain('[REDACTED_B]');
    expect(lines[2]).toBe('line3: clean');
  });

  test('content with no findings is unchanged', () => {
    const content = 'const x = 42;\nconst y = "hello";';
    const result = redactContent(content, []);
    expect(result).toBe(content);
  });

  test('findings without line/column are skipped', () => {
    const content = 'const key = "SECRET";';
    const findings: Finding[] = [
      makeFinding({
        file: 'test.ts',
        // No line or column
        match: 'SECRET',
        replacement: '[REDACTED]',
      }),
    ];

    const result = redactContent(content, findings);
    expect(result).toBe(content);
  });

  test('uses default replacement when none specified', () => {
    const content = 'const key = "SECRET_VALUE_HERE";';
    const findings: Finding[] = [
      makeFinding({
        file: 'test.ts',
        line: 1,
        column: 14,
        endColumn: 31,
        match: 'SECRET_VALUE_HERE',
        // No replacement specified
      }),
    ];

    const result = redactContent(content, findings);
    expect(result).toContain('***REDACTED***');
  });
});
