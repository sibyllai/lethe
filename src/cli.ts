#!/usr/bin/env node

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as process from 'node:process';
import { Command } from 'commander';
import chalk from 'chalk';
import { VERSION } from './index.js';
import { loadConfig, generateDefaultConfig } from './config.js';
import type { LetheConfig } from './config.js';
import { Severity } from './models.js';
import type { Finding, ScanResult, ScanStats } from './models.js';
import { scanRepo } from './scanner.js';
import type { ScanOptions } from './scanner.js';
import { writeRedactedOutput } from './redactor.js';
import { maskValue } from './utils.js';

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  [Severity.LOW]: chalk.dim,
  [Severity.MEDIUM]: chalk.yellow,
  [Severity.HIGH]: chalk.red,
  [Severity.CRITICAL]: chalk.bgRed.white.bold,
};

function severityTag(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(8);
  return SEVERITY_COLORS[severity](`[${label}]`);
}

function formatFindingsReport(findings: Finding[], groupBy: 'file' | 'type'): string {
  if (findings.length === 0) {
    return chalk.green('No findings detected.');
  }

  const lines: string[] = [];

  if (groupBy === 'file') {
    // Group findings by file
    const byFile = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = byFile.get(f.file);
      if (existing) {
        existing.push(f);
      } else {
        byFile.set(f.file, [f]);
      }
    }

    for (const [file, fileFindings] of byFile) {
      lines.push('');
      lines.push(chalk.underline(file));
      for (const f of fileFindings) {
        const loc = f.line ? `:${f.line}` : '';
        lines.push(`  ${severityTag(f.severity)} ${file}${loc} ${chalk.dim('\u2014')} ${f.type}`);
        if (f.match) {
          lines.push(`    ${chalk.dim(maskValue(f.match))}`);
        }
        if (f.description) {
          lines.push(`    ${chalk.dim(f.description)}`);
        }
      }
    }
  } else {
    // Group by type
    const byType = new Map<string, Finding[]>();
    for (const f of findings) {
      const existing = byType.get(f.type);
      if (existing) {
        existing.push(f);
      } else {
        byType.set(f.type, [f]);
      }
    }

    for (const [type, typeFindings] of byType) {
      lines.push('');
      lines.push(chalk.underline(type) + chalk.dim(` (${typeFindings.length})`));
      for (const f of typeFindings) {
        const loc = f.line ? `:${f.line}` : '';
        lines.push(`  ${severityTag(f.severity)} ${f.file}${loc}`);
        if (f.match) {
          lines.push(`    ${chalk.dim(maskValue(f.match))}`);
        }
      }
    }
  }

  return lines.join('\n');
}

function formatSummary(stats: ScanStats, mode: 'scan' | 'audit' = 'scan'): string {
  const lines: string[] = [];
  const affectedLabel = mode === 'audit' ? 'Files with findings' : 'Files redacted';

  lines.push('');
  lines.push(chalk.bold('Summary'));
  lines.push(chalk.dim('\u2500'.repeat(40)));
  lines.push(`  Files scanned:     ${stats.filesScanned}`);
  lines.push(`  Files skipped:     ${stats.filesSkipped}`);
  lines.push(`  Files excluded:    ${stats.filesExcluded}`);
  lines.push(`  Files passthrough: ${stats.filesPassthrough}`);
  lines.push(`  Files clean:       ${stats.filesClean}`);
  lines.push(`  ${affectedLabel.padEnd(17)}${stats.filesRedacted}`);
  lines.push('');

  const totalFindings = Object.values(stats.findingsBySeverity).reduce((a, b) => a + b, 0);
  lines.push(`  Total findings:    ${totalFindings}`);

  if (totalFindings > 0) {
    const severities: Severity[] = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW];
    for (const sev of severities) {
      const count = stats.findingsBySeverity[sev];
      if (count > 0) {
        lines.push(`    ${SEVERITY_COLORS[sev](sev.toUpperCase().padEnd(8))}: ${count}`);
      }
    }
  }

  return lines.join('\n');
}

function parseSeverity(value: string): Severity {
  const lower = value.toLowerCase();
  const valid: Record<string, Severity> = {
    low: Severity.LOW,
    medium: Severity.MEDIUM,
    high: Severity.HIGH,
    critical: Severity.CRITICAL,
  };
  const result = valid[lower];
  if (!result) {
    throw new Error(`Invalid severity: ${value}. Must be one of: low, medium, high, critical`);
  }
  return result;
}

/**
 * Produce a sanitized copy of a ScanResult for JSON output.
 * Replaces the full `match` field with a masked version to prevent
 * the report itself from leaking the secrets it detected.
 */
function sanitizeResultForOutput(result: ScanResult): ScanResult {
  return {
    ...result,
    findings: result.findings.map((f) => ({
      ...f,
      match: f.match ? maskValue(f.match) : undefined,
    })),
  };
}

// ---------------------------------------------------------------------------
// CLI program
// ---------------------------------------------------------------------------

const program = new Command();

program
  .name('lethe')
  .description('Pre-AI repo sanitization \u2014 redact secrets before your code meets the LLM')
  .version(VERSION);

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------
program
  .command('scan')
  .description('Scan and redact secrets from files')
  .argument('<paths...>', 'Paths to scan')
  .option('-o, --output <dir>', 'Output directory for redacted files')
  .option('-c, --config <path>', 'Path to config file')
  .option('-d, --dry-run', 'Show findings without writing redacted output')
  .option('-f, --format <format>', 'Output format (text, json)', 'text')
  .option('--no-entropy', 'Disable entropy detection')
  .option('-s, --severity <level>', 'Minimum severity level to report', 'low')
  .option('-v, --verbose', 'Verbose output')
  .option('-q, --quiet', 'Suppress all output except errors')
  .action(async (paths: string[], opts: {
    output?: string;
    config?: string;
    dryRun?: boolean;
    format: string;
    entropy: boolean;
    severity: string;
    verbose?: boolean;
    quiet?: boolean;
  }) => {
    try {
      const minSeverity = parseSeverity(opts.severity);

      for (const scanPath of paths) {
        const absPath = path.resolve(scanPath);
        const config: LetheConfig = await loadConfig(absPath, opts.config);

        const scanOptions: ScanOptions = {
          noEntropy: !opts.entropy,
          minSeverity,
          verbose: opts.verbose,
          quiet: opts.quiet,
          onFileStart: opts.verbose && !opts.quiet
            ? (file) => process.stdout.write(chalk.dim(`  scanning ${file}...\r`))
            : undefined,
        };

        if (!opts.quiet) {
          console.log(chalk.bold(`\nScanning ${absPath}...`));
        }

        const result = await scanRepo(absPath, config, scanOptions);

        if (opts.dryRun) {
          // Print findings report
          if (opts.format === 'json') {
            console.log(JSON.stringify(sanitizeResultForOutput(result), null, 2));
          } else {
            console.log(formatFindingsReport(result.findings, config.reporting.group_by));
            if (config.reporting.summary) {
              console.log(formatSummary(result.stats));
            }
          }
        } else {
          // Write redacted output
          const outputDir = opts.output ?? path.join(absPath, '.lethe-out');
          const absOutput = path.resolve(outputDir);

          // Warn if output overlaps with input
          if (absOutput.startsWith(absPath + path.sep) || absOutput === absPath) {
            console.error(chalk.yellow(
              `Warning: output directory is inside the scan path. ` +
              `Subsequent scans may process redacted output.`,
            ));
          }

          if (!opts.quiet) {
            console.log(chalk.dim(`Writing redacted output to ${outputDir}...`));
          }

          await writeRedactedOutput(result, absPath, outputDir, config);

          if (!opts.quiet) {
            if (opts.format === 'json') {
              console.log(JSON.stringify(sanitizeResultForOutput(result), null, 2));
            } else {
              console.log(formatFindingsReport(result.findings, config.reporting.group_by));
              if (config.reporting.summary) {
                console.log(formatSummary(result.stats));
              }
              console.log(chalk.green(`\nRedacted output written to ${outputDir}`));
            }
          }
        }
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(2);
    }
  });

// ---------------------------------------------------------------------------
// audit command
// ---------------------------------------------------------------------------
program
  .command('audit')
  .description('Audit files for secrets (non-destructive, exit code reflects findings)')
  .argument('<paths...>', 'Paths to audit')
  .option('-c, --config <path>', 'Path to config file')
  .option('-f, --format <format>', 'Output format (text, json)', 'text')
  .option('--no-entropy', 'Disable entropy detection')
  .option('-s, --severity <level>', 'Minimum severity level to report', 'low')
  .action(async (paths: string[], opts: {
    config?: string;
    format: string;
    entropy: boolean;
    severity: string;
  }) => {
    try {
      const minSeverity = parseSeverity(opts.severity);
      let totalFindings = 0;

      for (const scanPath of paths) {
        const absPath = path.resolve(scanPath);
        const config: LetheConfig = await loadConfig(absPath, opts.config);

        const scanOptions: ScanOptions = {
          noEntropy: !opts.entropy,
          minSeverity,
        };

        const result = await scanRepo(absPath, config, scanOptions);
        totalFindings += result.findings.length;

        if (opts.format === 'json') {
          console.log(JSON.stringify(sanitizeResultForOutput(result), null, 2));
        } else {
          console.log(formatFindingsReport(result.findings, config.reporting.group_by));
          if (config.reporting.summary) {
            console.log(formatSummary(result.stats, 'audit'));
          }
        }
      }

      process.exit(totalFindings > 0 ? 1 : 0);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(2);
    }
  });

// ---------------------------------------------------------------------------
// init command
// ---------------------------------------------------------------------------
program
  .command('init')
  .description('Create a .lethe.yaml configuration file in the current directory')
  .option('-p, --preset <preset>', 'Config preset (default, strict, minimal)', 'default')
  .option('-f, --force', 'Overwrite existing .lethe.yaml')
  .action(async (opts: { preset: string; force?: boolean }) => {
    try {
      const preset = opts.preset as 'default' | 'strict' | 'minimal';
      if (!['default', 'strict', 'minimal'].includes(preset)) {
        console.error(chalk.red(`Invalid preset: ${opts.preset}. Must be one of: default, strict, minimal`));
        process.exit(2);
      }

      const outputPath = path.join(process.cwd(), '.lethe.yaml');

      if (!opts.force) {
        try {
          await fs.access(outputPath);
          console.error(chalk.yellow('.lethe.yaml already exists. Use --force to overwrite.'));
          process.exit(1);
        } catch {
          // File doesn't exist, proceed
        }
      }

      const content = generateDefaultConfig(preset);
      await fs.writeFile(outputPath, content, 'utf-8');
      console.log(chalk.green(`Created .lethe.yaml with "${preset}" preset.`));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(chalk.red(`Error: ${message}`));
      process.exit(2);
    }
  });

program.parse();
