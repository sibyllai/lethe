export enum Severity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.LOW]: 0,
  [Severity.MEDIUM]: 1,
  [Severity.HIGH]: 2,
  [Severity.CRITICAL]: 3,
};

export enum FileAction {
  SCAN = 'scan',
  EXCLUDE = 'exclude',
  PASSTHROUGH = 'passthrough',
}

export interface Finding {
  file: string;
  line?: number;
  column?: number;
  endColumn?: number;
  type: string;
  severity: Severity;
  description?: string;
  match?: string;
  replacement?: string;
  layer: 'file_rule' | 'pattern' | 'entropy' | 'custom';
}

export interface ScanResult {
  root: string;
  findings: Finding[];
  stats: ScanStats;
}

export interface ScanStats {
  filesScanned: number;
  filesSkipped: number;
  filesExcluded: number;
  filesPassthrough: number;
  filesClean: number;
  filesRedacted: number;
  findingsBySeverity: Record<Severity, number>;
}

export interface PatternDefinition {
  id: string;
  name: string;
  pattern: string;
  severity: Severity;
  replacement: string;
  description: string;
}

export interface CustomRule {
  name: string;
  pattern: string;
  replacement: string;
  severity: Severity;
  description?: string;
}

export function createEmptyStats(): ScanStats {
  return {
    filesScanned: 0,
    filesSkipped: 0,
    filesExcluded: 0,
    filesPassthrough: 0,
    filesClean: 0,
    filesRedacted: 0,
    findingsBySeverity: {
      [Severity.LOW]: 0,
      [Severity.MEDIUM]: 0,
      [Severity.HIGH]: 0,
      [Severity.CRITICAL]: 0,
    },
  };
}

export function severityAtLeast(severity: Severity, minimum: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum];
}
