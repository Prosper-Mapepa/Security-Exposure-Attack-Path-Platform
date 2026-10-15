import { GitleaksAdapter } from './gitleaks';
import { SemgrepAdapter } from './semgrep';
import { TrivyAdapter } from './trivy';
import type { ScannerAdapter, ScannerName } from './types';
import { ZapAdapter } from './zap';

export { runCommand } from './command';
export * from './types';
export * from './normalize';
export * from './semgrep';
export * from './trivy';
export * from './gitleaks';
export * from './zap';

export function createScanner(name: ScannerName): ScannerAdapter {
  switch (name) {
    case 'SEMGREP':
      return new SemgrepAdapter();
    case 'TRIVY':
      return new TrivyAdapter();
    case 'ZAP':
      return new ZapAdapter();
    case 'GITLEAKS':
      return new GitleaksAdapter();
    default: {
      const exhaustive: never = name;
      return exhaustive;
    }
  }
}
