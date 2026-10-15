import { spawn } from 'node:child_process';

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function runCommand(
  binary: string,
  args: string[],
  options: { cwd?: string; timeoutMs: number; signal?: AbortSignal },
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`Command timed out: ${binary}`));
    }, options.timeoutMs);
    const onAbort = () => {
      child.kill('SIGTERM');
    };
    options.signal?.addEventListener('abort', onAbort);
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
      if (stdout.length > 20_000_000) child.kill('SIGKILL');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
      if (stderr.length > 2_000_000) stderr = stderr.slice(-2_000_000);
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

export async function commandAvailable(binary: string): Promise<boolean> {
  try {
    const result = await runCommand(binary, ['--version'], { timeoutMs: 15_000 });
    return result.code === 0 || result.stdout.length > 0 || result.stderr.length > 0;
  } catch {
    return false;
  }
}
