import * as path from 'path';

const ENTITIES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, c => ENTITIES[c]);
}

export function safeUrl(value: string | undefined): string | null {
  return value && /^https:\/\//.test(value) ? escapeHtml(value) : null;
}

/** Results written before 1.3.0 hold the absolute path of the machine that ran the scan: never show one. */
export function shownPath(projectPath: string | undefined): string | undefined {
  if (!projectPath || path.posix.isAbsolute(projectPath) || path.win32.isAbsolute(projectPath)) return undefined;
  return projectPath;
}
