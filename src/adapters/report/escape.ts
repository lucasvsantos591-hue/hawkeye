const ENTITIES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, c => ENTITIES[c]);
}

export function safeUrl(value: string | undefined): string | null {
  return value && /^https:\/\//.test(value) ? escapeHtml(value) : null;
}
