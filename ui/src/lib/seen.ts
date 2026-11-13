// Vulnerabilities already on screen in a list, kept so that opening one shows something at once
// while its full record loads.
import type { Vuln } from './types';

const seen = new Map<string, Vuln>();

export function remember(v: Vuln) {
  // Re-inserting moves it to the end, so the oldest entries are the first to go.
  seen.delete(v.id);
  seen.set(v.id, v);
  if (seen.size > 400) seen.delete(seen.keys().next().value!);
}

export function recall(id: string): Vuln | null {
  return seen.get(id) ?? seen.get(id.toUpperCase()) ?? null;
}
