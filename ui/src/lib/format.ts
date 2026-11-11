import type { Filter, Severity, Target, Vuln } from './types';

export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];
export const sevRank = (s: Severity | null | undefined) => (s ? SEVERITIES.indexOf(s) + 1 : 0);
export const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export function score(v: Pick<Vuln, 'cvss'>): string {
  return v.cvss == null ? '–' : v.cvss.toFixed(1);
}

export function pct(p: number | null | undefined): string {
  if (p == null) return '';
  const x = p * 100;
  return (x >= 10 ? x.toFixed(0) : x >= 1 ? x.toFixed(1).replace(/\.0$/, '') : x.toFixed(2)) + '%';
}

export function date(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(+d)) return '';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const s = (Date.now() - +new Date(iso)) / 1000;
  if (isNaN(s)) return '';
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 14) return `${Math.floor(s / 86400)} d ago`;
  return date(iso);
}

export function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const days = Math.round((+new Date(today.toDateString()) - +new Date(d.toDateString())) / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
}

export const pretty = (s: string) => s.replace(/\\/g, '').replace(/_/g, ' ');

export function targetPath(t: Target): string {
  const e = encodeURIComponent;
  switch (t.kind) {
    case 'product':
      return `/p/${e(t.vendor)}/${e(t.product)}`;
    case 'vendor':
      return `/vendor/${e(t.vendor)}`;
    case 'package':
      return `/pkg/${e(t.ecosystem)}/${e(t.name)}`;
    case 'keyword':
      return `/k/${e(t.keywords.join(','))}`;
    case 'everything':
      return '/latest';
  }
}

export function targetLabel(t: Target): string {
  switch (t.kind) {
    case 'product':
      return `Product · ${pretty(t.vendor)} / ${pretty(t.product)}`;
    case 'vendor':
      return `Vendor · ${pretty(t.vendor)}`;
    case 'package':
      return `Package · ${t.ecosystem} / ${t.name}`;
    case 'keyword':
      return `Keyword · ${t.keywords.join(', ')}`;
    case 'everything':
      return 'All vulnerabilities';
  }
}

/** A filter in one readable line, e.g. "High or worse · exploited only". */
export function filterLabel(f: Filter): string {
  const parts: string[] = [];
  if (f.exploited_only) parts.push('Known exploited only');
  if (f.min_severity) parts.push(f.min_severity === 'critical' ? 'Critical only' : `${cap(f.min_severity)} or worse`);
  if (f.attack_vectors.length) parts.push(f.attack_vectors.map(cap).join('/') + ' attacks');
  if (f.min_cvss) parts.push(`CVSS ≥ ${f.min_cvss.toFixed(1)}`);
  if (f.min_epss) parts.push(`EPSS ≥ ${pct(f.min_epss)}`);
  if (f.include_keywords.length) parts.push(`mentions ${f.include_keywords.join(' or ')}`);
  if (f.exclude_keywords.length) parts.push(`not ${f.exclude_keywords.join(', ')}`);
  if (!parts.length) return 'Every vulnerability';
  if ((f.min_severity || f.min_cvss || f.min_epss || f.attack_vectors.length) && !f.include_unscored) parts.push('scored only');
  return parts.join(' · ');
}

export function partLabel(part: string): string {
  return part === 'o' ? 'Operating system' : part === 'h' ? 'Hardware' : 'Software';
}
