export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type AttackVector = 'network' | 'adjacent' | 'local' | 'physical';

export type Target =
  | { kind: 'product'; vendor: string; product: string; keywords: string[] }
  | { kind: 'vendor'; vendor: string }
  | { kind: 'package'; ecosystem: string; name: string }
  | { kind: 'keyword'; keywords: string[] }
  | { kind: 'everything' };

export interface Filter {
  min_severity: Severity | null;
  min_cvss: number | null;
  include_unscored: boolean;
  attack_vectors: AttackVector[];
  exploited_only: boolean;
  always_if_exploited: boolean;
  min_epss: number | null;
  include_keywords: string[];
  exclude_keywords: string[];
}

export interface Subscription {
  id: number;
  name: string;
  target: Target;
  filter: Filter;
  enabled: boolean;
  notify: boolean;
  created_at?: string | null;
  alerts?: number;
  unread?: number;
}

export interface Vuln {
  id: string;
  aliases: string[];
  sources: string[];
  title: string | null;
  summary: string;
  published: string | null;
  modified: string | null;
  cvss: number | null;
  cvss_version: string | null;
  cvss_origin: string | null;
  vector: string | null;
  severity: Severity | null;
  attack_vector: AttackVector | null;
  exploited: boolean;
  kev_added: string | null;
  epss: number | null;
  epss_percentile: number | null;
  fixed_in: string[];
  status: string | null;
  url: string | null;
  description?: string;
  scores?: { version: string; base: number; vector: string | null; origin: string; source: string | null }[];
  products?: string[];
  cwes?: string[];
  references?: string[];
}

export interface Alert {
  id: number;
  sub_id: number;
  sub_name: string;
  vuln_id: string;
  kind: 'new' | 'exploited';
  created_at: string;
  read: boolean;
  vuln: Vuln;
}

export interface Product {
  part: string;
  vendor: string;
  product: string;
  title: string;
  versions: number;
}

export interface Settings {
  background: 'periodic' | 'realtime' | 'off';
  interval_minutes: number;
  max_age_days: number;
  lookback_days: number;
  nvd_api_key: string;
  use_circl: boolean;
  use_euvd: boolean;
  cvedetails_token: string;
  use_cvelist: boolean;
  use_epss: boolean;
  ntfy: { enabled: boolean; server: string; topic: string; token: string };
  webhook: { enabled: boolean; url: string };
  remote: { enabled: boolean; url: string; token: string };
  theme: 'system' | 'light' | 'dark';
}

export interface Status {
  version: string;
  mobile: boolean;
  remote: boolean;
  unread: number;
  subscriptions: number;
  interval_minutes: number;
  background: string;
  nvd_key: boolean;
  last_check?: string;
  last_ok?: string;
  last_errors?: string[];
  last_new?: number;
  server_version?: string;
}

export const defaultFilter = (): Filter => ({
  min_severity: null,
  min_cvss: null,
  include_unscored: true,
  attack_vectors: [],
  exploited_only: false,
  always_if_exploited: true,
  min_epss: null,
  include_keywords: [],
  exclude_keywords: [],
});
