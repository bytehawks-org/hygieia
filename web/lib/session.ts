// The credential lives in sessionStorage: it dies with the tab and is never written to disk by the app.
// (An XSS would still be able to read it; the UI is served with a hash-based CSP without 'unsafe-inline'
// scripts, and renders API data only through React's escaping.)
const KEY = 'hygeia.session';
const TENANT = 'hygeia.tenant';

export interface Session {
  token: string;
  kind: 'token' | 'oidc';
  /** unix seconds; OIDC id_token expiry (tokens pasted by hand have none) */
  expiresAt?: number;
}

const ss = (): Storage | null => {
  try { return typeof window === 'undefined' ? null : window.sessionStorage; } catch { return null; }
};

export function loadSession(): Session | null {
  try {
    const raw = ss()?.getItem(KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    if (typeof s.token !== 'string' || !s.token) return null;
    if (s.expiresAt && s.expiresAt * 1000 < Date.now()) { clearSession(); return null; }
    return s;
  } catch { return null; }
}
export function saveSession(s: Session) { ss()?.setItem(KEY, JSON.stringify(s)); }
export function clearSession() { ss()?.removeItem(KEY); ss()?.removeItem(TENANT); }
export const loadTenant = () => ss()?.getItem(TENANT) ?? null;
export const saveTenant = (id: string) => ss()?.setItem(TENANT, id);
