// OIDC authorization-code flow with PKCE (public client, no secret). The API validates the resulting ID token
// (signature, issuer, audience, expiry); the checks here only protect the redirect round-trip.
import type { Session } from './session';

const FLOW = 'hygeia.oidc.flow';

interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string }

const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));

export async function challengeFor(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}

async function discover(issuer: string): Promise<Discovery> {
  const r = await fetch(`${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
  if (!r.ok) throw new Error('OIDC discovery failed');
  const d = (await r.json()) as Discovery;
  // mix-up protection: the document must describe the issuer we were configured with
  if (d.issuer.replace(/\/+$/, '') !== issuer.replace(/\/+$/, '')) throw new Error('OIDC discovery issuer mismatch');
  for (const u of [d.authorization_endpoint, d.token_endpoint]) {
    if (!u.startsWith('https://') && !/^http:\/\/(localhost|127\.0\.0\.1)[:/]/.test(u)) throw new Error('OIDC endpoint must be https');
  }
  return d;
}

export const redirectUri = () => `${window.location.origin}/auth/callback/`;

export async function startLogin(cfg: { issuer: string; client_id: string; scope: string }): Promise<void> {
  const d = await discover(cfg.issuer);
  const verifier = rand(48), state = rand(), nonce = rand();
  sessionStorage.setItem(FLOW, JSON.stringify({ verifier, state, nonce, ...cfg }));
  const u = new URL(d.authorization_endpoint);
  u.search = new URLSearchParams({
    response_type: 'code', client_id: cfg.client_id, redirect_uri: redirectUri(), scope: cfg.scope,
    state, nonce, code_challenge: await challengeFor(verifier), code_challenge_method: 'S256',
  }).toString();
  window.location.assign(u.toString());
}

function claims(jwt: string): { exp?: number; nonce?: string } {
  const part = jwt.split('.')[1];
  if (!part) throw new Error('malformed id_token');
  return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')));
}

export async function finishLogin(search: string): Promise<Session> {
  const params = new URLSearchParams(search);
  const raw = sessionStorage.getItem(FLOW);
  sessionStorage.removeItem(FLOW); // one-shot
  if (!raw) throw new Error('No login in progress.');
  const flow = JSON.parse(raw) as { verifier: string; state: string; nonce: string; issuer: string; client_id: string };
  if (params.get('error')) throw new Error(`Identity provider: ${params.get('error')}`);
  if (params.get('state') !== flow.state) throw new Error('State mismatch (possible CSRF); start again.');
  const code = params.get('code');
  if (!code) throw new Error('No authorization code returned.');

  const d = await discover(flow.issuer);
  const r = await fetch(d.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: redirectUri(),
      client_id: flow.client_id, code_verifier: flow.verifier,
    }),
  });
  if (!r.ok) throw new Error('Token exchange failed.');
  const tok = (await r.json()) as { id_token?: string };
  if (!tok.id_token) throw new Error('The provider returned no id_token (is the openid scope enabled?).');
  const c = claims(tok.id_token);
  if (c.nonce !== flow.nonce) throw new Error('Nonce mismatch; start again.');
  return { token: tok.id_token, kind: 'oidc', expiresAt: c.exp };
}
