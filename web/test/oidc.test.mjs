// node --test web/test/   (Node >= 22.18 strips TypeScript types natively)
import test from 'node:test';
import assert from 'node:assert/strict';
import { challengeFor } from '../lib/oidc.ts';

test('PKCE S256 challenge matches the RFC 7636 appendix B vector', async () => {
  assert.equal(await challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});
