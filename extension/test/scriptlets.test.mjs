// node --test extension/test/
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { injectScriptlets } from '../scriptlets.js';

function run(calls, setup = '') {
  const ctx = vm.createContext({});
  vm.runInContext(`this.window = this; ${setup}`, ctx);
  vm.runInContext(`(${injectScriptlets.toString()})(${JSON.stringify(calls)})`, ctx);
  return ctx;
}
const ev = (ctx, code) => vm.runInContext(code, ctx);

test('set-constant on missing nested chain applies when parents appear', () => {
  const ctx = run([{ name: 'set-constant', args: ['ads.enabled', 'false'] }]);
  ev(ctx, 'window.ads = { enabled: true, other: 1 }');
  assert.equal(ev(ctx, 'window.ads.enabled'), false);
  assert.equal(ev(ctx, 'window.ads.other'), 1);
});

test('set-constant on existing property, numeric and function values', () => {
  const ctx = run(
    [{ name: 'set', args: ['cfg.n', '42'] }, { name: 'set-constant', args: ['cfg.f', 'noopFunc'] }],
    'this.cfg = { n: 1, f: () => 7 }',
  );
  assert.equal(ev(ctx, 'cfg.n'), 42);
  assert.equal(ev(ctx, 'cfg.f()'), undefined);
});

test('abort-on-property-read throws on read, write is ignored', () => {
  const ctx = run([{ name: 'aopr', args: ['adblockDetected'] }]);
  assert.throws(() => ev(ctx, 'adblockDetected'), /ReferenceError|[a-z0-9]{6,}/);
  assert.doesNotThrow(() => ev(ctx, 'window.adblockDetected = 1'));
});

test('abort-on-property-write throws on assignment', () => {
  const ctx = run([{ name: 'abort-on-property-write', args: ['popunder'] }]);
  assert.throws(() => ev(ctx, 'window.popunder = 1'));
});

test('no-setTimeout-if blocks matching callbacks only', () => {
  const ctx = run(
    [{ name: 'nostif', args: ['adsLoader'] }],
    'this.hits = []; this.setTimeout = function (cb) { hits.push(String(cb)); return 1; }',
  );
  ev(ctx, 'setTimeout(function adsLoader(){}, 10); setTimeout(function good(){}, 10)');
  assert.equal(ev(ctx, 'hits.length'), 1);
  assert.match(ev(ctx, 'hits[0]'), /good/);
});

test('hostile input is ignored: bad chains, unknown names, non-array args, prototype paths', () => {
  const ctx = run([
    { name: 'set-constant', args: ['a.b); evil(', 'true'] },
    { name: 'set-constant', args: ['__proto__.polluted', 'true'] },
    { name: 'set-constant', args: ['constructor.prototype.polluted2', 'true'] },
    { name: 'eval', args: ['1'] },
    { name: 'trusted-set-constant', args: ['x', '1'] },
    { name: 'set-constant', args: 'oops' },
    null,
  ]);
  assert.equal(ev(ctx, 'typeof evil'), 'undefined');
  assert.equal(ev(ctx, '({}).polluted'), undefined);
  assert.equal(ev(ctx, 'typeof window.__proto__'), 'object', 'window.__proto__ must not be shadowed');
  assert.equal(ev(ctx, 'typeof x'), 'undefined');
});

test('non-array calls do not throw', () => {
  assert.doesNotThrow(() => run('nope'));
});
