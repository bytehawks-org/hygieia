// Scriptlets: packaged code, parameterised by DATA from the signed bundle.
// MV3 forbids remote code, so lists can only choose a name from this table and
// supply string arguments. NOTHING here evaluates strings (no eval/Function,
// no regex from lists: a hostile list could ship a catastrophic pattern).
//
// `injectScriptlets` is passed to chrome.scripting.executeScript({ func }) and is
// serialised via toString(): it MUST stay fully self-contained.
export function injectScriptlets(calls) {
  const PATH = /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/;
  const rnd = () => Math.random().toString(36).slice(2, 10);

  const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);

  function parseValue(v) {
    switch (v) {
      case 'true': return true;
      case 'false': return false;
      case 'null': return null;
      case 'undefined': return undefined;
      case 'noopFunc': return function () {};
      case 'trueFunc': return function () { return true; };
      case 'falseFunc': return function () { return false; };
      case 'emptyStr': return '';
      case 'emptyArr': return [];
      case 'emptyObj': return {};
    }
    if (/^-?\d{1,15}(\.\d{1,6})?$/.test(v)) return Number(v);
    return v;
  }

  // Install `leaf()` descriptor at the end of `chain`, even if parents do not exist yet.
  function hook(chain, leaf) {
    if (typeof chain !== 'string' || !PATH.test(chain)) return;
    const parts = chain.split('.');
    if (parts.some((p) => FORBIDDEN.has(p))) return;
    const walk = (owner, i) => {
      const prop = parts[i];
      const desc = Object.getOwnPropertyDescriptor(owner, prop);
      if (i === parts.length - 1) {
        if (desc && desc.configurable === false) return;
        try { Object.defineProperty(owner, prop, Object.assign({ configurable: true }, leaf())); } catch (e) { /* ignore */ }
        return;
      }
      if (desc && 'value' in desc && desc.value && (typeof desc.value === 'object' || typeof desc.value === 'function')) {
        walk(desc.value, i + 1);
        return;
      }
      if (desc && desc.configurable === false) return;
      let val = desc && 'value' in desc ? desc.value : undefined;
      try {
        Object.defineProperty(owner, prop, {
          configurable: true,
          enumerable: desc ? desc.enumerable : true,
          get() { return val; },
          set(v) {
            val = v;
            if (v && (typeof v === 'object' || typeof v === 'function')) walk(v, i + 1);
          },
        });
      } catch (e) { /* ignore */ }
    };
    walk(window, 0);
  }

  function noTimerIf(name, needle, delay) {
    if (typeof needle !== 'string') return;
    const orig = window[name];
    if (typeof orig !== 'function') return;
    window[name] = new Proxy(orig, {
      apply(target, thisArg, args) {
        try {
          const cb = args[0];
          const text = typeof cb === 'function' ? Function.prototype.toString.call(cb) : String(cb);
          const delayOk = delay === undefined || delay === '' || String(args[1]) === delay;
          if (needle !== '' && text.includes(needle) && delayOk) return 0;
        } catch (e) { /* fall through */ }
        return Reflect.apply(target, thisArg, args);
      },
    });
  }

  const table = {
    'set-constant': (chain, value) => hook(chain, () => {
      const v = parseValue(value === undefined ? '' : value);
      return { get: () => v, set: () => {} };
    }),
    'abort-on-property-read': (chain) => hook(chain, () => ({ get() { throw new ReferenceError(rnd()); }, set() {} })),
    'abort-on-property-write': (chain) => hook(chain, () => ({ get: () => undefined, set() { throw new ReferenceError(rnd()); } })),
    'no-setTimeout-if': (needle, delay) => noTimerIf('setTimeout', needle, delay),
    'no-setInterval-if': (needle, delay) => noTimerIf('setInterval', needle, delay),
  };
  const aliases = {
    set: 'set-constant',
    aopr: 'abort-on-property-read',
    aopw: 'abort-on-property-write',
    nostif: 'no-setTimeout-if',
    nosiif: 'no-setInterval-if',
  };

  if (!Array.isArray(calls)) return;
  for (const c of calls) {
    try {
      if (!c || typeof c.name !== 'string' || !Array.isArray(c.args)) continue;
      const fn = table[aliases[c.name] || c.name];
      if (!fn) continue; // unknown scriptlet: ignore, never guess
      fn(...c.args.slice(0, 4).map(String));
    } catch (e) { /* a broken scriptlet must never break the page */ }
  }
}
