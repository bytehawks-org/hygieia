// Cosmetic filtering (element hiding). Selectors come from the signed bundle via
// the background engine. One invalid selector invalidates a whole CSS rule, so each
// selector is validated with CSS.supports() and applied in small groups.
const api = globalThis.browser ?? globalThis.chrome;

(async () => {
  try {
    const r = await api.runtime.sendMessage({ type: 'cosmetics', host: location.hostname });
    if (!r || !Array.isArray(r.selectors) || r.selectors.length === 0) return;
    const ok = r.selectors.filter((s) => {
      try { return typeof s === 'string' && CSS.supports(`selector(${s})`); } catch { return false; }
    });
    if (ok.length === 0) return;
    let css = '';
    for (let i = 0; i < ok.length; i += 100) {
      css += `${ok.slice(i, i + 100).join(',\n')}{display:none!important}\n`;
    }
    try {
      // Constructed stylesheets are not subject to the page's CSP (Chromium).
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      const before = document.adoptedStyleSheets.length;
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
      if (document.adoptedStyleSheets.length === before) throw new Error('not adopted');
    } catch {
      // Firefox content scripts cannot touch adoptedStyleSheets through Xray wrappers:
      // ask the background to inject the CSS as a user stylesheet (also CSP-exempt).
      await api.runtime.sendMessage({ type: 'insert-css', css });
    }
  } catch { /* extension reloading or background asleep: fail open */ }
})();
