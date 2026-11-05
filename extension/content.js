// Cosmetic filtering (element hiding). Selectors come from the signed bundle via
// the background engine. One invalid selector invalidates a whole CSS rule, so each
// selector is validated with CSS.supports() and applied in small groups.
(async () => {
  try {
    const r = await chrome.runtime.sendMessage({ type: 'cosmetics', host: location.hostname });
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
      // Constructed stylesheets are not subject to the page's CSP.
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    } catch {
      const st = document.createElement('style');
      st.textContent = css;
      (document.head || document.documentElement).appendChild(st);
    }
  } catch { /* extension reloading or background asleep: fail open */ }
})();
