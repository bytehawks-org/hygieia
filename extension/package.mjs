// Assemble a browser-specific build in dist/<browser>/ (the repo root `extension/` stays loadable in Chrome as is).
//   ./extension/build.sh && node extension/package.mjs firefox
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const target = process.argv[2];
if (!['chrome', 'firefox'].includes(target)) {
  console.error('usage: node extension/package.mjs <chrome|firefox>');
  process.exit(2);
}

const out = path.join(here, 'dist', target);
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const f of ['background.js', 'content.js', 'scriptlets.js', 'options.html', 'options.js']) cpSync(path.join(here, f), path.join(out, f));
cpSync(path.join(here, 'pkg'), path.join(out, 'pkg'), { recursive: true });

const m = JSON.parse(readFileSync(path.join(here, 'manifest.json'), 'utf8'));
if (target === 'firefox') {
  // Firefox MV3: event page instead of service worker, webRequest blocking instead of DNR.
  m.permissions = m.permissions.filter((p) => p !== 'declarativeNetRequest').concat(['webRequest', 'webRequestBlocking']);
  m.background = { scripts: ['background.js'], type: 'module' };
  delete m.minimum_chrome_version;
  m.options_ui = { page: 'options.html', open_in_tab: true };
  delete m.options_page;
  m.browser_specific_settings = {
    gecko: {
      id: 'hygieia-blocker@hygieia.invalid', // replace with your own add-on id before signing
      strict_min_version: '140.0', // >=128 needed for scripting world MAIN; 140 for data_collection_permissions
      data_collection_permissions: { required: ['none'] },
    },
    gecko_android: { strict_min_version: '142.0' },
  };
}
writeFileSync(path.join(out, 'manifest.json'), `${JSON.stringify(m, null, 2)}\n`);
console.log(`packaged ${target} -> ${path.relative(process.cwd(), out)}`);
