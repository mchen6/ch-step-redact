'use strict';
// countinghouse's logger step 1 removed the DeviceError and CHError globals:
// a module's own failure is ctx.error with its own code, never one of the
// runtime's catalogue codes (which the runtime reserves for itself).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const walk = (dir) => fs.readdirSync(dir, {withFileTypes: true}).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : /\.[cm]?js$/.test(e.name) ? [path.join(dir, e.name)] : []));
const files = () => ['handlers', 'lib'].filter((d) => fs.existsSync(path.join(ROOT, d))).flatMap((d) => walk(path.join(ROOT, d)));
// the code, comments aside ('//' after a colon or inside quotes is a URL or a string, kept)
const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

test('no handler or lib file reaches for an error global the runtime no longer gives', () => {
  assert.ok(files().length > 0);
  // any mention in code: new, a call, instanceof, globalThis
  for (const file of files()) assert.ok(!/\b(DeviceError|CHError)\b/.test(code(fs.readFileSync(file, 'utf8'))), `${path.relative(ROOT, file)} uses a removed error global`);
});

test('every ctx.error code is the module\'s own, none of the runtime\'s catalogue', () => {
  const {CODES} = require('countinghouse/lib/error-catalogue');
  let seen = 0;
  for (const file of files()) {
    for (const m of code(fs.readFileSync(file, 'utf8')).matchAll(/ctx\.error\(\s*['"`]([^'"`]+)['"`]/g)) {
      seen++;
      assert.ok(!Object.prototype.hasOwnProperty.call(CODES, m[1]), `${path.relative(ROOT, file)}: ${m[1]} is a catalogue code`);
      assert.match(m[1], /^[A-Z][A-Z0-9_]{2,}$/, `${path.relative(ROOT, file)}: ${m[1]}`);
    }
  }
  assert.ok(seen > 0, 'the handler reports its input error through ctx.error');
});
