'use strict';
// countinghouse's logger step 1 removed the DeviceError and CHError globals:
// a module's own failure is ctx.error with its own code.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const walk = (dir) => fs.readdirSync(dir, {withFileTypes: true}).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.js') ? [path.join(dir, e.name)] : []));

test('no handler or lib file reaches for an error global the runtime no longer gives', () => {
  const files = ['handlers', 'lib'].filter((d) => fs.existsSync(path.join(ROOT, d))).flatMap((d) => walk(path.join(ROOT, d)));
  assert.ok(files.length > 0);
  // any mention in code (comments aside): new, a call, instanceof, globalThis
  const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const file of files) assert.ok(!/\b(DeviceError|CHError)\b/.test(code(fs.readFileSync(file, 'utf8'))), `${path.relative(ROOT, file)} uses a removed error global`);
});
