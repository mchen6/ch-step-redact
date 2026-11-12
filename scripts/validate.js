'use strict';
// Validates the module as users get it: the packed tarball, extracted into a
// temporary directory and checked by countinghouse-validate (the runtime's own
// check, from the pinned devDependency). The repository itself cannot be
// validated in place: its node_modules holds the runtime's dependencies, and
// the validator rightly refuses native code inside a module directory.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

// npm as `node npm-cli.js`: no shell on any system (Windows refuses to spawn
// npm.cmd without one).
function npmCli() {
  const fromNpm = process.env.npm_execpath;
  if (fromNpm && /npm-cli\.js$/.test(fromNpm) && fs.existsSync(fromNpm)) return fromNpm;
  const bin = path.dirname(process.execPath);
  const candidates = [
    path.join(bin, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(bin, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')
  ];
  const found = candidates.find((c) => fs.existsSync(c));
  if (!found) throw new Error(`cannot find npm beside ${process.execPath}`);
  return found;
}

const root = path.join(__dirname, '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ch-validate-'));
// The exit code is set, never process.exit()ed, so the finally below always
// removes the temporary directory (process.exit inside try skips finally).
try {
  const packed = spawnSync(process.execPath, [npmCli(), 'pack', '--json', '--pack-destination', tmp], {cwd: root, encoding: 'utf8'});
  if (packed.status !== 0) { process.stderr.write(packed.stderr); process.exitCode = 2; return; }
  const tarball = path.join(tmp, JSON.parse(packed.stdout)[0].filename);
  const extracted = spawnSync('tar', ['-xzf', tarball, '-C', tmp], {encoding: 'utf8'});
  if (extracted.status !== 0) { process.stderr.write(extracted.stderr); process.exitCode = 2; return; }
  const validator = require.resolve('countinghouse/bin/countinghouse-validate.js', {paths: [root]});
  const result = spawnSync(process.execPath, [validator, path.join(tmp, 'package')], {stdio: 'inherit'});
  process.exitCode = result.status == null ? 2 : result.status;
} finally {
  fs.rmSync(tmp, {recursive: true, force: true});
}
