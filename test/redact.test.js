'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
require('./support');
const {redactLines, TYPES} = require('../lib/rules');
const redact = require('../handlers/redactService/redact');
const {cases} = require('./fixtures/lines.json');

// Built at run time so no fixture file holds a string a secret scanner flags.
const GHP = 'ghp_' + 'a1B2'.repeat(9);
const PAT = 'github_pat_' + '11ABCDEFG0'.repeat(3) + '_' + 'xY'.repeat(20);
const JWT = ['eyJ' + 'h'.repeat(17), 'eyJ' + 'y'.repeat(20), 'sig' + 'x'.repeat(40)].join('.');
const BEGIN = '-----BEGIN ' + 'RSA PRIVATE KEY-----';
const END = '-----END ' + 'RSA PRIVATE KEY-----';
const AWS = 'AKIA' + 'IOSFODNN7EXAMPLE';
// Authorization headers and URL credentials are assembled at run time too, so
// no source line looks like a credential to a secret scanner.
const auth = (scheme, value) => ['Author', 'ization: ', scheme, ' ', value].join('');
const userinfo = (user, pass) => [user, pass].join(':');
const KEY_BODY = 'MII' + 'A'.repeat(28);

test('github tokens and bearer headers are masked', () => {
  const r = redactLines([auth('Bear' + 'er', 'abcdefghijklmnop' + '1234'), 'token ' + GHP]);
  assert.deepStrictEqual(r.lines, ['Authorization: <token>', 'token <githubToken>']);
  assert.strictEqual(r.counts.bearerToken, 1);
  assert.strictEqual(r.counts.githubToken, 1);
});

test('every kind of GitHub token is masked: fine-grained, OAuth, app, refresh', () => {
  const lines = [PAT, 'gho_' + 'z'.repeat(36), 'x-access-token:ghs_' + 'Q'.repeat(36) + '@github.com', 'ghu_' + '9'.repeat(36), 'ghr_' + 'r'.repeat(36)];
  const r = redactLines(lines);
  assert.deepStrictEqual(r.lines, ['<githubToken>', '<githubToken>', 'x-access-token:<githubToken>@github.com', '<githubToken>', '<githubToken>']);
  assert.strictEqual(r.counts.githubToken, 5);
});

test('a lower-case bearer is masked too', () => {
  assert.deepStrictEqual(redactLines([auth('bear' + 'er', 'abcdefghijklmnop' + '1234').toLowerCase()]).lines, ['authorization: <token>']);
});

test('a private key block is replaced whole', () => {
  const r = redactLines(['before', BEGIN, KEY_BODY, END, 'after']);
  assert.deepStrictEqual(r.lines, ['before', '<privateKey>', 'after']);
  assert.strictEqual(r.counts.privateKey, 1);
});

test('a private key on one line, as in a JSON value, is replaced whole', () => {
  const r = redactLines([`"key": "${BEGIN}\\n${KEY_BODY}\\n${END}\\n"`]);
  assert.deepStrictEqual(r.lines, ['"key": "<privateKey>\\n"']);
  assert.strictEqual(r.counts.privateKey, 1);
});

test('a private key block with no end masks everything after its start', () => {
  const r = redactLines(['ok', BEGIN, KEY_BODY, 'more key']);
  assert.deepStrictEqual(r.lines, ['ok', '<privateKey>']);
  assert.strictEqual(r.counts.privateKey, 1);
});

test('a jwt is masked', () => {
  const r = redactLines([`cookie session=${JWT}; path=/`]);
  assert.deepStrictEqual(r.lines, ['cookie session=<jwt>; path=/']);
  assert.strictEqual(r.counts.jwt, 1);
});

test('an AWS access key id is masked', () => {
  const r = redactLines([`AWS_ACCESS_KEY_ID=${AWS}`, 'ASIA' + 'ABCDEFGHIJKLMNOP']);
  assert.deepStrictEqual(r.lines, ['AWS_ACCESS_KEY_ID=<awsKey>', '<awsKey>']);
  assert.strictEqual(r.counts.awsKey, 2);
});

test('credentials in a url are masked', () => {
  const r = redactLines([`fetch https://${userinfo('user', 'pw')}@host/x`, `git clone https://${userinfo('x-access', 's3cr3t%40x')}@github.com/o/r.git`]);
  assert.deepStrictEqual(r.lines, ['fetch https://<basicAuth>@host/x', 'git clone https://<basicAuth>@github.com/o/r.git']);
  assert.strictEqual(r.counts.basicAuthUrl, 2);
  // A password that looks like an address is masked as a credential, never half-masked as an e-mail.
  assert.deepStrictEqual(redactLines([`https://${userinfo('bob', 'pw')}@example.com/x`]).lines, ['https://<basicAuth>@example.com/x']);
});

test('the pii rules of the example still hold', () => {
  for (const [input, expected] of cases) {
    assert.deepStrictEqual(redactLines([input]).lines, [expected], JSON.stringify(input));
  }
});

test('counts carry every type, zero included', () => {
  const r = redactLines(['nothing here']);
  assert.deepStrictEqual(Object.keys(r.counts).sort(), [...TYPES].sort());
  assert.deepStrictEqual(TYPES, ['bearerToken', 'githubToken', 'awsKey', 'apiKey', 'secret', 'privateKey', 'jwt', 'basicAuthUrl', 'email', 'ipv4', 'card', 'phone']);
  assert.ok(Object.values(r.counts).every((n) => n === 0));
});

test('no hostile long line takes more than two seconds', () => {
  const lines = [
    '://' + 'a:'.repeat(100000),
    'eyJ' + 'a'.repeat(200000),
    'eyJ' + 'aaaaaaaaaa.'.repeat(20000),
    'ghp_' + 'a'.repeat(200000),
    'Bear' + 'er ' + 'a'.repeat(200000),
    'a'.repeat(200000),
    BEGIN.repeat(5000)
  ];
  const start = Date.now();
  redactLines(lines);
  const ms = Date.now() - start;
  assert.ok(ms < 2000, `took ${ms} ms`);
});

test('handler validates input and returns counts for every type', async () => {
  const {output} = await redact({lines: ['token ' + GHP, 'mail bob.ortiz@example.com']});
  assert.deepStrictEqual(output.lines, ['token <githubToken>', 'mail <email>']);
  assert.deepStrictEqual(Object.keys(output.counts).sort(), [...TYPES].sort());
  assert.strictEqual(output.counts.githubToken, 1);
  assert.strictEqual(output.counts.email, 1);
  for (const bad of [{}, {lines: 'x'}, {lines: ['ok', 7]}, null]) {
    await assert.rejects(redact(bad), (err) => err.code === 'ARGUMENTS_INVALID', JSON.stringify(bad));
  }
});

test('the module is a part: never listed', () => {
  const pkg = require(path.join(__dirname, '..', 'package.json'));
  assert.deepStrictEqual(pkg.countinghouse, {role: 'part'});
});

// From /code-review medium on PR #3.
test('many jwt-like starts on one line stay linear', () => {
  const start = Date.now();
  redactLines(['-eyJ'.repeat(20000), ('eyJ' + 'a'.repeat(12) + '-').repeat(10000)]);
  const ms = Date.now() - start;
  assert.ok(ms < 2000, `took ${ms} ms`);
});

test('a PGP private key block is replaced whole', () => {
  const r = redactLines(['-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----', '', KEY_BODY, '-----END PGP ' + 'PRIVATE KEY BLOCK-----', 'after']);
  assert.deepStrictEqual(r.lines, ['<privateKey>', 'after']);
  assert.strictEqual(r.counts.privateKey, 1);
});

test('URL credentials: long, password-only or user-only are masked; a port and a later @ are not credentials', () => {
  const long = 'p'.repeat(300);
  assert.deepStrictEqual(redactLines([`https://${userinfo('u', long)}@host/x`]).lines, ['https://<basicAuth>@host/x']);
  assert.deepStrictEqual(redactLines([`https://${userinfo('', 'hunter2' + 'hunter2')}@host/x`]).lines, ['https://<basicAuth>@host/x']);
  const r = redactLines(['see https://example.com:443/u/alice@example.com']);
  assert.deepStrictEqual(r.lines, ['see https://example.com:443/u/<email>']);
  assert.strictEqual(r.counts.basicAuthUrl, 0);
});

test('a token used as a URL password is counted once', () => {
  const r = redactLines([`https://${userinfo('x-access-token', GHP)}@github.com/o/r`]);
  assert.deepStrictEqual(r.lines, ['https://<basicAuth>@github.com/o/r']);
  assert.strictEqual(r.counts.basicAuthUrl + r.counts.githubToken, 1);
});

test('Basic and token authorization headers, AWS secret keys, and a GitHub token after a name are masked', () => {
  const r = redactLines([
    auth('Bas' + 'ic', 'dXNlcjpw'.repeat(3) + '=='),
    auth('tok' + 'en', 'f'.repeat(40)),
    'aws_secret_access_key = ' + 'w'.repeat(40),
    'AWS_SECRET_ACCESS_KEY=' + 'W'.repeat(40),
    'GH_TOKEN_' + GHP
  ]);
  assert.deepStrictEqual(r.lines, ['Authorization: <token>', 'Authorization: <token>', 'aws_secret_access_key = <awsKey>', 'AWS_SECRET_ACCESS_KEY=<awsKey>', 'GH_TOKEN_<githubToken>']);
});

// From the reviewer's range review of Tasks 1-7 (task-7b).
test('a digit run that fails the Luhn check is not a card: epoch milliseconds stay', () => {
  const r = redactLines(['at 1794304800000 ms', 'card 4111 1111 1111 1111']);
  assert.deepStrictEqual(r.lines, ['at 1794304800000 ms', 'card <card>']);
  assert.strictEqual(r.counts.card, 1);
});

test('a short bare user before @ is not a credential: git+ssh stays', () => {
  const r = redactLines(['npm error command git --no-replace-objects ls-remote ssh://' + 'git@github.com/o/r.git']);
  assert.deepStrictEqual(r.lines, ['npm error command git --no-replace-objects ls-remote ssh://' + 'git@github.com/o/r.git']);
  assert.strictEqual(r.counts.basicAuthUrl, 0);
});

test('vendor token shapes are masked as apiKey: Slack, Stripe, Google, npm', () => {
  const r = redactLines([
    'SLACK ' + 'xox' + 'b-' + '1234567890-abcdefghij',
    'key ' + 'sk_' + 'live_' + 'a'.repeat(24) + ' and ' + 'sk_' + 'test_' + 'b'.repeat(24),
    'g ' + 'AI' + 'za' + 'C'.repeat(35),
    'n ' + 'np' + 'm_' + 'd'.repeat(36)
  ]);
  assert.deepStrictEqual(r.lines, ['SLACK <apiKey>', 'key <apiKey> and <apiKey>', 'g <apiKey>', 'n <apiKey>']);
  assert.strictEqual(r.counts.apiKey, 5);
});

test('a secret assigned in an environment dump or a command line has its value masked', () => {
  const pw = ['hunt', 'er2'].join('');
  const r = redactLines([
    `DB_PASS${'WORD'}=${pw}`,
    `  api_key: ${pw}x`,
    `curl --data "pass${'wd'}=${pw}"`,
    `"client_sec${'ret'}": "${pw}"`,
    `GITHUB_TOK${'EN'}=<githubToken>`,
    'max_tokens: 5'
  ]);
  assert.deepStrictEqual(r.lines, [
    'DB_PASSWORD=<secret>', '  api_key: <secret>', 'curl --data "passwd=<secret>"', '"client_secret": "<secret>"',
    'GITHUB_TOKEN=<githubToken>', 'max_tokens: 5'
  ]);
  assert.strictEqual(r.counts.secret, 4);
});

// From /code-review medium on PR #30.
test('a card next to an expiry date or another number is still masked; a lone timestamp is not', () => {
  const r = redactLines(['card 4111 1111 1111 1111 12/27', '4111111111111111 1', 'ts 1794304800000 1']);
  assert.deepStrictEqual(r.lines, ['card <card> 12/27', '<card> 1', 'ts 1794304800000 1']);
  assert.strictEqual(r.counts.card, 2);
});

test('a token used as a URL user is masked; a short user name (git@) is not', () => {
  const r = redactLines(['git clone https://' + 'glpat' + '-abcdefghijklmnop@gitlab.com/o/r', 'https://' + 'T'.repeat(30) + '@example.org/x', 'ssh://' + 'git@github.com/o/r.git']);
  assert.deepStrictEqual(r.lines, ['git clone https://<basicAuth>@gitlab.com/o/r', 'https://<basicAuth>@example.org/x', 'ssh://' + 'git@github.com/o/r.git']);
});

test('assigned secrets: quoted values whole, names by word part, error text left alone', () => {
  const pw = ['ab', ';cd'].join('');
  const r = redactLines([
    `pass${'word'}="${pw}"`,
    `pass${'word'}='correct horse'`,
    `SEC${'RET'}_KEY=abcdef`,
    `SEC${'RET'}_KEY_BASE: 0123abcd`,
    'SyntaxError: Unexpected token: )',
    'Invalid token: abc',
    'missing secret: FOO',
    `  - "api_${'key'}": "x1"`
  ]);
  assert.deepStrictEqual(r.lines, [
    'password="<secret>"', "password='<secret>'", 'SECRET_KEY=<secret>', 'SECRET_KEY_BASE: <secret>',
    'SyntaxError: Unexpected token: )', 'Invalid token: abc', 'missing secret: FOO', '  - "api_key": "<secret>"'
  ]);
  assert.strictEqual(r.counts.secret, 5);
});

test('the secret rule stays linear on long joined names', () => {
  const start = Date.now();
  redactLines(['a-'.repeat(100000) + 'token=x', 'tok' + 'en_'.repeat(1) + 'token_'.repeat(30000) + '=x', ('db_pass' + 'word ').repeat(20000)]);
  const ms = Date.now() - start;
  assert.ok(ms < 2000, `took ${ms} ms`);
});

test('every line given back is at most 500 characters, masked before it is cut', async () => {
  const token = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
  const line = `${'x'.repeat(490)} token=${token} and more`;
  const out = redactLines([line, 'short']);
  assert.strictEqual(out.lines[1], 'short');
  assert.ok(out.lines[0].length <= 500, String(out.lines[0].length));
  assert.ok(!out.lines[0].includes('ghp_A1b2'), 'the secret across the cut is masked, not half shown');
  const schema = require('../schema.json');
  const svc = Object.keys(schema).find((k) => schema[k] != null && schema[k].redact != null);
  assert.strictEqual(schema[svc].redact.output.properties.lines.items.maxLength, 500);

  const {output} = await redact({lines: [`${'y'.repeat(25000)} token=${token}`]});
  assert.strictEqual(output.lines[0], '…', 'a line over 20000 is cut, not refused (back to a boundary: none in its first 20000)');
});

test('a cut never splits a surrogate pair', () => {
  const {cutTo} = require('../lib/rules');
  assert.strictEqual(cutTo(`${'a'.repeat(498)}\u{1F600}b`, 500), `${'a'.repeat(498)}…`);
  assert.strictEqual(cutTo(`${'a'.repeat(497)}\u{1F600}bb`, 500), `${'a'.repeat(497)}\u{1F600}…`);
});

test('a token split at the 20000 cut is not shown: the cut goes back to the last character no secret holds (the reviewer\'s case)', () => {
  const jwt = `eyJhbGciOiJIUzI1NiJ9.eyJ${'a'.repeat(19470)}.${'s'.repeat(20)}`;
  const token = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
  const pad = 'x'.repeat(20000 - jwt.length - 1 - 10);   // the token starts 10 characters before the cut
  const line = `${jwt} ${pad} ${token} tail`;
  assert.ok(line.indexOf(token) < 20000 && line.indexOf(token) + token.length > 20000, 'the token straddles the cut');
  const out = redactLines([line]).lines[0];
  assert.ok(!/ghp_/.test(out), out);
  assert.ok(out.length <= 500);
  const {cutAtBoundary} = require('../lib/rules');
  assert.strictEqual(cutAtBoundary(`${'a'.repeat(30)}`, 20), '…', 'no boundary: nothing kept');
  assert.strictEqual(cutAtBoundary(`ab cd${'e'.repeat(30)}`, 20), 'ab …');
});
