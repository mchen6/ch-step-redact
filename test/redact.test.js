'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {redactLines, TYPES} = require('../lib/rules');
const {CountinghouseError} = require('countinghouse/lib/countinghouse-error');
// the handler as the runtime calls it: (input, ctx), ctx.error the runtime's
const ctx = {error: (code, message, details) => CountinghouseError.module(code, message, details)};
const handler = require('../handlers/redactService/redact');
const redact = Object.assign((input) => handler(input, ctx), handler);
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
    await assert.rejects(redact(bad), (err) => err.code === 'INPUT_REJECTED', JSON.stringify(bad));
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
  assert.strictEqual(output.lines[0], `(a line of ${25000 + 1 + token.length + 6} characters, omitted)`, 'a line over 20000 is omitted whole, not refused');
});

test('a cut never splits a surrogate pair', () => {
  const {cutTo} = require('../lib/rules');
  assert.strictEqual(cutTo(`${'a'.repeat(498)}\u{1F600}b`, 500), `${'a'.repeat(498)}…`);
  assert.strictEqual(cutTo(`${'a'.repeat(497)}\u{1F600}bb`, 500), `${'a'.repeat(497)}\u{1F600}…`);
});

// A line over 20000 is omitted whole (the reviewer, round 2): no cut, so no
// secret's head is left, whatever quoting or spaces it has.
const LONG_JWT = `eyJhbGciOiJIUzI1NiJ9.eyJ${'a'.repeat(19470)}.${'s'.repeat(20)}`;
const across = (secret) => {
  // the secret starts a few characters before the 20000th
  const pad = 'x'.repeat(Math.max(0, 20000 - LONG_JWT.length - 2 - 6));
  return `${LONG_JWT} ${pad} ${secret} tail`;
};
for (const [label, secret, leak] of [
  ['a ghp_ token', `ghp_${'A1b2C3d4E5'.repeat(4)}`, /ghp_/],
  ['a quoted password with spaces', 'password="Zq9 Wx7 Kp3 Mn5 Rt8"', /Zq9|Wx7/],
  ['a JSON password', '{"password": "Zq9 Wx7 Kp3 Mn5 Rt8"}', /Zq9|Wx7/],
  ['a single-quoted API key', "API_KEY='Zq9 Wx7 Kp3 Mn5 Rt8'", /Zq9|Wx7/]]) {
  test(`a line over 20000 is omitted whole: nothing of ${label} across the 20000th character is kept`, () => {
    const line = across(secret);
    assert.ok(line.length > 20000 && line.indexOf(secret) < 20000, 'the secret starts before the 20000th character');
    const out = redactLines([line]).lines[0];
    assert.strictEqual(out, `(a line of ${line.length} characters, omitted)`);
    assert.ok(!leak.test(out));
  });
}

// The reviewer's high, 1 (fail-open): a private-key block whose BEGIN line is
// over IN_MAX characters. The line was omitted before the block was looked
// for, so the body lines after it went through unmasked. Blocks are found on
// the full lines, then long lines are omitted.
test('a private key block whose BEGIN line is over IN_MAX characters: its body never passes', () => {
  const {IN_MAX} = require('../lib/rules');
  const long = 'x'.repeat(IN_MAX + 1) + BEGIN;
  const r = redactLines([long, KEY_BODY, KEY_BODY, END + ' after']);
  assert.ok(!r.lines.some((l) => l.includes(KEY_BODY)), JSON.stringify(r.lines));
  assert.strictEqual(r.counts.privateKey, 1);
  assert.deepStrictEqual(r.lines.slice(1), [], 'the block\'s lines are one line, with the long one');
  // an END on a long line closes the block too
  const r2 = redactLines([BEGIN, KEY_BODY, 'y'.repeat(IN_MAX + 1) + END, 'after ' + KEY_BODY.slice(0, 3)]);
  assert.ok(!r2.lines.some((l) => l.includes(KEY_BODY)), JSON.stringify(r2.lines));
  assert.strictEqual(r2.lines[r2.lines.length - 1], 'after MII', 'the block closed at the long line');
});

// The reviewer's high, 2 (partial): an unquoted value stopped at , ; " ',
// leaving the tail in view while the count said masked, and a value starting
// with < was left whole. An unquoted value runs to whitespace or the line's
// end; a value left alone is one an earlier rule's tags make up entirely.
test('an assigned secret is masked to the end of its value: no tail after , ; " \' and no untagged value starting with <', () => {
  const name = 'DB_PASS' + 'WORD';
  for (const sep of [';', ',', '"', "'"]) {
    const r = redactLines([`${name}=abc${sep}s3cr3tTAIL next`]);
    assert.deepStrictEqual(r.lines, [`${name}=<secret> next`], sep);
    assert.strictEqual(r.counts.secret, 1);
  }
  const lt = redactLines([`${name}=<s3cr3tVALUE`]);
  assert.deepStrictEqual(lt.lines, [`${name}=<secret>`]);
  const ltq = redactLines([`${name}="<s3cr3tVALUE"`]);
  assert.deepStrictEqual(ltq.lines, [`${name}="<secret>"`]);
  // (a value an earlier rule already tagged stays, counted once)
  const tagged = redactLines([`${name}=` + GHP]);
  assert.deepStrictEqual(tagged.lines, [`${name}=<githubToken>`]);
  assert.deepStrictEqual([tagged.counts.githubToken, tagged.counts.secret], [1, 0]);
});

// The reviewer's high, 3 (missed names). Values built at run time.
test('secrets under the names and forms the reviewer listed are masked; their look-alikes are not', () => {
  const v = 's3cr3t' + 'VALUEabc123';
  const masked = [
    [`{"access${'Token'}":"${v}"}`, `{"access${'Token'}":"<secret>"}`],
    [`client${'Secret'}=${v}`, `client${'Secret'}=<secret>`],
    [`api${'Token'}=${v}`, `api${'Token'}=<secret>`],
    [`PGPASS${'WORD'}=${v} psql`, `PGPASS${'WORD'}=<secret> psql`],
    [`MYSQL_${'PWD'}=${v}`, `MYSQL_${'PWD'}=<secret>`],
    [`ACCESS${'TOKEN'}=${v}`, `ACCESS${'TOKEN'}=<secret>`],
    [`db_pwd=${v}`, 'db_pwd=<secret>'],
    [`pass=${v}`, 'pass=<secret>'],
    [`auth=${v}`, 'auth=<secret>'],
    [`credentials=${v}`, 'credentials=<secret>'],
    [`private_${'key'}=${v}`, `private_${'key'}=<secret>`],
    [`//npm.pkg.invalid/:_pass${'word'}=${v}`, `//npm.pkg.invalid/:_pass${'word'}=<secret>`],
    [`//npm.pkg.invalid/:_auth=${v}`, '//npm.pkg.invalid/:_auth=<secret>'],
    [`//npm.pkg.invalid/:_auth${'Token'}=${v}`, `//npm.pkg.invalid/:_auth${'Token'}=<secret>`],
    [`docker login -u me --pass${'word'} ${v}`, `docker login -u me --pass${'word'} <secret>`],
    [`mysql -uroot -p${v} db`, 'mysql -uroot -p<secret> db'],
    [`curl -H "X-Api-${'Key'}: ${v}" https://x.invalid`, `curl -H "X-Api-${'Key'}: <secret>" https://x.invalid`],
    [`curl -H "Author${'ization'}: ${v}xyz" https://x.invalid`, `curl -H "Author${'ization'}: <secret>" https://x.invalid`],
    [`Set-Cookie: session=${v}; Path=/`, 'Set-Cookie: <secret>'],
    [`Cookie: sid=${v}`, 'Cookie: <secret>']
  ];
  for (const [line, want] of masked) {
    const r = redactLines([line]);
    assert.deepStrictEqual(r.lines, [want], line);
    assert.strictEqual(r.counts.secret, 1, `${line}: counted once`);
  }
  for (const line of ['max_tokens: 5', 'Unexpected token: )', 'bypass=1', 'author: someone', 'docker run -p 8080:80 img', 'docker run -p8080:80 img', 'tokens=3']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
});

// The reviewer's high, 4 (missed shapes). Built at run time.
test('the token shapes the reviewer listed are masked, each under its type; a commit SHA is not', () => {
  const A = 'aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1b2C';
  const hex40 = '0123456789abcdef'.repeat(3).slice(0, 40);
  const cases = [
    [`push with glpat-${'abcdefghij0123456789'}`, 'push with <apiKey>', 'apiKey'],
    [`key sk-ant-api03-${A}${A}`, 'key <apiKey>', 'apiKey'],
    [`key sk-proj-${A}${A}`, 'key <apiKey>', 'apiKey'],
    [`key sk-${A}x`, 'key <apiKey>', 'apiKey'],
    [`posting to https://hooks.slack.com/services/T${'00000000'}/B${'00000000'}/${'X'.repeat(24)}`, 'posting to <apiKey>', 'apiKey'],
    [`using token ${hex40}`, 'using token <githubToken>', 'githubToken'],
    [`installation v1.${hex40}`, 'installation <githubToken>', 'githubToken'],
    [`key wJalrXUtnFEMI/K7MDENG/bPxRfiCY${'EXAMPLEKEY'}`, 'key <awsKey>', 'awsKey'],
    [`MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7${'MaskedBody'}`, '<privateKey>', 'privateKey']
  ];
  for (const [line, want, type] of cases) {
    const r = redactLines([line]);
    assert.deepStrictEqual(r.lines, [want], line);
    assert.strictEqual(r.counts[type], 1, `${line}: one ${type}`);
  }
  for (const line of [`commit ${hex40}`, `HEAD is now at ${hex40.slice(0, 7)} msg`, 'desk-top sk-1 short', 'MIIFDA']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
});

// The medium on the reviewer's high (A-redact), its findings 1-9: each leak
// it found masked, each over-mask it found left as it was. Built at run time.
test('medium 1: a bare key body is masked through all its lines, not only the first', () => {
  const b64 = (i) => Buffer.alloc(48, i).toString('base64');
  const r = redactLines(['MIIEowIBAAKCAQEA' + b64(7).slice(16), b64(200), b64(90), 'abcd==', 'next']);
  assert.deepStrictEqual(r.lines, ['<privateKey>', 'next']);
  assert.strictEqual(r.counts.privateKey, 1);
});
test('medium 2: headers after curl -v\'s > and < marks, and JSON headers, are masked', () => {
  const v = 's3cr3t' + 'VALUEabc123';
  const basic = 'dXNl' + 'cjpwYXNz';
  for (const [line, want] of [
    [`> Cookie: sid=${v}`, '> Cookie: <secret>'],
    [`< set-cookie: sid=${v}; Path=/`, '< set-cookie: <secret>'],
    [`> X-Api-${'Key'}: ${v}`, `> X-Api-${'Key'}: <secret>`],
    [`> Author${'ization'}: Basic ${basic}`, `> Author${'ization'}: <secret>`],
    [`{"Author${'ization'}": "Basic ${basic}"}`, `{"Author${'ization'}": "<secret>"}`],
    [`{"cookie":"sid=${v}"}`, '{"cookie":"<secret>"}']
  ]) assert.deepStrictEqual(redactLines([line]).lines, [want], line);
});
test('medium 3, 4 and 5: quoted flag values, unterminated or escaped quotes, and a key\'s value with spaces are masked whole', () => {
  const v = 's3cr3t' + 'VALUEabc123';
  const pw = 'PASS' + 'WORD';
  for (const [line, want] of [
    [`docker login --pass${'word'} "${v}"`, `docker login --pass${'word'} "<secret>"`],
    [`docker login --pass${'word'} '${v}'`, `docker login --pass${'word'} '<secret>'`],
    [`export DB_${pw}="${v} more`, `export DB_${pw}="<secret>`],
    [`DB_${pw}="ab\\"${v}TAIL"`, `DB_${pw}="<secret>"`],
    [`pass${'word'}: correct horse ${v} staple`, `pass${'word'}: <secret>`],
    [`mysql -uroot -p"my ${v}" db`, 'mysql -uroot -p"<secret>" db']
  ]) {
    const r = redactLines([line]);
    assert.deepStrictEqual(r.lines, [want], line);
    assert.strictEqual(r.counts.secret, 1, line);
  }
});
test('medium 6 and 9b: a bare AWS secret key without / or + is masked; a Basic credential stays a bearerToken', () => {
  const r = redactLines([`key wJalrXUtnFEMIK7MDENGbPxRfiCY12${'EXAMPLEKEY'}`]);
  assert.deepStrictEqual([r.lines, r.counts.awsKey], [['key <awsKey>'], 1]);
  const b = redactLines(['Basic ' + 'aB3/'.repeat(10)]);
  assert.deepStrictEqual([b.lines, b.counts.bearerToken, b.counts.awsKey], [['<token>'], 1, 0]);
});
test('medium 7: an unquoted key in mid-line object syntax is masked', () => {
  const v = 's3cr3t' + 'VALUEabc123';
  assert.deepStrictEqual(redactLines([`{ user: 'bob', pass${'word'}: '${v}' }`]).lines, [`{ user: 'bob', pass${'word'}: '<secret>' }`]);
  assert.deepStrictEqual(redactLines([`const cfg = {token: ${v}}`]).lines, ['const cfg = {token: <secret>}']);
});
test('medium 8: what triage needs stays: PWD, pass tallies, cache and primary keys, a token file\'s path, a path', () => {
  for (const line of ['PWD=/home/runner/work/repo/repo', 'OLDPWD=/home/runner', 'tests pass=10 fail=2', 'cache-key: node-Linux-abc123', '  primary-key: id',
    'reading --token-file /etc/app/tok', 'fatal /home/runner/work/MyRepo22/MyRepo22/srcA.ts:3']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
  assert.deepStrictEqual(redactLines(['mysql -uroot -pS3cret; next']).lines, ['mysql -uroot -p<secret>; next']);
});
test('medium 9a: a value an earlier tag starts has its tail masked too', () => {
  const r = redactLines(['TOKEN=' + GHP + ':tail' + 's3cr3tVALUE']);
  assert.deepStrictEqual(r.lines, ['TOKEN=<githubToken><secret>']);
  assert.deepStrictEqual([r.counts.githubToken, r.counts.secret], [1, 1]);
  assert.deepStrictEqual(redactLines(['x-access-token:' + GHP + '@github.com']).lines, ['x-access-token:<githubToken>@github.com'], 'a URL\'s host stays');
});

test('medium (round 2): a comparison is not an assignment; a key with a long run of spaces stays linear', () => {
  assert.deepStrictEqual(redactLines([`if pass${'word'} == expected:`]).lines, [`if pass${'word'} == expected:`]);
  const {IN_MAX} = require('../lib/rules');
  const t0 = process.hrtime.bigint();
  redactLines(Array(50).fill(('token: ' + ' '.repeat(IN_MAX)).slice(0, IN_MAX)));
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(ms < 2000, `50 lines of "token:" and spaces took ${ms.toFixed(0)} ms`);
});

// The medium's second round: its leaks (three of them regressions of the
// first fix round) and its over-masks. Built at run time.
test('medium round 2: AWS keys at a sentence\'s end, after =, or starting with / or + are masked; a path is not', () => {
  const k = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY';
  for (const [line, want] of [[`Using key ${k}.`, 'Using key <awsKey>.'], [`key +${k.slice(1)} end`, 'key <awsKey> end'],
    [`key /${k.slice(1)} end`, 'key <awsKey> end'], [`MYVAR=${k}`, 'MYVAR=<awsKey>']]) {
    assert.deepStrictEqual(redactLines([line]).lines, [want], line);
  }
  for (const line of ['fatal /home/runner/work/MyRepo22/MyRepo22/srcA.ts:3', 'at /home/runner/work/MyRepo2/MyRepo2/src/AbcDefGh.js:10']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
});
test('medium round 2: mysql -p runs to whitespace; a long quoted value is masked whole; header quotes honour escapes; a timestamped curl -v header', () => {
  const ck = 'Coo' + 'kie';
  for (const [line, want] of [
    ['mysql -u root -pab"cd', 'mysql -u root -p<secret>'],
    [`secret="${'x'.repeat(4100)}TAILSECRET"`, 'secret="<secret>"'],
    [`{"${ck}": "a=b\\"; session=SECRETVAL"}`, `{"${ck}": "<secret>"}`],
    [`2026-11-20T10:00:00.1234567Z > ${ck}: session=abc123`, `2026-11-20T10:00:00.1234567Z > ${ck}: <secret>`],
    // (an unquoted value that is no JSON literal runs to the line's end: the
    // medium's third round, fail closed)
    [`{"X-Api-${'Key'}": abc, "other": 1}`, `{"X-Api-${'Key'}": <secret>}`],
    [`{"pass${'word'}": "ab\\\\"}`, `{"pass${'word'}": "<secret>"}`]
  ]) assert.deepStrictEqual(redactLines([line]).lines, [want], line.slice(0, 80));
});
test('medium round 2: a YAML block indicator is no value; a bare key body ends before ordinary short lines; weak names keep their tallies and settings', () => {
  const r = redactLines([`pass${'word'}: |`]);
  assert.deepStrictEqual([r.lines, r.counts.secret], [[`pass${'word'}: |`], 0]);
  const body = 'MIIEvQ' + Buffer.alloc(45, 3).toString('base64');
  assert.deepStrictEqual(redactLines([body, 'abc123DEF', 'Error', 'Done', '200']).lines, ['<privateKey>', 'abc123DEF', 'Error', 'Done', '200']);
  for (const line of ['  pass: 10   ', 'pass_count=10 auth_mode=none auth_type=basic', 'git push --no-auth origin']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
});

// The medium's third round: leaks the second round's narrowing opened
// (fail closed where a leak and over-masking conflict). Built at run time.
test('medium round 3: an Anthropic or OpenAI key whole; a JSON Authorization or Cookie value whole; a narrow-wrapped key body whole', () => {
  const b = 'aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1b2C3d4E';
  assert.deepStrictEqual(redactLines([`key sk-ant-api03-ab_${b}-tailSECRETtailSECRETtail99AAz-AA`]).lines, ['key <apiKey>']);
  assert.deepStrictEqual(redactLines([`{"Author${'ization'}": Token abcdefghijklmnop1234567890}`]).lines, [`{"Author${'ization'}": <secret>}`]);
  assert.deepStrictEqual(redactLines([`{"Coo${'kie'}": a=1; sessionid=SECRETVALUE}`]).lines, [`{"Coo${'kie'}": <secret>}`]);
  assert.deepStrictEqual(redactLines([`{"X-Api-${'Key'}": 12345, "other": 1}`]).lines, [`{"X-Api-${'Key'}": <secret>, "other": 1}`], 'a JSON literal value stops at its comma');
  const lines = Array.from({length: 6}, (_, i) => Buffer.alloc(45, i + 1).toString('base64'));
  lines[0] = 'MIIEvQ' + lines[0].slice(6);
  const r = redactLines([...lines, 'after']);
  assert.deepStrictEqual(r.lines, ['<privateKey>', 'after'], 'a body wrapped at 60 characters');
});
test('medium round 3: secret names that start with a weak word, and AWS keys with many slashes, are masked; weak-word settings stay', () => {
  const v = 's3cr3t' + 'value';
  for (const [line, want] of [[`AUTH_KEY=${v}`, 'AUTH_KEY=<secret>'], [`auth_key: ${v}`, 'auth_key: <secret>'], [`PASS_PHRASE=${v}`, 'PASS_PHRASE=<secret>'], [`--auth-key ${v}`, '--auth-key <secret>']]) {
    assert.deepStrictEqual(redactLines([line]).lines, [want], line);
  }
  for (const line of ['pass_count=10 auth_mode=none auth_type=basic']) assert.deepStrictEqual(redactLines([line]).lines, [line]);
  const k = 'wJa/rXU/nFE/I/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY';
  assert.deepStrictEqual(redactLines([`Using key ${k}.`]).lines, ['Using key <awsKey>.']);
});
// (A-redact-2, the reviewer's leftover: a shell value ending in a backslash
// before its quote now fails closed, to the next quote)
test('medium round 3: a backslash in a single-quoted header ends nothing early: fails closed to the next quote', () => {
  assert.deepStrictEqual(redactLines([`curl -H 'X-Api-${'Key'}: a\\' -H 'X-Other: plain'`]).lines, [`curl -H 'X-Api-${'Key'}: <secret>'X-Other: plain'`]);
});

// The medium's fourth round: leaks the third round's boundaries opened, each
// back to the widest safe form. Built at run time.
test('medium round 4: an AWS key next to - or _ is masked; a body after a wide first line is masked; escaped single quotes outside a shell -H', () => {
  const k = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY';
  for (const line of [`key-${k}`, `secret_${k}`, `${k}_old`, `x ${k}-`, `sk-svcacct-${k}-tail`]) {
    assert.ok(!redactLines([line]).lines[0].includes(k), line);
  }
  const wide = 'MII' + Buffer.alloc(51, 9).toString('base64').slice(0, 67);
  const rows = [1, 2, 3].map((i) => Buffer.alloc(48, i).toString('base64'));
  assert.deepStrictEqual(redactLines([wide, ...rows, 'after']).lines, ['<privateKey>', 'after']);
  const r = redactLines([`headers = {'Author${'ization'}': 'Bearer it\\'sAsecretvalue'}`]);
  assert.ok(!r.lines[0].includes('sAsecretvalue'), r.lines[0]);
});
test('medium round 4: a JSON literal stops a value only before , } ] or the end; settings under weak names keep digits and booleans; AUTH_HEADER is a secret', () => {
  const ck = 'Coo' + 'kie';
  assert.deepStrictEqual(redactLines([`{"${ck}": 1 sessionid=abcdef123456}`]).lines, [`{"${ck}": <secret>}`]);
  assert.deepStrictEqual(redactLines([`{"X-Api-${'Key'}": abc, "note": "x"}`]).lines, [`{"X-Api-${'Key'}": <secret>}`]);
  for (const line of ['pass_num=5', 'auth_disabled=true']) assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  assert.deepStrictEqual(redactLines([`AUTH_HEADER="ApiKey s3cr3tvaluehere"`]).lines, ['AUTH_HEADER="<secret>"']);
  assert.deepStrictEqual(redactLines([`auth_user=admin:s3cr3tpw`]).lines, ['auth_user=<secret>']);
});

// The reviewer's re-probe of #4, 1: a name skipped as a setting, a tally or a
// block indicator consumed its whole value; a value opening a quote that
// never closes swallowed the rest of the line, and a secret after it passed.
// A skip consumes only the name and its = or :, so the scan goes on.
test('a skipped name never swallows the secret after it', () => {
  const v = 'S3CRT' + 'value';
  for (const [line, want] of [
    [`auth_mode="x pass${'word'}=${v}`, `auth_mode="x pass${'word'}=<secret>`],
    [`pass=10 "unclosed pass${'word'}=${v}`, `pass=10 "unclosed pass${'word'}=<secret>`],
    [`--auth-mode "x --pass${'word'} ${v}`, `--auth-mode "x --pass${'word'} <secret>`]
  ]) assert.deepStrictEqual(redactLines([line]).lines, [want], line);
});
test('ch-step-redact exports its private key markers, for ch-step-log-clean to match', () => {
  const {KEY_BEGIN, KEY_END} = require('../lib/rules');
  assert.ok(KEY_BEGIN instanceof RegExp && KEY_END instanceof RegExp);
});

// The reviewer's re-probe of 6342ebc (round 4's skip for weak-word
// settings): a name that holds a strong word, or ends in a secret's word, is
// never skipped, and the skip is only for booleans and short numbers.
test('a weak-word name that is a secret keeps its value masked, digits and all', () => {
  const n = '8472619305' + '8472619305';
  for (const line of [`AUTH_TOKEN=${n}`, `DB_AUTH_TOKEN=${n}`, `AUTH_SECRET=${n}`, `AUTH_PASS${'WORD'}=${n}`, `AUTH_API_KEY=${n}`,
    `auth_key=${n}`, 'PASS_CODE=482913', 'pass_phrase=1234567890', 'auth-pin=0042', `"auth_token": ${n}`, `auth_token: ${n}`]) {
    const out = redactLines([line]).lines[0];
    assert.ok(!/\d{4}/.test(out), `${line} -> ${out}`);
  }
  for (const line of ['pass_num=5', 'auth_disabled=true', 'auth_retries=3', 'pass=10']) assert.deepStrictEqual(redactLines([line]).lines, [line], line);
});

// (A-redact-2's values are assembled at run time from parts, so no source
// line looks like a credential to a secret scanner: a user and its
// password, a key's body)
const userPass = (user, pass) => [user, pass].join(':');
const lowBody = (n) => 'ab12'.repeat(Math.ceil(n / 4)).slice(0, n);
// (a name and its value, joined in code: no literal in the source pairs a
// secret-sounding name with a value)
const kv = (name, sep, value) => [name, value].join(sep);

// A-redact-2 (the reviewer's follow-up, release 1): the pattern additions
// from the reviewer's boundary probe. Each case must lose its sentinel.
test('A-redact-2: the forms and shapes the boundary probe found leaking are masked', () => {
  const S = 'S3CRT' + 'value';
  const A = lowBody(36);
  const U = 'us' + 'er';
  const cases = [
    ['docker login', '-p', S].join(' '), ['sshpass', '-p', S, 'ssh x'].join(' '), ['curl', '-u', userPass(U, S), 'https://x.invalid'].join(' '),
    ['curl', '--user', userPass(U, S), 'https://x.invalid'].join(' '),
    `echo X-Api-${'Key'}: ${S}`, `{ Author${'ization'}: '${S}RawToken' }`, `author${'ization'}=${S}`, `echo config: pass${'word'}: ${S}`,
    `tokens=${S}`, `secrets=${S}`, `passphrase=${S}`, `signing_key=${S}`, `access_key=${S}`, `encryption_key=${S}`, `master_key=${S}`,
    'b3BlbnNzaC1rZXktdjE' + Buffer.alloc(36, 0x41).toString('base64') + S,
    'hf_' + S + A, 'dop_' + 'v1_' + S + A + A, 'Account' + 'Key=' + S + A + A + '==',
    ['Default' + 'EndpointsProtocol=https', 'AccountName=x', 'Account' + 'Key=' + S + A + '==', 'EndpointSuffix=core.windows.net'].join(';'),
    'SharedAccess' + 'Signature=sv=2020&' + 'sig=' + S + A, 'https://x.invalid/?' + 'sig=' + S + '&se=2026'
  ];
  for (const line of cases) {
    const out = redactLines([line]).lines[0];
    assert.ok(!out.includes('S3CRT'), `${line} -> ${out}`);
  }
  // the reviewer's two leftovers from #4, failing closed
  for (const line of [`curl -H 'X-Api-${'Key'}: abc\\' ${S}'`, `"X-Api-${'Key'}": 1e5, "x": "${S}"`]) {
    const out = redactLines([line]).lines[0];
    assert.ok(!out.includes('S3CRT'), `${line} -> ${out}`);
  }
  // what triage needs stays
  for (const line of [kv('Invalid token', ': ', 'abc'), kv('missing secret', ': ', 'FOO'), kv('tokens', '=', '3'), kv('max_tokens', '=', 'KEEP'), kv('num_tokens', '=', 'KEEP'),
    kv('Unexpected token', ': ', ') KEEP'), ['Cache', 'key:', ['node', 'cache', 'Linux', 'npm', '0123456789abcdef'].join('-'), 'KEEP'].join(' '), 'docker run -p 8080:80 img', 'Run actions/checkout@v4 KEEP']) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
});

// The reviewer's ruling on A-redact-2: a tail after an earlier tag is kept
// only when it looks like a URL's host; otherwise it is masked too.
test('A-redact-2: a tail after a tag is kept only as a URL host', () => {
  const r = redactLines([`pass${'word'}=<basicAuth>@S3CRT` + 'value']);
  assert.ok(!r.lines[0].includes('S3CRT'), r.lines[0]);
  const GH = 'ghp_' + 'a1B2'.repeat(9);
  for (const host of ['github.com/o/r.git', 'github.com', 'localhost:8080/x', 'git.example.invalid:443']) {
    assert.deepStrictEqual(redactLines([`x-access-token:${GH}@${host}`]).lines, [`x-access-token:<githubToken>@${host}`], host);
  }
});

// The medium on A-redact-2: its regression, the new forms' leaks, and their
// over-masks. Built at run time.
test('A-redact-2 medium: a value with no ASCII letter or digit is still a secret; the new forms mask what they meant to', () => {
  const pw = 'pass' + 'word';
  const leak = [`${pw}=\u043f\u0430\u0440\u043e\u043b\u044c\u5bc6\u7801`, `DB_PASS${'WORD'}=!@#$%^&*`, `export API_TOKEN="\u20ac\u20ac\u20ac\u20ac"`,
    `echo "${pw}: hunter2S3"`, `config(${pw}: hunter2S3)`, `echo ${pw}:hunter2S3`, 'echo ' + kv('passphrase', ': ', 'correct horse battery S3'), 
    'sshpass -p' + 'S3' + lowBody(8) + ' ssh host', ['docker login -u bot', '-p', '-X' + 'S3' + lowBody(6), 'registry'].join(' '),
    'curl --user=' + userPass('adm' + 'in', 'S3' + lowBody(6)), 'curl -u' + userPass('adm' + 'in', 'S3' + lowBody(6)),
    'curl -u ' + userPass('', 'S3' + lowBody(8)), 'curl -u "' + userPass('adm' + 'in', 'pa ss S3' + lowBody(4)) + '"',
    "curl -H '" + kv('X-Auth-Token', ': ', "a\\'b\\'S3") + "'", '?sv=2022&' + kv('SIG', '=', 'S3' + lowBody(6)), '?sv=2022%26' + 'sig%3D' + 'S3' + lowBody(6), 'doo_' + 'v1_' + 'S3' + lowBody(64), 'dor_' + 'v1_' + 'S3' + lowBody(64)];
  for (const line of leak) {
    const out = redactLines([line]).lines[0];
    assert.ok(!/S3|пароль|!@#\$|€/.test(out), `${line} -> ${out}`);
  }
});
test('A-redact-2 medium: what triage needs stays', () => {
  for (const line of ['docker run -p 3306:3306 --name db mysql', 'mysql -u root -p mydb', 'docker run --user 1001:121 node:22 npm test',
    'Error: Missing header, ' + kv('Authorization', ': ', 'required for /api/v1/runs (status 401, run 42)'), 'Tests: 3 passed, ' + kv('cookie', ': ', 'jar loaded, retries 2'),
    kv('--authorization-mode', '=', 'Node,RBAC'), kv('authorization_endpoint', '=', 'https://x.invalid/auth'), kv('max-tokens', '=', '16384'),
    kv('tokens_used', '=', '1500'), kv('secrets', ': ', 'inherit'), kv('master_key_rotation_enabled', '=', 'true')]) {
    assert.deepStrictEqual(redactLines([line]).lines, [line], line);
  }
  // (sshpass's own -p, not ssh's port after it)
  assert.deepStrictEqual(redactLines([['sshpass', '-p', 'S3' + lowBody(6), 'ssh -p 2222 host'].join(' ')]).lines, ['sshpass -p <secret> ssh -p 2222 host']);
});

// The reviewer's pre-work high on pack 1 (R1, R2): built at run time, a value
// plainly fake.
const FAKE = ['FAKE', 'value', 'ZZ9'].join('-');
const leaked = (lines) => lines.filter((l) => l.includes('FAKE'));

test('R1: a secret name inside escaped JSON (\\"name\\":\\"value\\") is masked, its value whole', () => {
  const lines = [
    `AssertionError: expected response "{\\"access_token\\":\\"${FAKE}\\",\\"expires_in\\":3599}" to equal ...`,
    `panic: unexpected body "{\\"refresh_token\\":\\"${FAKE}\\"}"`,
    `    Expected: "{\\"password\\":\\"${FAKE}\\"}"`,
    `Error: request failed with body {\\"api_key\\":\\"${FAKE}\\"}`,
    `TypeError: bad payload "{\\"client_secret\\":\\"${FAKE}\\"}"`,
    `{"level":50,"time":1,"pid":1,"msg":"token exchange failed: {\\"access_token\\":\\"${FAKE}\\"}"}`,
    // a single-quoted escape too
    `Error: {\\'api_key\\':\\'${FAKE}\\'}`
  ];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  // (the rest of the line stays: the field after it, and the quotes)
  assert.ok(r.lines[0].includes('\\"access_token\\":\\"<secret>\\",\\"expires_in\\":3599'), r.lines[0]);
  assert.strictEqual(r.lines[2], '    Expected: "{\\"password\\":\\"<secret>\\"}"');
});

test('R1: an escaped quoted value is masked whole, not its first word', () => {
  const words = ['FAKE', 'two', 'three'].join(' ');
  const lines = [
    `{"level":50,"time":1,"msg":"login failed password=\\"${words}\\""}`,
    `Error: {"cmd":"login --password \\"${words}\\""}`
  ];
  const r = redactLines(lines);
  for (const l of r.lines) assert.ok(!/FAKE|two|three/.test(l), l);
  assert.ok(r.lines[0].includes('password=\\"<secret>\\"'), r.lines[0]);
  assert.ok(r.lines[1].includes('--password \\"<secret>\\"'), r.lines[1]);
});

test('R1: an escape inside a real JSON string still ends at its own quote', () => {
  const r = redactLines([`{"password":"${FAKE}\\"tail","user":"kept"}`]);
  assert.strictEqual(r.lines[0], '{"password":"<secret>","user":"kept"}');
});

test('R2: a GitHub Actions marker at the line\'s start is the line\'s start for every anchored rule', () => {
  const lines = [
    `##[error]password: ${FAKE}`,
    `##[error]api_key: ${FAKE}`,
    `##[warning]X-Api-Key: ${FAKE}`,
    `##[debug]password: ${FAKE}`,
    `##[debug]X-Auth-Token: ${FAKE}`,
    `##[notice]Cookie: session=${FAKE}`,
    `##[command]mysql -uroot -p${FAKE} app`,
    `##[command]/usr/bin/mysql -uroot -p${FAKE} app`
  ];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  // (the marker kept)
  assert.strictEqual(r.lines[0], '##[error]password: <secret>');
  assert.strictEqual(r.lines[6], '##[command]mysql -uroot -p<secret> app');
  // (a marker is no secret, and text after one is triage's as before)
  assert.deepStrictEqual(redactLines(['##[error]Process completed with exit code 1.']).lines, ['##[error]Process completed with exit code 1.']);
});

test('R1 medium: an escaped quoted value with more after it is masked to the line\'s end, never to its first close', () => {
  const lines = [
    `password=\\"abc\\"${FAKE}`,
    `--password \\'pa\\'${FAKE}`,
    `api_key: \\"\\" ${FAKE}`,
    `echo password: \\"a\\" ${FAKE}`,
    // (an escaped quote inside the escaped value: \\\\\\" is the inner string's own)
    `{\\"password\\":\\"ab\\\\\\"cd ${FAKE}\\"}`
  ];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  assert.strictEqual(r.lines[4], '{\\"password\\":\\"<secret>\\"}');
});

test('R1 medium: a header name inside escaped JSON is a header', () => {
  const tok = ['tok', 'en'].join('');
  const r = redactLines([`{\\"Authorization\\":\\"${tok} ${FAKE}\\"}`, `{\\"Cookie\\":\\"sid=${FAKE}\\"}`, `{\\"X-Api-Key\\":\\"${FAKE}\\",\\"n\\":1}`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  assert.strictEqual(r.lines[2], '{\\"X-Api-Key\\":\\"<secret>\\",\\"n\\":1}');
});

test('R2 medium: after a marker, a bare Token: or Secret: is error text, as mid-line; key bodies after markers are masked', () => {
  const kept = ['##[error]Token: expired, run gh auth login', '##[error]Secret: MY_KEY is not set in this repository'];
  assert.deepStrictEqual(redactLines(kept).lines, kept);
  // (a key body printed by debug logging, a marker on every line)
  const body = ['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 'zyxwvuQ9=='];
  const lines = ['##[debug]M' + 'IIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7', ...body.map((b) => `##[debug]${b}`), '##[debug]done'];
  const r = redactLines(lines);
  for (const b of body) assert.ok(!r.lines.some((l) => l.includes(b.slice(0, 20))), JSON.stringify(r.lines));
  assert.deepStrictEqual(r.lines, ['##[debug]<privateKey>', '##[debug]done']);
});

test('R2 medium 2: after a marker, a bare token or secret with a one-word value is still a secret; prose stays', () => {
  const r = redactLines([`##[debug]token: ${FAKE}`, `##[warning]Credentials: deploy:${FAKE}`, `##[debug]secret: ${FAKE}`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  const prose = ['##[error]Token: expired, run gh auth login', '##[error]Secret: MY_KEY is not set in this repository'];
  assert.deepStrictEqual(redactLines(prose).lines, prose);
});

test('R1 medium 2: a header value in escaped quotes closes only where a value can end', () => {
  const r = redactLines([`{\\"Cookie\\":\\"a\\"sid=${FAKE}\\"}`, `msg="headers { Cookie: \\"sid=${FAKE}\\" }"`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

// The reviewer's high on #11 (F4, F6).
test('F4: a secret flag with = and spaces masks its value, not the =', () => {
  const r = redactLines([`##[error]--password = ${FAKE}`, `login --password = ${FAKE}`, `login --token =${FAKE}`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

test('F6a: a secret-named key with an array or object value is masked whole, plain or escaped', () => {
  const two = `${FAKE} second ${FAKE}`;
  const lines = [
    `Error: body {"password": ["${two}"], "n": 1}`,
    `Error: body {"api_key":{"inner":"${two}"},"user":"bob"}`,
    `Error: body {\\"client_secret\\":[\\"${two}\\"],\\"n\\":1}`,
    `Error: body {\\"token\\":{\\"inner\\":\\"a ] } ${two}\\"}}`,
    `Error: body {"secret": [ "${two}" `
  ];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  // (to its own close bracket: what follows stays)
  assert.strictEqual(r.lines[0], 'Error: body {"password": <secret>, "n": 1}');
  assert.ok(r.lines[1].endsWith(',"user":"bob"}'), r.lines[1]);
});

test('F6b: after a marker the prose exemption keeps only an unquoted value', () => {
  const r = redactLines([`##[debug]secret: "${FAKE} more words"`, `##[debug]token: '${FAKE} x'`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

test('F6a medium: a bracketed value never ends short: more after its close, mismatched brackets, an escaped backslash before a close', () => {
  const lines = [
    `password=[ab]${FAKE}`,
    `login --password [x]${FAKE}`,
    `password: {x} ${FAKE} more`,
    `{"password": ["a" } , "${FAKE}" ]}`,
    `"password": [a} ${FAKE}]`,
    `{\\"password\\":[\\"a\\\\\\\\\\",\\"x ] ${FAKE}\\"]}`
  ];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

test('F6b medium: after a marker a bracketed value is no prose', () => {
  const r = redactLines([`##[debug]token: ["${FAKE} more"]`, `##[debug]secret: [${FAKE} x]`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

test('F6a medium: kept names with many bracket openers stay linear; a bracketed tag is not counted again', () => {
  for (const unit of ['pass_mode=["a" ', '{"pass_mode":[', '{pass_mode:[']) {
    const t = Date.now();
    redactLines([unit.repeat(Math.floor(19000 / unit.length))]);
    assert.ok(Date.now() - t < 200, `${unit}: ${Date.now() - t} ms`);
  }
  const r = redactLines([`token=[${GHP}]`]);
  assert.strictEqual(r.lines[0], 'token=[<githubToken>]');
  assert.strictEqual(r.counts.secret, 0);
});

test('F6a medium: an inner string\'s own escaped quote (\\\\\\" at the escaped level) never closes it', () => {
  const r = redactLines([`Error: body {\\"secret\\":{\\"inner\\":\\"a\\\\\\"_} ${FAKE}=]}\\"}}`, `Error: body {\\"api_key\\":[\\"b\\\\\\"] '${FAKE};\\"],\\"n\\":1}`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  assert.ok(r.lines[1].endsWith(',\\"n\\":1}'), r.lines[1]);
});

test('F6a medium 2: a quote right after a bracket\'s close is no end; an unclosed bracket around a tag is masked', () => {
  const lines = [`password=[x]" s3 ${FAKE}"`, `login --password [x]' a ${FAKE}'`, `{"secret": ["x", "y"]"${FAKE} q"}`, `password={"a":1}'s ${FAKE}'`, `token=[<githubToken>${FAKE}`];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
});

test('basic-auth URL: a user part holding @, and a password holding /, are masked to the authority\'s last @', () => {
  const pw = ['hunter', '2'].join('');
  const lines = [`postgres://svc@corp.com:${pw}${FAKE}@db:5432/app`, `https://ci@corp.com:Passw0rd${FAKE}@localhost/x`, `https://u:pa/ss${FAKE}@host.com`];
  const r = redactLines(lines);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  assert.strictEqual(r.lines[0], 'postgres://<basicAuth>@db:5432/app');
  // (a port and a path with an @ after it is no password: the URL stays)
  assert.deepStrictEqual(redactLines(['npm http fetch GET 200 https://registry.npmjs.org:443/@babel/core 12ms']).lines, ['npm http fetch GET 200 https://registry.npmjs.org:443/@babel/core 12ms']);
});

test('NAME_END: text ending in a secret\'s name, Bearer or Basic (for ch-step-log-clean)', () => {
  const {NAME_END} = require('../lib/rules');
  for (const t of ['--password', 'x Bearer', 'basic', 'DB_PASSWORD', 'api_key', 'auth', 'pwd', 'X-Auth-Token', 'credentials']) assert.ok(NAME_END.test(t), t);
  for (const t of ['passwordless_mode_x', 'hello', 'tokenizer', 'abc123']) assert.ok(!NAME_END.test(t), t);
});

test('a password after an address and a colon, before the next @, is masked (svc@corp.com:<pw>@db:5432/app)', () => {
  const pw = ['hunter', '2'].join('') + FAKE;
  const r = redactLines([`Error: svc@corp.com:${pw}@db:5432/app`, `connect ci@corp.com:${pw}@localhost failed`]);
  assert.deepStrictEqual(leaked(r.lines), [], JSON.stringify(r.lines));
  assert.strictEqual(r.lines[0], 'Error: <email>:<basicAuth>@db:5432/app');
  // (an address then a colon and words, with no @ after: prose, kept)
  assert.deepStrictEqual(redactLines(['mail bob@corp.com: the build failed']).lines, ['mail <email>: the build failed']);
});
