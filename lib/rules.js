'use strict';
// Masks secrets and personal data in text lines before any of them can reach a
// result. A pure function of its input: no disk, no network, no state.
//
// Starts from countinghouse's examples/log-triage pii-redact (its e-mail masker
// and its bearer, card, IPv4 and phone patterns, unchanged in what they match)
// and adds the secrets a CI log carries: GitHub tokens, AWS access key ids,
// private key blocks, JWTs and credentials in URLs.
//
// Order is load-bearing, as in the example: secrets first, so the e-mail and
// digit patterns never see inside one (a URL password "pw@example.com" must be
// masked as a credential, not half-masked as an address); card before phone.
// A match is replaced whole by its tag, so no prefix or length leaks.
//
// Every pattern is linear on hostile input: lengths are bounded where a
// pattern could otherwise scan to the end of the line from many starts, a JWT
// is found with a single forward scan, and so is a private key block (PGP's
// "PRIVATE KEY BLOCK" included), never [\s\S]*?.

const TYPES = ['bearerToken', 'githubToken', 'awsKey', 'apiKey', 'secret', 'privateKey', 'jwt', 'basicAuthUrl', 'email', 'ipv4', 'card', 'phone'];

const EMAIL = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}';

// The example's e-mail masker: its lookbehind lets a match start only at the
// beginning of a run of local-part characters (linear on a long run with no
// @); a sticky copy without the lookbehind takes a match starting exactly
// where the previous one ended (a@b.com_c@d.org).
// Not right after '://': a URL's user part (ssh://git@github.com) is no address.
const EMAIL_SEARCH = new RegExp(`(?<![A-Za-z0-9._%+-])(?<!:\\/\\/)${EMAIL}`, 'g');
const EMAIL_RESUME = new RegExp(EMAIL, 'y');

function maskEmails(line, tag) {
  const search = EMAIL_SEARCH;
  const resume = EMAIL_RESUME;
  let out = '';
  let n = 0;
  let pos = 0;
  for (;;) {
    resume.lastIndex = pos;
    let m = resume.exec(line);
    if (m === null) {
      search.lastIndex = pos;
      m = search.exec(line);
      if (m === null) break;
    }
    out += line.slice(pos, m.index) + tag;
    pos = m.index + m[0].length;
    n++;
  }
  return {text: out + line.slice(pos), n};
}

// A JWT, eyJ<10+>.<10+>.<10+> over [A-Za-z0-9_-], found in one linear pass:
// the end of every run of segment characters is computed once, so each "eyJ"
// start is checked in constant time (a regex rescans the run from every start).
const SEGMENT = /[A-Za-z0-9_-]/;
const WORD = /[A-Za-z0-9_]/;
function maskJwts(line, tag) {
  if (!line.includes('eyJ')) return {text: line, n: 0};
  const runEnd = new Int32Array(line.length + 1);
  runEnd[line.length] = line.length;
  for (let i = line.length - 1; i >= 0; i--) runEnd[i] = SEGMENT.test(line[i]) ? runEnd[i + 1] : i;
  const segment = (from) => (from < line.length ? runEnd[from] : from);
  let out = '';
  let n = 0;
  let pos = 0;
  for (let p = line.indexOf('eyJ'); p !== -1; p = line.indexOf('eyJ', p + 1)) {
    if (p < pos || (p > 0 && WORD.test(line[p - 1]))) continue;
    // The regex's segments are greedy, so each ends where its run ends.
    const e1 = segment(p);
    if (e1 - p < 13 || line[e1] !== '.') continue;
    const e2 = segment(e1 + 1);
    if (e2 - e1 - 1 < 10 || line[e2] !== '.') continue;
    const e3 = segment(e2 + 1);
    if (e3 - e2 - 1 < 10) continue;
    out += line.slice(pos, p) + tag;
    pos = e3;
    n++;
  }
  return {text: out + line.slice(pos), n};
}

function luhn(match) {
  const digits = match.replace(/\D/g, '');
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

// A card number is 13-19 digits that pass the Luhn check; a 13-digit epoch
// millisecond mostly does not. A digit run may hold more than the card (an
// expiry, a count after it), so whole digit groups are tried, the whole run
// first, then shorter runs of groups from the left.
const DIGIT_RUN = /\b(?:\d[ -]?){12,18}\d\b/g;
function maskCards(line, tag) {
  let n = 0;
  const text = line.replace(DIGIT_RUN, (run) => {
    const groups = [...run.matchAll(/\d+/g)].map((m) => ({at: m.index, end: m.index + m[0].length, digits: m[0]}));
    for (let len = groups.length; len >= 1; len--) {
      for (let i = 0; i + len <= groups.length; i++) {
        const digits = groups.slice(i, i + len).map((g) => g.digits).join('');
        if (digits.length < 13 || digits.length > 19 || !luhn(digits)) continue;
        n++;
        return run.slice(0, groups[i].at) + tag + run.slice(groups[i + len - 1].end);
      }
    }
    return run;
  });
  return {text, n};
}

// Assigned secrets. A name is word parts joined by _ or - with one part (or
// api_key) naming a secret: DB_PASSWORD, SECRET_KEY, client_secret, api-key;
// max_tokens is not one. "name = value" counts anywhere; "name: value" only as
// a key, at the start of a line or quoted, so the error text "Unexpected
// token: )" stays. A value an earlier rule tagged (<…>) is left alone.
// Bounded (at most 8 parts of 64 on each side) so a long run of joined parts
// costs a fixed amount per start: unbounded, '-eyJ' x 20000 took 7 s.
const SECRET_NAME = '(?:[A-Za-z0-9]{1,64}[_-]){0,8}(?:password|passwd|secret|token|api[_-]?key)(?:[_-][A-Za-z0-9]{1,64}){0,8}';
const SECRET_VALUE = `("[^"\\n]{0,4096}"|'[^'\\n]{0,4096}'|(?![<"'])[^\\s"',;]+)`;
const SECRET_FORMS = [
  new RegExp(`(?<![A-Za-z0-9_])(${SECRET_NAME})(["']?\\s*=\\s*)${SECRET_VALUE}`, 'gi'),
  new RegExp(`(^\\s*(?:-\\s+)?)(${SECRET_NAME})(\\s*:\\s*)${SECRET_VALUE}`, 'gi'),
  new RegExp(`(["'])(${SECRET_NAME})\\1(\\s*:\\s*)${SECRET_VALUE}`, 'gi')
];
function maskSecrets(line, tag) {
  let n = 0;
  let text = line;
  SECRET_FORMS.forEach((re, form) => {
    text = text.replace(re, (...m) => {
      const value = form === 0 ? m[3] : m[4];
      const quote = /^["']/.test(value) ? value[0] : '';
      if (value.slice(quote.length).startsWith('<')) return m[0];
      n++;
      return m[0].slice(0, m[0].length - value.length) + quote + tag + quote;
    });
  });
  return {text, n};
}

// Applied in this order, to every line, after private key blocks are gone.
// A URL's credentials before a token type, so a token used as a URL password
// is masked (and counted) once.
const PATTERNS = [
  {type: 'jwt', tag: '<jwt>', mask: maskJwts},
  // A password is required: a bare user (ssh://git@github.com) is no secret.
  // A password, or a user long enough to be a token (https://glpat-…@host);
  // a short bare user (ssh://git@github.com) is no secret.
  {type: 'basicAuthUrl', tag: '://<basicAuth>@', re: /:\/\/(?:[^/:@\s]{0,1024}:[^/@\s]{1,1024}|[^/:@\s]{16,1024})@/g},
  {type: 'githubToken', tag: '<githubToken>', re: /(?<![A-Za-z0-9])(?:gh[oprsu]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g},
  {type: 'awsKey', tag: '<awsKey>', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g},
  {type: 'awsKey', tag: '$1$2<awsKey>', re: /\b(aws_secret_access_key)(\s*[=:]\s*)["']?[A-Za-z0-9/+]{40}["']?/gi},
  {type: 'bearerToken', tag: '<token>', re: /\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi},
  {type: 'bearerToken', tag: '<token>', re: /\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}/gi},
  {type: 'bearerToken', tag: '$1<token>', re: /(authorization:\s*)token\s+[A-Za-z0-9_-]{16,}/gi},
  // Vendors' key shapes: Slack, Stripe (secret and restricted), Google, npm.
  {type: 'apiKey', tag: '<apiKey>', re: /(?<![A-Za-z0-9])(?:xox[baprs]-[A-Za-z0-9-]{10,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])/g},
  // A secret assigned in an environment dump, a config or a command line: the
  // value goes (a quoted one whole), the name stays.
  {type: 'secret', tag: '<secret>', mask: maskSecrets},
  {type: 'email', tag: '<email>', mask: maskEmails},
  {type: 'card', tag: '<card>', mask: maskCards},
  {type: 'ipv4', tag: '<ipv4>', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g},
  {type: 'phone', tag: '<phone>', re: /(?:\+\d{1,3}[-. ]?)?(?:\(\d{3}\)|\d{3})[-. ]\d{3}[-. ]\d{4}\b/g}
];

const KEY_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const KEY_TAG = '<privateKey>';

// Private key blocks, within a line or across lines, each replaced by one tag;
// a block's inner lines are dropped, so three lines in are one line out. A
// block with no end masks everything after its start.
function maskKeyBlocks(lines, counts) {
  const out = [];
  let inside = false; // within a block opened on an earlier line
  for (const line of lines) {
    let text = '';
    let pos = 0;
    if (inside) {
      KEY_END.lastIndex = 0;
      const end = KEY_END.exec(line);
      if (end === null) continue; // an inner line: dropped
      inside = false;
      pos = end.index + end[0].length;
      text = out.pop(); // the block's tag line takes the rest of this one
    }
    for (;;) {
      KEY_BEGIN.lastIndex = pos;
      const begin = KEY_BEGIN.exec(line);
      if (begin === null) break;
      counts.privateKey++;
      text += line.slice(pos, begin.index) + KEY_TAG;
      KEY_END.lastIndex = begin.index + begin[0].length;
      const end = KEY_END.exec(line);
      if (end === null) {
        inside = true;
        pos = line.length;
        break;
      }
      pos = end.index + end[0].length;
    }
    out.push(text + line.slice(pos));
  }
  return out;
}

// -> {lines, counts}: the lines with every match replaced by its tag, and how
// many matches of each type were replaced. A zero count is not evidence that
// the text holds no secret or personal data: the patterns are what they are.
function redactLines(lines) {
  const counts = Object.fromEntries(TYPES.map((t) => [t, 0]));
  const masked = maskKeyBlocks(lines, counts).map((line) => {
    let out = line;
    for (const p of PATTERNS) {
      if (p.mask) {
        const r = p.mask(out, p.tag);
        out = r.text;
        counts[p.type] += r.n;
      } else {
        out = out.replace(p.re, (...m) => {
          counts[p.type]++;
          return p.tag.replace(/\$(\d)/g, (_, i) => m[Number(i)]);
        });
      }
    }
    return out;
  });
  return {lines: masked, counts};
}

module.exports = {redactLines, TYPES};
