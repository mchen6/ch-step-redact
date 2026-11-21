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
// (the reviewer's high, 3) A strong word may be glued to what is before it
// (PGPASSWORD, ACCESSTOKEN, accessToken, clientSecret). A weak one is a part
// of its own after another part (MYSQL_PWD, DB_PASS, npmrc's _auth): pwd
// alone is the shell's working directory (PWD=/home/...). pass and auth may
// also stand alone, but not with a value of digits only (pass=10 is a test
// tally). A leading _ is npmrc's (:_password=, :_auth=, :_authToken=).
const STRONG = '(?:password|passwd|secret|token|api[_-]?key|credentials?|private[_-]?key)';
const WEAK = '(?:pass|pwd|auth)';
const PART = '(?:[A-Za-z0-9]{1,64}[_-])';
const SECRET_NAME = `(?:_?${PART}{0,8}[A-Za-z0-9]{0,32}${STRONG}|_?${PART}{1,8}${WEAK}|_?(?:pass|auth))(?:[_-][A-Za-z0-9]{1,64}){0,8}`;
const STANDALONE = /^_?(?:pass|auth)$/i;
// Values (the reviewer's high, 2, and its medium, 4-5): a quoted one whole,
// escapes inside it included; one whose quote never closes, to the line's
// end; an unquoted one to whitespace, or, as a key's value at the line's
// start (YAML), to the line's end: stopping at , ; or a quote would leave the
// rest of the value in view while the count says masked.
const QUOTED = `"(?:[^"\\\\\\n]|\\\\.){0,4096}"|'(?:[^'\\\\\\n]|\\\\.){0,4096}'|["'][^\\n]{0,4096}`;
const SECRET_VALUE = `(${QUOTED}|(?!["'])\\S+)`;
// (to the line's end from its first character, which is no space, so the
// spaces before it can split only one way: linear; trailing spaces trimmed
// in maskedValue)
const KEY_VALUE = `(${QUOTED}|(?!["'\\s])[^\\n]+)`;
// A value an earlier rule's tag starts is that rule's (it took the whole
// token): the tag stays. What follows it, if anything worth hiding, is
// masked too, except a URL's host (@github.com after a URL's token).
const TAG = /^<(?:jwt|basicAuth|githubToken|awsKey|token|apiKey|privateKey|secret)>/;
const TAGGED = TAG;
// An unquoted value's trailing closing punctuation is the line's, not the
// value's ("passwd=abc" in a quoted argument, {token: abc}): kept.
const CLOSING = /["')\]},;]+$/;
const SECRET_FORMS = [
  // name = value, anywhere
  // (an = that starts == is a comparison, not an assignment)
  new RegExp(`(?<![A-Za-z0-9_])(${SECRET_NAME})(["']?\\s*=(?!=)\\s*)${SECRET_VALUE}`, 'gi'),
  // name: value as a key at the line's start (YAML), its value to the end
  new RegExp(`(^\\s*(?:-\\s+)?)(${SECRET_NAME})(\\s*:\\s*)${KEY_VALUE}`, 'gi'),
  // "name": value (JSON)
  new RegExp(`(["'])(${SECRET_NAME})\\1(\\s*:\\s*)${SECRET_VALUE}`, 'gi'),
  // { name: value } mid-line (an object literal, util.inspect)
  new RegExp(`([{,]\\s*)(${SECRET_NAME})(\\s*:\\s*)${SECRET_VALUE}`, 'gi')
];
// a value masked whole, its quotes (and an unquoted one's trailing closing
// punctuation) kept -> the replacement, or null to leave it
function maskedValue(value, tag) {
  const quote = /^["']/.test(value) ? value[0] : '';
  const closed = quote !== '' && value.length > 1 && value.endsWith(quote) && value[value.length - 2] !== '\\';
  const inner = value.slice(quote.length, closed ? -1 : undefined);
  const tagged = TAG.exec(inner);
  if (tagged != null) {
    const rest = inner.slice(tagged[0].length);
    if (!/[A-Za-z0-9]/.test(rest) || rest.startsWith('@')) return null;
    return {text: quote + tagged[0] + tag + (closed ? quote : ''), counted: true};
  }
  const trailing = quote === '' ? /\s*$/.exec(value)[0] : '';
  const kept = quote === '' ? (CLOSING.exec(value.trimEnd()) || [''])[0] : (closed ? quote : '');
  return {text: quote + tag + kept + trailing, counted: true};
}
function maskSecrets(line, tag) {
  let n = 0;
  let text = line;
  SECRET_FORMS.forEach((re) => {
    text = text.replace(re, (...m) => {
      const name = m[0] === undefined ? '' : (re === SECRET_FORMS[0] ? m[1] : m[2]);
      const value = re === SECRET_FORMS[0] ? m[3] : m[4];
      if (STANDALONE.test(name) && /^\d+$/.test(value)) return m[0];
      const r = maskedValue(value, tag);
      if (r == null) return m[0];
      n++;
      return m[0].slice(0, m[0].length - value.length) + r.text;
    });
  });
  return {text, n};
}

// (the reviewer's high, 3, and its medium, 2-3, 8) Secrets that come without
// "name = value":
// - a header: at the line's start (curl -v's "> " and "< " too), after a
//   quote (its name quoted too, as JSON's), or after -H/--header: a
//   hyphenated name ending in a secret word (X-Api-Key, X-Auth-Token),
//   Authorization or Proxy-Authorization, Cookie or Set-Cookie. Its value:
//   a quoted one inside its quotes, else to the quote the header opened
//   with, else to the line's end (a scheme and its credential together,
//   every cookie). cache-key and primary-key are no secret names;
// - a command-line flag naming a secret, its value the next word or a
//   quoted string (--password s3cr3t, --password "s3 cr3t"), not a flag that
//   names a file, a path or the like (--token-file /etc/app/tok);
// - mysql's own -p<password> (quoted too), only on a line that runs mysql,
//   mysqldump, mysqladmin or mariadb (-p8080:80 is docker's port).
const HEADER_NAME = `(?:[A-Za-z0-9]{1,32}-){1,6}[A-Za-z0-9]{0,32}(?:${STRONG}|${WEAK})|(?:proxy-)?authorization|(?:set-)?cookie`;
const HEADER = new RegExp(`((?:^[<>]\\s+|^|["']|(?:^|\\s)(?:-H|--header)\\s+["']?)\\s*)(${HEADER_NAME})(["']?)(\\s*:\\s*)`, 'gi');
const FLAG = new RegExp(`((?:^|\\s)--?(${SECRET_NAME}))(\\s+)(${QUOTED}|(?![-<])\\S+)`, 'gi');
const NOT_A_SECRET_FLAG = /[_-](?:file|path|dir|env|url|name|type|id|count|length|size|var|header)$/i;
const MYSQL = /(?:^|[\s/])(?:mysql|mysqldump|mysqladmin|mariadb)(?:\s|$)/;
const MYSQL_P = new RegExp(`(\\s-p)(${QUOTED}|[^\\s"']+)`, 'g');
function maskHeadersAndFlags(line, tag) {
  let n = 0;
  // headers and cookies: one forward scan, each value replaced whole
  let out = '';
  let pos = 0;
  HEADER.lastIndex = 0;
  for (let m = HEADER.exec(line); m !== null; m = HEADER.exec(line)) {
    let from = m.index + m[0].length;
    const opened = m[1].trimEnd();
    const openQuote = /["']$/.test(opened) && m[3] === '' ? opened.slice(-1) : null;
    let end;
    if (line[from] === '"' || line[from] === "'") {
      const q = line[from];
      from += 1;
      const close = line.indexOf(q, from);
      end = close === -1 ? line.length : close;
    } else if (openQuote != null) {
      const close = line.indexOf(openQuote, from);
      end = close === -1 ? line.length : close;
    } else end = line.length;
    if (end <= from || TAGGED.test(line.slice(from))) continue;
    out += line.slice(pos, from) + tag;
    pos = end;
    n++;
    HEADER.lastIndex = end;
  }
  let text = out + line.slice(pos);
  text = text.replace(FLAG, (whole, flag, name, space, value) => {
    if (NOT_A_SECRET_FLAG.test(name)) return whole;
    const r = maskedValue(value, tag);
    if (r == null) return whole;
    n++;
    return flag + space + r.text;
  });
  if (MYSQL.test(text)) {
    text = text.replace(MYSQL_P, (whole, flag, value) => {
      const r = maskedValue(value, tag);
      if (r == null) return whole;
      n++;
      return flag + r.text;
    });
  }
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
  // (the reviewer's high, 4) GitHub's installation token v1.<40 hex> (a legacy
  // 40-hex token is masked below, only where a token is said to follow: a
  // bare 40-hex run is a commit SHA, which triage needs, and stays)
  {type: 'githubToken', tag: '<githubToken>', re: /(?<![A-Za-z0-9.])v1\.[0-9a-f]{40}(?![0-9a-f])/g},
  {type: 'awsKey', tag: '<awsKey>', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g},
  {type: 'awsKey', tag: '$1$2<awsKey>', re: /\b(aws_secret_access_key)(\s*[=:]\s*)["']?[A-Za-z0-9/+]{40}["']?/gi},
  {type: 'bearerToken', tag: '<token>', re: /\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi},
  {type: 'bearerToken', tag: '<token>', re: /\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}/gi},
  {type: 'bearerToken', tag: '$1<token>', re: /(authorization:\s*)token\s+[A-Za-z0-9_-]{16,}/gi},
  // (4, after the Authorization header's own rules) a legacy 40-hex token
  // where a token is said to follow
  {type: 'githubToken', tag: '$1<githubToken>', re: /(\b(?:token|bearer)\s+)[0-9a-f]{40}(?![0-9A-Za-z])/gi},
  // (4; the medium, 6, 8 and 9b) a bare AWS secret access key: exactly 40
  // base64 characters, starting with a letter or digit, with an upper and a
  // lower case letter and a digit (a commit SHA has no upper case), never
  // part of a longer run, a path or a name (nothing of / . - _ around it).
  // After Basic and Bearer, so their credentials stay theirs.
  {type: 'awsKey', tag: '<awsKey>', re: /(?<![A-Za-z0-9/+=._-])(?=[A-Za-z0-9/+]{0,39}[A-Z])(?=[A-Za-z0-9/+]{0,39}[a-z])(?=[A-Za-z0-9/+]{0,39}[0-9])[A-Za-z0-9][A-Za-z0-9/+]{39}(?![A-Za-z0-9/+=._-])/g},
  // Vendors' key shapes: Slack, Stripe (secret and restricted), Google, npm;
  // (4) GitLab, Anthropic, OpenAI (project and legacy), and a Slack webhook
  // URL (its path is the secret).
  {type: 'apiKey', tag: '<apiKey>', re: /(?<![A-Za-z0-9])(?:xox[baprs]-[A-Za-z0-9-]{10,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{32,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})(?![A-Za-z0-9_-])/g},
  {type: 'apiKey', tag: '<apiKey>', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{1,256}/g},
  // (4) a bare PEM key body (no BEGIN line): base64 from MII, MIG or MHc (DER's
  // SEQUENCE header), 40 or more characters
  {type: 'privateKey', tag: '<privateKey>', re: /(?<![A-Za-z0-9/+])M(?:II|IG|Hc)[A-Za-z0-9+/]{37,}={0,2}/g},
  // A secret assigned in an environment dump, a config or a command line: the
  // value goes (a quoted one whole), the name stays.
  {type: 'secret', tag: '<secret>', mask: maskHeadersAndFlags},
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
// (the medium on the reviewer's high, 1) A bare key body -- a whole line of
// base64 from MII, MIG or MHc (DER's SEQUENCE header), 40 or more characters,
// with no BEGIN line before it -- opens a block of its own: it and the base64
// lines after it are one tag, up to the first line that is not one. A
// continuation line is base64 only and looks like it (a digit, + / or =, or
// both cases), so a plain word ("next") ends it.
const BARE_BODY = /^\s*M(?:II|IG|Hc)[A-Za-z0-9+/]{37,}={0,2}\s*$/;
const BODY_LINE = /^\s*[A-Za-z0-9+/]{1,100}={0,2}\s*$/;
const looksEncoded = (l) => /[0-9+/=]/.test(l) || (/[A-Z]/.test(l) && /[a-z]/.test(l));
function maskKeyBlocks(lines, counts) {
  const out = [];
  let inside = false; // within a block opened on an earlier line
  let bare = false; // within a bare key body
  for (const line of lines) {
    if (bare) {
      if (BODY_LINE.test(line) && looksEncoded(line)) continue;
      bare = false;
    }
    if (!inside && BARE_BODY.test(line)) {
      counts.privateKey++;
      out.push(KEY_TAG);
      bare = true;
      continue;
    }
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
// Every line given back is at most LINE_MAX characters, cut with … (the
// reviewer, 2026-11-13), as ch-step-log-clean and ch-step-error-patterns
// cut. Masked first, then cut: a line cut first could split a secret at
// the cut and leave the half in view unmatched. A line taken in may be up to
// IN_MAX (ch-step-log-clean's bound; a longer one is omitted whole, below): the
// rules are linear in it. A cut never falls between the halves of a
// surrogate pair.
const LINE_MAX = 500;
const IN_MAX = 20000;
function cutTo(t, max) {
  if (t.length <= max) return t;
  let end = max - 1;
  const c = t.charCodeAt(end - 1);
  if (c >= 0xd800 && c <= 0xdbff) end--;
  return `${t.slice(0, end)}…`;
}
const cutLine = (t) => cutTo(t, LINE_MAX);
// A line over IN_MAX characters is never cut and kept: it is replaced whole
// by "(a line of N characters, omitted)" (the reviewer, 2026-11-13). A cut
// anywhere in it can split a secret, a token or a quoted value holding
// spaces (password="Zq9 Wx7 …"), whose head then matches no pattern; masks
// earlier in the line shrink it until that head is within the 500 kept.
// Lines that long do not help triage. ch-step-log-clean omits them the same
// way.
const omitted = (t) => (t.length > IN_MAX ? `(a line of ${t.length} characters, omitted)` : t);

function redactLines(lines) {
  const counts = Object.fromEntries(TYPES.map((t) => [t, 0]));
  // Private key blocks are found on the full lines, before a long line is
  // omitted: a BEGIN or END marker on a line over IN_MAX still opens or
  // closes its block, so the body after a long BEGIN line never passes (the
  // reviewer's high, 1). The markers' patterns are bounded, so this is linear.
  const masked = maskKeyBlocks(lines, counts).map(omitted).map((line) => {
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
    return cutLine(out);
  });
  return {lines: masked, counts};
}

module.exports = {redactLines, TYPES, LINE_MAX, IN_MAX, cutTo, omitted};
