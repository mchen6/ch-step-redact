'use strict';
// ch-step-redact/redactService.redact: {lines} -> {lines, counts}.
const {redactLines} = require('../../lib/rules');

module.exports = async (input, ctx) => {
  const lines = input != null ? input.lines : null;
  // A line over 20000 characters is cut to it (lib/rules.js), not refused:
  // one minified line must not cost the whole log its masking.
  if (!Array.isArray(lines) || !lines.every((l) => typeof l === 'string')) {
    throw ctx.error('INPUT_REJECTED', 'lines must be an array of strings');
  }
  return {output: redactLines(lines)};
};
