'use strict';
// ch-step-redact/redactService.redact: {lines} -> {lines, counts}.
const {redactLines} = require('../../lib/rules');

module.exports = async (input) => {
  const lines = input != null ? input.lines : null;
  if (!Array.isArray(lines) || !lines.every((l) => typeof l === 'string')) {
    throw new DeviceError('ARGUMENTS_INVALID', 'lines must be an array of strings');
  }
  return {output: redactLines(lines)};
};
