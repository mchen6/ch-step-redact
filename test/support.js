'use strict';
// What a handler finds in the runtime and a test calling it directly must
// supply: the global DeviceError, countinghouse's own (the pinned devDependency).
const {DeviceError} = require('countinghouse/lib/countinghouse-error');

if (typeof globalThis.DeviceError !== 'function') globalThis.DeviceError = DeviceError;

module.exports = {DeviceError};
