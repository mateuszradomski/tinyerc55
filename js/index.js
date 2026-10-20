const { wasmBase64 } = require('./module');

// Scratch area in the wasm memory used to pass the address in and the
// checksummed address out. It sits below the stack, which only grows down to
// a few hundred bytes under 1MB.
const SCRATCH_OFFSET = 8192;
const SCRATCH_SIZE = 64;

let loaded = false;
let validateAddressHandle = null;
let writeInput = null;
let readOutput = null;

function decodeBase64(base64) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64');
  } else {
    const binStr = atob(base64.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  }
}

function loadWasmModule() {
    const buffer = decodeBase64(wasmBase64);
    const mod = new WebAssembly.Module(buffer);
    const instance = new WebAssembly.Instance(mod);
    const memoryBuffer = instance.exports.memory.buffer;
    validateAddressHandle = instance.exports.validateAddress;

    // The input is written as UTF-8 and the returned byte count is passed as
    // the length. Any non-ASCII character makes it differ from the string
    // length and the wasm side rejects bytes outside of ASCII. Buffer is used
    // when available since it's noticeably faster than TextEncoder/Decoder.
    // The memory never grows, so the views stay valid.
    if (typeof Buffer !== 'undefined') {
        const scratch = Buffer.from(memoryBuffer, SCRATCH_OFFSET, SCRATCH_SIZE);
        writeInput = (address) => scratch.write(address, 0, SCRATCH_SIZE, 'utf8');
        readOutput = () => scratch.latin1Slice(0, 42);
    } else {
        const scratch = new Uint8Array(memoryBuffer, SCRATCH_OFFSET, SCRATCH_SIZE);
        const output = scratch.subarray(0, 42);
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        writeInput = (address) => encoder.encodeInto(address, scratch).written;
        readOutput = () => decoder.decode(output);
    }

    loaded = true
}

function validateAddress(address) {
    if(loaded === false) {
        loadWasmModule()
    }

    if(typeof address !== 'string') {
        return { valid: false };
    }
    if(address.length !== 40 && address.length !== 42) {
        return { valid: false };
    }

    const written = writeInput(address);
    if(written !== address.length) {
        return { valid: false };
    }

    const result = validateAddressHandle(SCRATCH_OFFSET, written);
    if(result === 0) {
        return { valid: false };
    }

    if(result === 1 && address.length === 42) {
        return { valid: true, address };
    } else {
        return { valid: true, address: readOutput() };
    }
}

module.exports = {
    validateAddress,
}
