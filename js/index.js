const { wasmBase64 } = require('./module');

let loaded = false;
let instance = null;
let memoryBuffer = null;
let validateAddressHandle = null;
const decoder = new TextDecoder()

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
    instance = new WebAssembly.Instance(mod);
    memoryBuffer = instance.exports.memory.buffer;
    validateAddressHandle = instance.exports.validateAddress;

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

    const cArray = new Uint32Array(memoryBuffer, 8192, address.length);
    for (let i = 0; i < address.length; i++) {
        cArray[i] = address.charCodeAt(i);
    }

    const result = validateAddressHandle(8192, address.length);
    if(result === 0) {
        return { valid: false };
    }

    if(result === 1 && address.length == 42) {
        return { valid: true, address };
    } else {
        const array = new Uint8Array(memoryBuffer, 8192, 42);
        return { valid: true, address: decoder.decode(array) };
    }
}

module.exports = { 
    validateAddress,
}
