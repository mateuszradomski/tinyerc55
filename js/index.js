const { wasmBase64 } = require('./module');

let loaded = false;
let instance = null;
let memoryBuffer = null;
let validateAddressHandle = null;

function decodeBase64(base64) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64');
  } else {
    const binStr = atob(base64);
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
        return false
    }
    if(address.length !== 40 || address.length !== 42) {
        return false;
    }

    const cArray = new Uint32Array(memoryBuffer, 8192, address.length);
    for (let i = 0; i < address.length; i++) {
        cArray[i] = address.charCodeAt(i);
    }

    return validateAddressHandle(8192, address.length);
}

module.exports = { 
    validateAddress,
}
