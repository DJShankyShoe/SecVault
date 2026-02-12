/**
 * SecVault v3.0 - Cryptographic Utilities
 */

const crypto = window.crypto.subtle;

if (typeof hashwasm !== 'undefined') {
}

export function b64encode(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function b64decode(s) {
    const b = atob(s);
    const buf = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) buf[i] = b.charCodeAt(i);
    return buf.buffer;
}

export function strToBytes(s) {
    return new TextEncoder().encode(s);
}

export function bytesToStr(b) {
    return new TextDecoder().decode(b);
}

export function getRandomBytes(n) {
    return window.crypto.getRandomValues(new Uint8Array(n)).buffer;
}

export async function argon2id(password, salt, memory = 65536, iterations = 15, parallelism = 4) {
    if (typeof hashwasm === 'undefined') {
        throw new Error('hashwasm library not loaded. Please refresh the page.');
    }
    
    const result = await hashwasm.argon2id({
        password,
        salt: new Uint8Array(salt),
        iterations,
        memorySize: memory,
        parallelism,
        hashLength: 32,
        outputType: 'binary'
    });
    return result.buffer;
}

export async function hkdf(ikm, info, length = 32) {
    const key = await crypto.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
    return crypto.deriveBits({
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: strToBytes(info)
    }, key, length * 8);
}

export async function sha256(data) {
    return crypto.digest('SHA-256', data);
}

export async function aesGcmEncrypt(key, plaintext, aad = null) {
    const nonce = getRandomBytes(12);
    const cryptoKey = await crypto.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const params = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) params.additionalData = aad;
    const ciphertext = await crypto.encrypt(params, cryptoKey, plaintext);
    return { nonce: b64encode(nonce), ciphertext: b64encode(ciphertext) };
}

export async function aesGcmDecrypt(key, nonceB64, ciphertextB64, aad = null) {
    const nonce = b64decode(nonceB64);
    const ciphertext = b64decode(ciphertextB64);
    const cryptoKey = await crypto.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const params = { name: 'AES-GCM', iv: nonce, tagLength: 128 };
    if (aad) params.additionalData = aad;
    return crypto.decrypt(params, cryptoKey, ciphertext);
}

// X25519
export async function generateX25519KeyPair() {
    // Private key: extractable=true so we can export it
    // Public key: automatically created with extractable=true for exporting
    return crypto.generateKey({ name: 'X25519' }, true, ['deriveBits']);
}

export async function exportX25519Public(publicKey) {
    return b64encode(await crypto.exportKey('raw', publicKey));
}

export async function importX25519Public(publicKeyB64) {
    // Public keys: extractable=false, empty usage (usage determined at deriveBits time)
    return crypto.importKey('raw', b64decode(publicKeyB64), { name: 'X25519' }, false, []);
}

export async function exportX25519Private(privateKey) {
    return crypto.exportKey('pkcs8', privateKey);
}

export async function importX25519Private(pkcs8) {
    // Private keys: extractable=true for re-export, deriveBits usage
    return crypto.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
}

export async function x25519DeriveSharedSecret(privateKey, publicKey) {
    // The private key must have 'deriveBits' usage
    // The public key is specified here
    return crypto.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256);
}

// Ed25519
export async function generateEd25519KeyPair() {
    return crypto.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
}

export async function exportEd25519Public(publicKey) {
    return b64encode(await crypto.exportKey('raw', publicKey));
}

export async function importEd25519Public(publicKeyB64) {
    return crypto.importKey('raw', b64decode(publicKeyB64), { name: 'Ed25519' }, false, ['verify']);
}

export async function exportEd25519Private(privateKey) {
    return crypto.exportKey('pkcs8', privateKey);
}

export async function importEd25519Private(pkcs8) {
    return crypto.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
}

export async function ed25519Sign(privateKey, data) {
    const signature = await crypto.sign('Ed25519', privateKey, data);
    return b64encode(signature);
}

export async function ed25519Verify(publicKey, signatureB64, data) {
    const signature = b64decode(signatureB64);
    return crypto.verify('Ed25519', publicKey, signature, data);
}
