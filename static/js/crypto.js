const crypto = window.crypto.subtle;

if (typeof hashwasm !== "undefined") {}

/*
 * CRYPTO OVERVIEW
 * - Encoding helpers: b64encode/b64decode + text/byte conversions.
 * - KDFs: Argon2id for password/PIN hardening and HKDF for key separation.
 * - File ratchet: per-version forward derivation for update secrecy.
 * - Primitives: AES-GCM encryption + X25519/Ed25519 key operations.
 */

// Encodes ArrayBuffer data to base64.
export function b64encode(buf) {
    try {
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const result = btoa(binary);
        return result;
    } catch (err) {
        console.error("[b64encode] ERROR:", err);
        throw err;
    }
}

// Decodes a base64 string into an ArrayBuffer.
export function b64decode(s) {
    try {
        const cleanStr = s.trim();
        const b = atob(cleanStr);
        const buf = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) {
            buf[i] = b.charCodeAt(i);
        }
        return buf.buffer;
    } catch (err) {
        console.error("[b64decode] ERROR:", err);
        throw new Error("Invalid base64 string: " + err.message);
    }
}

// Converts a UTF-8 string to bytes.
export function strToBytes(s) {
    return (new TextEncoder).encode(s);
}

// Converts UTF-8 bytes to a JavaScript string.
export function bytesToStr(b) {
    return (new TextDecoder).decode(b);
}

// Generates cryptographically secure random bytes.
export function getRandomBytes(n) {
    return window.crypto.getRandomValues(new Uint8Array(n)).buffer;
}

// Derives a key from a password using Argon2id.
export async function argon2id(password, salt, memory = 65536, iterations = 15, parallelism = 4) {
    if (typeof hashwasm === "undefined") {
        throw new Error("hashwasm library not loaded. Please refresh the page.");
    }
    const result = await hashwasm.argon2id({
        password: password,
        salt: new Uint8Array(salt),
        iterations: iterations,
        memorySize: memory,
        parallelism: parallelism,
        hashLength: 32,
        outputType: "binary"
    });
    return result.buffer;
}

// Derives deterministic key material from input key material and context info.
export async function hkdf(ikm, info, length = 32) {
    const key = await crypto.importKey("raw", ikm, {
        name: "HKDF"
    }, false, [ "deriveBits" ]);
    return crypto.deriveBits({
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: strToBytes(info)
    }, key, length * 8);
}

// Computes SHA-256 hash for arbitrary binary data.
export async function sha256(data) {
    return crypto.digest("SHA-256", data);
}

// Initializes version 1 of the file ratchet chain.
export function initializeRatchet() {
    const rootKey = getRandomBytes(32);
    return {
        rootKey: rootKey,
        version: 1
    };
}

// Derives the current version's file key and next chain key from a root key.
export async function deriveVersionKeys(rootKey, version) {
    const fileKeyInfo = `file_v${version}`;
    const fileKey = await hkdf(rootKey, fileKeyInfo, 32);
    const chainKeyInfo = `chain_v${version}`;
    const chainKey = await hkdf(rootKey, chainKeyInfo, 32);
    return {
        fileKey: fileKey,
        chainKey: chainKey,
        version: version
    };
}

// Advances the ratchet by one version and derives next keys.
export async function ratchetForward(currentChainKey, currentVersion) {
    const nextVersion = currentVersion + 1;
    const fileKeyInfo = `file_v${nextVersion}`;
    const fileKey = await hkdf(currentChainKey, fileKeyInfo, 32);
    const chainKeyInfo = `chain_v${nextVersion}`;
    const chainKey = await hkdf(currentChainKey, chainKeyInfo, 32);
    return {
        fileKey: fileKey,
        chainKey: chainKey,
        version: nextVersion
    };
}

// Reconstructs the file key for a specific version by replaying ratchet derivations.
export async function deriveFileKeyForVersion(rootKey, version) {
    if (version === 1) {
        const fileKeyInfo = `file_v${version}`;
        return await hkdf(rootKey, fileKeyInfo, 32);
    }

    // Replay chain derivation from v1 so any authorized version can be reconstructed.
    let chainKey = await hkdf(rootKey, "chain_v1", 32);
    for (let v = 2; v <= version; v++) {
        if (v === version) {
            const fileKeyInfo = `file_v${v}`;
            return await hkdf(chainKey, fileKeyInfo, 32);
        } else {
            const chainKeyInfo = `chain_v${v}`;
            chainKey = await hkdf(chainKey, chainKeyInfo, 32);
        }
    }
}

// Checks whether a user can access a requested file version.
export function canAccessVersion(requestedVersion, maxVersion) {
    return requestedVersion <= maxVersion;
}

// Encrypts plaintext with AES-GCM and returns base64-encoded nonce/ciphertext.
export async function aesGcmEncrypt(key, plaintext, aad = null) {
    const nonce = getRandomBytes(12);
    const cryptoKey = await crypto.importKey("raw", key, {
        name: "AES-GCM"
    }, false, [ "encrypt" ]);
    const params = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aad) params.additionalData = aad;
    const ciphertext = await crypto.encrypt(params, cryptoKey, plaintext);
    return {
        nonce: b64encode(nonce),
        ciphertext: b64encode(ciphertext)
    };
}

// Decrypts AES-GCM data from base64 nonce/ciphertext.
export async function aesGcmDecrypt(key, nonceB64, ciphertextB64, aad = null) {
    const nonce = b64decode(nonceB64);
    const ciphertext = b64decode(ciphertextB64);
    const cryptoKey = await crypto.importKey("raw", key, {
        name: "AES-GCM"
    }, false, [ "decrypt" ]);
    const params = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aad) params.additionalData = aad;
    return crypto.decrypt(params, cryptoKey, ciphertext);
}

// Generates an X25519 keypair used for ECDH key agreement.
export async function generateX25519KeyPair() {
    return crypto.generateKey({
        name: "X25519"
    }, true, [ "deriveBits" ]);
}

// Exports an X25519 public key to base64.
export async function exportX25519Public(publicKey) {
    return b64encode(await crypto.exportKey("raw", publicKey));
}

// Imports an X25519 public key from base64.
export async function importX25519Public(publicKeyB64) {
    return crypto.importKey("raw", b64decode(publicKeyB64), {
        name: "X25519"
    }, false, []);
}

// Exports an X25519 private key in PKCS#8 format.
export async function exportX25519Private(privateKey) {
    return crypto.exportKey("pkcs8", privateKey);
}

// Imports an X25519 private key from PKCS#8 bytes.
export async function importX25519Private(pkcs8) {
    return crypto.importKey("pkcs8", pkcs8, {
        name: "X25519"
    }, true, [ "deriveBits" ]);
}

// Derives a shared secret from an X25519 private/public key pair.
export async function x25519DeriveSharedSecret(privateKey, publicKey) {
    return crypto.deriveBits({
        name: "X25519",
        public: publicKey
    }, privateKey, 256);
}

// Wraps key material for a recipient by ECDH + HKDF + AES-GCM.
export async function x25519Wrap(recipientPublicKey, keyToWrap) {
    const ephemeralPair = await generateX25519KeyPair();
    const sharedSecret = await x25519DeriveSharedSecret(ephemeralPair.privateKey, recipientPublicKey);
    const wrapKey = await hkdf(sharedSecret, "file_key_wrap", 32);
    const encrypted = await aesGcmEncrypt(wrapKey, keyToWrap);
    const ephemeralPub = await exportX25519Public(ephemeralPair.publicKey);
    return {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        ephemeralPub: ephemeralPub
    };
}

// Generates an Ed25519 keypair used for signatures.
export async function generateEd25519KeyPair() {
    return crypto.generateKey({
        name: "Ed25519"
    }, true, [ "sign", "verify" ]);
}

// Exports an Ed25519 public key to base64.
export async function exportEd25519Public(publicKey) {
    return b64encode(await crypto.exportKey("raw", publicKey));
}

// Imports an Ed25519 public key from base64.
export async function importEd25519Public(publicKeyB64) {
    return crypto.importKey("raw", b64decode(publicKeyB64), {
        name: "Ed25519"
    }, false, [ "verify" ]);
}

// Exports an Ed25519 private key in PKCS#8 format.
export async function exportEd25519Private(privateKey) {
    return crypto.exportKey("pkcs8", privateKey);
}

// Imports an Ed25519 private key from PKCS#8 bytes.
export async function importEd25519Private(pkcs8) {
    return crypto.importKey("pkcs8", pkcs8, {
        name: "Ed25519"
    }, true, [ "sign" ]);
}

// Signs data using Ed25519 and returns base64 signature.
export async function ed25519Sign(privateKey, data) {
    const signature = await crypto.sign("Ed25519", privateKey, data);
    return b64encode(signature);
}

// Verifies an Ed25519 base64 signature against data.
export async function ed25519Verify(publicKey, signatureB64, data) {
    const signature = b64decode(signatureB64);
    return crypto.verify("Ed25519", publicKey, signature, data);
}