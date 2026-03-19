import * as crypto from "./crypto.js";

const STORAGE_PREFIX = "__secvault_";

/*
 * KEYSTORE OVERVIEW
 * - Derives a PIN key (Argon2id) for local key-bundle protection.
 * - Stores only encrypted bundles outside memory (server endpoint).
 * - Maintains decrypted key objects in MEMORY during active session.
 */

const MEMORY = {
    userSymKey: null,
    x25519Priv: null,
    x25519Pub: null,
    ed25519Priv: null,
    ed25519Pub: null,
    decrypted: false
};

// Derives a PIN-based encryption key with Argon2id.
async function derivePinKey(pin, salt) {
    const pinKey = await crypto.argon2id(pin, salt, 32768, 15, 4);
    return pinKey;
}

// Encrypts user keys with PIN and caches decrypted keys in memory.
export async function encryptAndStoreKeys(pin, email, keys) {
    try {
        // Email-derived salt keeps PIN KDF deterministic per account.
        // This allows decryption across page reloads while still being account-specific.
        const pinSalt = crypto.strToBytes("pin_encryption_" + email.toLowerCase());
        const pinKey = await derivePinKey(pin, pinSalt);
        const x25519PrivDer = await crypto.exportX25519Private(keys.x25519Priv);
        const ed25519PrivDer = await crypto.exportEd25519Private(keys.ed25519Priv);
        // Serialize keys to base64-safe bundle before AES-GCM encryption.
        const keysBundle = {
            userSymKey: crypto.b64encode(keys.userSymKey),
            x25519Priv: crypto.b64encode(x25519PrivDer),
            x25519Pub: keys.x25519PubB64,
            ed25519Priv: crypto.b64encode(ed25519PrivDer),
            ed25519Pub: keys.ed25519PubB64
        };
        const bundleJson = JSON.stringify(keysBundle);
        const bundleBytes = crypto.strToBytes(bundleJson);
        // AES-GCM protects confidentiality and integrity of key bundle in one step.
        const encrypted = await crypto.aesGcmEncrypt(pinKey, bundleBytes);
        const encryptedBlob = {
            enc: encrypted.ciphertext,
            nonce: encrypted.nonce,
            email: email,
            timestamp: Date.now()
        };
        MEMORY.userSymKey = keys.userSymKey;
        MEMORY.x25519Priv = keys.x25519Priv;
        MEMORY.x25519Pub = keys.x25519Pub;
        MEMORY.ed25519Priv = keys.ed25519Priv;
        MEMORY.ed25519Pub = keys.ed25519Pub;
        MEMORY.decrypted = true;
        return encryptedBlob;
    } catch (err) {
        console.error("Key encryption error:", err);
        return null;
    }
}

// Fetches encrypted key blob from server and decrypts it with PIN.
export async function decryptKeysWithPin(pin, email, api) {
    try {
        if (MEMORY.decrypted) {
            return MEMORY;
        }
        let encryptedData;
        try {
            encryptedData = await api("GET", "/api/encrypted-keys");
        } catch (err) {
            throw new Error("Session expired - please logout and login again");
        }
        if (!encryptedData || !encryptedData.enc) {
            throw new Error("Session expired - please logout and login again");
        }
        if (encryptedData.email !== email) {
            // Hard stop if blob/account mismatch; prevents cross-user key restoration.
            return null;
        }
        const pinSalt = crypto.strToBytes("pin_encryption_" + email.toLowerCase());
        const pinKey = await derivePinKey(pin, pinSalt);
        let decryptedBytes;
        try {
            // Wrong PIN or tampered ciphertext will fail authenticated decryption.
            decryptedBytes = await crypto.aesGcmDecrypt(pinKey, encryptedData.nonce, encryptedData.enc);
        } catch (err) {
            throw new Error("Wrong PIN");
        }
        const decryptedJson = crypto.bytesToStr(decryptedBytes);
        // Parsed bundle restores all runtime crypto materials.
        const keysBundle = JSON.parse(decryptedJson);
        const userSymKey = crypto.b64decode(keysBundle.userSymKey);
        const x25519PrivDer = crypto.b64decode(keysBundle.x25519Priv);
        const ed25519PrivDer = crypto.b64decode(keysBundle.ed25519Priv);
        const x25519Priv = await crypto.importX25519Private(x25519PrivDer);
        const ed25519Priv = await crypto.importEd25519Private(ed25519PrivDer);
        const x25519Pub = await crypto.importX25519Public(keysBundle.x25519Pub);
        const ed25519Pub = await crypto.importEd25519Public(keysBundle.ed25519Pub);
        // Once imported, runtime code can use these CryptoKey objects for operations.
        MEMORY.userSymKey = userSymKey;
        MEMORY.x25519Priv = x25519Priv;
        MEMORY.x25519Pub = x25519Pub;
        MEMORY.ed25519Priv = ed25519Priv;
        MEMORY.ed25519Pub = ed25519Pub;
        MEMORY.decrypted = true;
        return {
            userSymKey: userSymKey,
            x25519Priv: x25519Priv,
            x25519Pub: x25519Pub,
            x25519PubB64: keysBundle.x25519Pub,
            ed25519Priv: ed25519Priv,
            ed25519Pub: ed25519Pub,
            ed25519PubB64: keysBundle.ed25519Pub
        };
    } catch (err) {
        console.error("Key decryption error:", err.message);
        throw err;
    }
}

// Returns true when decrypted keys are already available in memory.
export function hasKeysInMemory() {
    return MEMORY.decrypted;
}

// Returns decrypted key objects from memory, if available.
export function getKeysFromMemory() {
    if (MEMORY.decrypted) {
        return MEMORY;
    }
    return null;
}

// Indicates encrypted key storage is expected to exist server-side.
export function hasEncryptedKeys() {
    return true;
}

// Legacy compatibility helper retained for callers expecting this API.
export function getStoredEmail() {
    return null;
}

// Clears all decrypted keys from memory.
export function clearEncryptedKeys() {
    MEMORY.userSymKey = null;
    MEMORY.x25519Priv = null;
    MEMORY.x25519Pub = null;
    MEMORY.ed25519Priv = null;
    MEMORY.ed25519Pub = null;
    MEMORY.decrypted = false;
}