/**
 * SecVault v3.0 - Strong PIN-Protected Key Storage
 * 
 * Security Model:
 * - PIN required ONLY on login (not registration)
 * - Keys encrypted with Argon2id(PIN) - memory-hard, GPU-resistant
 * - Stored encrypted in sessionStorage
 * - Wrong PIN = cannot decrypt keys
 * - Forgotten PIN = must re-login to set new PIN
 */

import * as crypto from './crypto.js';

const STORAGE_PREFIX = '__secvault_';
const MEMORY = {
    userSymKey: null,
    x25519Priv: null,
    x25519Pub: null,
    ed25519Priv: null,
    ed25519Pub: null,
    decrypted: false
};

/**
 * Derive strong encryption key from PIN using Argon2id
 * Parameters tuned for security vs UX balance:
 * - 32MB memory (vs 64MB for password) - still very strong
 * - 15 iterations
 * - 4 parallelism
 * Takes ~100ms to derive, very resistant to brute force
 */
async function derivePinKey(pin, salt) {
    const pinKey = await crypto.argon2id(pin, salt, 32768, 15, 4); // 32MB
    return pinKey;
}

/**
 * Encrypt and store keys with PIN
 * Called after successful login
 */
export async function encryptAndStoreKeys(pin, email, sessionToken, keys) {
    try {
        
        // Derive PIN encryption key
        const pinSalt = crypto.strToBytes('pin_encryption_' + email.toLowerCase() + '_' + sessionToken);
        const pinKey = await derivePinKey(pin, pinSalt);
        
        // Export private keys to serializable format
        const x25519PrivDer = await crypto.exportX25519Private(keys.x25519Priv);
        const ed25519PrivDer = await crypto.exportEd25519Private(keys.ed25519Priv);
        
        // Create keys bundle
        const keysBundle = {
            userSymKey: crypto.b64encode(keys.userSymKey),
            x25519Priv: crypto.b64encode(x25519PrivDer),
            x25519Pub: keys.x25519PubB64,
            ed25519Priv: crypto.b64encode(ed25519PrivDer),
            ed25519Pub: keys.ed25519PubB64
        };
        
        const bundleJson = JSON.stringify(keysBundle);
        const bundleBytes = crypto.strToBytes(bundleJson);
        
        // Encrypt with PIN-derived key
        const encrypted = await crypto.aesGcmEncrypt(pinKey, bundleBytes);
        
        // Store encrypted blob
        const storage = {
            enc: encrypted.ciphertext,
            nonce: encrypted.nonce,
            email: email,
            sessionToken: sessionToken,
            timestamp: Date.now()
        };
        
        sessionStorage.setItem(STORAGE_PREFIX + 'encrypted', JSON.stringify(storage));
        
        // Also store in memory for immediate use
        MEMORY.userSymKey = keys.userSymKey;
        MEMORY.x25519Priv = keys.x25519Priv;
        MEMORY.x25519Pub = keys.x25519Pub;
        MEMORY.ed25519Priv = keys.ed25519Priv;
        MEMORY.ed25519Pub = keys.ed25519Pub;
        MEMORY.decrypted = true;
        
        return true;
    } catch (err) {
        console.error('❌ Encryption error:', err);
        return false;
    }
}

/**
 * Decrypt keys with PIN
 * Called when user enters PIN on dashboard
 */
export async function decryptKeysWithPin(pin, email, sessionToken) {
    try {
        
        // Check if already decrypted in memory
        if (MEMORY.decrypted) {
            return MEMORY;
        }
        
        // Get encrypted blob
        const stored = sessionStorage.getItem(STORAGE_PREFIX + 'encrypted');
        if (!stored) {
            return null;
        }
        
        const storage = JSON.parse(stored);
        
        // Verify session token
        if (storage.sessionToken !== sessionToken) {
            clearEncryptedKeys();
            return null;
        }
        
        // Verify email
        if (storage.email !== email) {
            return null;
        }
        
        // Derive PIN key (same parameters as encryption)
        const pinSalt = crypto.strToBytes('pin_encryption_' + email.toLowerCase() + '_' + sessionToken);
        const pinKey = await derivePinKey(pin, pinSalt);
        
        // Attempt decryption
        let decryptedBytes;
        try {
            decryptedBytes = await crypto.aesGcmDecrypt(pinKey, storage.nonce, storage.enc);
        } catch (err) {
            throw new Error('Wrong PIN');
        }
        
        const decryptedJson = crypto.bytesToStr(decryptedBytes);
        const keysBundle = JSON.parse(decryptedJson);
        
        // Import keys
        const userSymKey = crypto.b64decode(keysBundle.userSymKey);
        const x25519PrivDer = crypto.b64decode(keysBundle.x25519Priv);
        const ed25519PrivDer = crypto.b64decode(keysBundle.ed25519Priv);
        
        const x25519Priv = await crypto.importX25519Private(x25519PrivDer);
        const ed25519Priv = await crypto.importEd25519Private(ed25519PrivDer);
        const x25519Pub = await crypto.importX25519Public(keysBundle.x25519Pub);
        const ed25519Pub = await crypto.importEd25519Public(keysBundle.ed25519Pub);
        
        // Store in memory
        MEMORY.userSymKey = userSymKey;
        MEMORY.x25519Priv = x25519Priv;
        MEMORY.x25519Pub = x25519Pub;
        MEMORY.ed25519Priv = ed25519Priv;
        MEMORY.ed25519Pub = ed25519Pub;
        MEMORY.decrypted = true;
        
        
        return {
            userSymKey,
            x25519Priv,
            x25519Pub,
            x25519PubB64: keysBundle.x25519Pub,
            ed25519Priv,
            ed25519Pub,
            ed25519PubB64: keysBundle.ed25519Pub
        };
    } catch (err) {
        console.error('❌ Decryption error:', err);
        throw err;
    }
}

/**
 * Check if keys are already decrypted in memory
 */
export function hasKeysInMemory() {
    return MEMORY.decrypted;
}

/**
 * Get keys from memory (if already decrypted)
 */
export function getKeysFromMemory() {
    if (MEMORY.decrypted) {
        return MEMORY;
    }
    return null;
}

/**
 * Check if encrypted keys exist
 */
export function hasEncryptedKeys() {
    return !!sessionStorage.getItem(STORAGE_PREFIX + 'encrypted');
}

/**
 * Get stored email for PIN verification
 */
export function getStoredEmail() {
    const stored = sessionStorage.getItem(STORAGE_PREFIX + 'encrypted');
    if (!stored) return null;
    return JSON.parse(stored).email;
}

/**
 * Clear all keys
 */
export function clearEncryptedKeys() {
    sessionStorage.removeItem(STORAGE_PREFIX + 'encrypted');
    MEMORY.userSymKey = null;
    MEMORY.x25519Priv = null;
    MEMORY.x25519Pub = null;
    MEMORY.ed25519Priv = null;
    MEMORY.ed25519Pub = null;
    MEMORY.decrypted = false;
}
