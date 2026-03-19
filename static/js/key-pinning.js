import * as crypto from "./crypto.js";

const PINNED_KEYS_STORAGE_KEY = "secvault_pinned_keys";

/*
 * KEY PINNING OVERVIEW (TOFU)
 * - First contact: store fingerprint for that email.
 * - Next contacts: reject if fingerprint changes unexpectedly.
 * - Optional toast provides visibility during first-use trust event.
 */

// Loads all pinned key records from localStorage.
function getPinnedKeys() {
    try {
        const stored = localStorage.getItem(PINNED_KEYS_STORAGE_KEY);
        return stored ? JSON.parse(stored) : {};
    } catch (err) {
        console.error("Failed to load pinned keys:", err);
        return {};
    }
}

// Persists pinned key records to localStorage.
function savePinnedKeys(pinnedKeys) {
    try {
        localStorage.setItem(PINNED_KEYS_STORAGE_KEY, JSON.stringify(pinnedKeys));
    } catch (err) {
        console.error("Failed to save pinned keys:", err);
    }
}

// Computes a stable fingerprint from email and both public keys.
async function computeKeyFingerprint(email, x25519Public, ed25519Public) {
    const keyData = `${email}||${x25519Public}||${ed25519Public}`;
    const keyBytes = crypto.strToBytes(keyData);
    const fingerprintBytes = await crypto.sha256(keyBytes);
    const fingerprint = crypto.b64encode(fingerprintBytes);
    return fingerprint;
}

// Pins first-seen keys and rejects unexpected key changes for known users.
export async function pinPublicKeys(email, x25519Public, ed25519Public) {
    const fingerprint = await computeKeyFingerprint(email, x25519Public, ed25519Public);
    const pinnedKeys = getPinnedKeys();
    if (pinnedKeys[email]) {
        // Existing user: fingerprint must match previously pinned value.
        if (pinnedKeys[email].fingerprint !== fingerprint) {
            throw new Error(`⚠️ SECURITY WARNING: Public keys for ${email} have changed!\n\n` + `This could indicate:\n` + `• A man-in-the-middle attack\n` + `• The user re-registered their account\n` + `• Server database was compromised\n\n` + `Expected fingerprint:\n${pinnedKeys[email].fingerprint}\n\n` + `Received fingerprint:\n${fingerprint}\n\n` + `Do NOT proceed unless you can verify this change with the user directly.`);
        }
        pinnedKeys[email].lastSeen = Date.now();
        savePinnedKeys(pinnedKeys);
        return {
            pinned: true,
            firstUse: false,
            fingerprint: fingerprint
        };
    } else {
        // First observation: persist trust record (TOFU model).
        pinnedKeys[email] = {
            fingerprint: fingerprint,
            x25519Public: x25519Public,
            ed25519Public: ed25519Public,
            firstSeen: Date.now(),
            lastSeen: Date.now()
        };
        savePinnedKeys(pinnedKeys);
        return {
            pinned: true,
            firstUse: true,
            fingerprint: fingerprint
        };
    }
}

// Verifies server-provided keys against TOFU pins and optionally notifies first-use.
export async function verifyAndPinPublicKeys(email, x25519Public, ed25519Public, showToast = true) {
    try {
        const result = await pinPublicKeys(email, x25519Public, ed25519Public);
        if (result.firstUse && showToast) {
            const toast = (await import("./api.js")).toast;
            toast(`🔐 First time seeing keys for ${email}\n` + `Fingerprint: ${result.fingerprint.substring(0, 16)}...`, "info");
        }
        return {
            verified: true,
            firstUse: result.firstUse,
            fingerprint: result.fingerprint
        };
    } catch (err) {
        throw err;
    }
}

// Returns pinned key metadata for a specific user.
export function getPinnedKeyInfo(email) {
    const pinnedKeys = getPinnedKeys();
    return pinnedKeys[email] || null;
}

// Removes one user's pinned keys.
export function unpinUser(email) {
    const pinnedKeys = getPinnedKeys();
    delete pinnedKeys[email];
    savePinnedKeys(pinnedKeys);
}

// Exports all pinned key records.
export function exportPinnedKeys() {
    return getPinnedKeys();
}

// Imports and stores pinned key records.
export function importPinnedKeys(keys) {
    savePinnedKeys(keys);
}

// Removes all pinned key records.
export function clearAllPinnedKeys() {
    localStorage.removeItem(PINNED_KEYS_STORAGE_KEY);
}