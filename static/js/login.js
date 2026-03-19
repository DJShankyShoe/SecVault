import * as crypto from "./crypto.js";

import { api, toast } from "./api.js";

import { state } from "./state.js";

import { encryptAndStoreKeys } from "./keystore.js";

/*
 * LOGIN FLOW OVERVIEW
 * 1) Validate PIN policy on the client.
 * 2) Derive master key from password using server-provided KDF params.
 * 3) Authenticate with derived password hash.
 * 4) Decrypt private keys, verify registration signature, and hydrate runtime state.
 * 5) Re-encrypt session keys with PIN and hand encrypted blob to server storage.
 */

// Handles login form submission, key derivation, vault unlock, and session setup.
export async function handleLogin(e) {
    e.preventDefault();

    const form = e.target;
    const submitBtn = form.querySelector("[type=submit]");

    const email = form.email.value.trim().toLowerCase();
    const password = form.password.value;
    const pin = form.pin.value;

    if (!pin || pin.length < 11) {
        toast("PIN must be at least 11 characters", "error");
        return;
    }

    if (pin.length > 32) {
        toast("PIN must be 32 characters or less", "error");
        return;
    }

    // PIN complexity checks reduce weak local key protection choices.
    const hasUpperCase = /[A-Z]/.test(pin);
    const hasLowerCase = /[a-z]/.test(pin);
    const hasNumbers = /[0-9]/.test(pin);
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pin);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChars) {
        toast("PIN must contain uppercase, lowercase, numbers, and special characters", "error");
        return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Fetching params...';

    try {
        // Prelogin returns KDF settings so server can tune hardness over time.
        const preloginData = await api(
            "POST",
            "/api/prelogin",
            {
                email: email
            },
            false
        );

        submitBtn.innerHTML = '<span class="spinner"></span> Deriving master key (Argon2id 64MB)...';
        await new Promise(resolve => setTimeout(resolve, 100));

        // Password-based key schedule:
        // password -> masterKey -> (masterPasswordHash + vaultKey)
        const salt = crypto.strToBytes(email);
        const masterKey = await crypto.argon2id(
            password,
            salt,
            preloginData.kdfMemory,
            preloginData.kdfIterations,
            preloginData.kdfParallelism
        );
        const masterPasswordHash = await crypto.hkdf(masterKey, "master_password_hash", 32);
        const vaultKey = await crypto.hkdf(masterKey, "vault", 32);

        // Why two HKDF outputs from the same master key?
        // - masterPasswordHash is for server authentication only.
        // - vaultKey is for local decryption of protected key material.
        // This key separation avoids reusing one key for multiple purposes.

        submitBtn.innerHTML = '<span class="spinner"></span> Authenticating...';
        const loginData = await api(
            "POST",
            "/api/login",
            {
                email: email,
                masterPasswordHash: crypto.b64encode(masterPasswordHash)
            },
            false
        );

        submitBtn.innerHTML = '<span class="spinner"></span> Unlocking vault...';

        // protectedSymKey stores nonce|ciphertext for the symmetric vault key.
        // AES-GCM here recovers userSymmetricKey, which protects private keys at rest.
        // If password is wrong, this decryption fails and login cannot proceed.
        const [pn, pc] = loginData.protectedSymKey.split("|");
        const userSymmetricKey = await crypto.aesGcmDecrypt(vaultKey, pn, pc);

        // Server stores each encrypted private key as nonce|ciphertext.
        // We decrypt both with userSymmetricKey, then import DER bytes into CryptoKey objects.
        const [xn, xc] = loginData.encryptedX25519.split("|");
        const [en, ec] = loginData.encryptedEd25519.split("|");
        const [xpd, epd] = await Promise.all([
            crypto.aesGcmDecrypt(userSymmetricKey, xn, xc),
            crypto.aesGcmDecrypt(userSymmetricKey, en, ec)
        ]);
        const [x25519Private, ed25519Private] = await Promise.all([
            crypto.importX25519Private(xpd),
            crypto.importEd25519Private(epd)
        ]);
        const [x25519Public, ed25519Public] = await Promise.all([
            crypto.importX25519Public(loginData.x25519Public),
            crypto.importEd25519Public(loginData.ed25519Public)
        ]);

        // At this point:
        // - x25519Private/x25519Public are used for key agreement and wrapping.
        // - ed25519Private/ed25519Public are used for signing and verification.

        submitBtn.innerHTML = '<span class="spinner"></span> Verifying signatures...';

        // Signature check confirms public-key bundle integrity before use.
        // The signed message ties identity (email) to both public keys.
        // If this check fails, keys may have been altered in transit/storage.
        const registrationData = crypto.strToBytes(email + "||" + loginData.x25519Public + "||" + loginData.ed25519Public);
        const signatureValid = await crypto.ed25519Verify(ed25519Public, loginData.registrationSig, registrationData);

        if (!signatureValid) throw new Error("Signature verification failed! Keys may be forged.");

        // Runtime state keeps active session keys in memory for file operations.
        state.email = email;
        state.userSymKey = userSymmetricKey;
        state.x25519Priv = x25519Private;
        state.x25519Pub = x25519Public;
        state.x25519PubB64 = loginData.x25519Public;
        state.ed25519Priv = ed25519Private;
        state.ed25519Pub = ed25519Public;
        state.ed25519PubB64 = loginData.ed25519Public;

        submitBtn.innerHTML = '<span class="spinner"></span> Encrypting with PIN (Argon2id 32MB)...';
        await new Promise(resolve => setTimeout(resolve, 100));

        // PIN-protected key blob enables unlock-on-dashboard without password re-entry.
        // This creates a second protection layer for session recovery:
        // password unlocks vault at login; PIN unlocks cached encrypted keys later.
        const encryptedBlob = await encryptAndStoreKeys(pin, email, {
            userSymKey: userSymmetricKey,
            x25519Priv: x25519Private,
            x25519PubB64: loginData.x25519Public,
            ed25519Priv: ed25519Private,
            ed25519PubB64: loginData.ed25519Public
        });

        if (!encryptedBlob) {
            throw new Error("Failed to encrypt keys with PIN");
        }

        submitBtn.innerHTML = '<span class="spinner"></span> Securing keys...';
        // Encrypted blob is sent to server for HttpOnly cookie storage.
        // JavaScript cannot directly read HttpOnly cookies, reducing XSS token/key theft risk.
        await api("POST", "/api/store-encrypted-keys", {
            encryptedBlob: encryptedBlob
        });

        toast(`Welcome back!`, "success");
        setTimeout(() => window.location.href = "/dashboard.html", 500);
    } catch (err) {
        toast(err.message, "error");
        submitBtn.disabled = false;
        submitBtn.innerHTML = "Unlock Vault";
    }
}