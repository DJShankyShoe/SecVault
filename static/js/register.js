import * as crypto from "./crypto.js";

import { api, toast } from "./api.js";

/*
 * REGISTRATION FLOW OVERVIEW
 * 1) Validate password policy.
 * 2) Derive password-based keys with Argon2id + HKDF.
 * 3) Generate identity keypairs (X25519 and Ed25519).
 * 4) Encrypt private keys with user symmetric key.
 * 5) Sign identity bundle and submit account payload.
 */

// Handles registration: validates password, creates keys, and submits account payload.
export async function handleRegister(e) {
    e.preventDefault();

    const form = e.target;
    const submitBtn = form.querySelector("[type=submit]");

    const email = form.email.value.trim().toLowerCase();
    const password = form.password.value;
    const password2 = form.password2.value;

    if (password !== password2) {
        toast("Passwords do not match", "error");
        return;
    }

    if (password.length < 14) {
        toast("Password must be at least 14 characters", "error");
        return;
    }

    // Enforce complexity to reduce weak account passwords.
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChars) {
        toast("Password must contain uppercase, lowercase, numbers, and special characters", "error");
        return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Deriving keys (Argon2id 64MB)...';

    await new Promise(resolve => setTimeout(resolve, 100));

    try {
        // Password key schedule used by login for deterministic re-derivation.
        const salt = crypto.strToBytes(email);
        const masterKey = await crypto.argon2id(password, salt, 65536, 15, 4);
        const masterPasswordHash = await crypto.hkdf(masterKey, "master_password_hash", 32);
        const vaultKey = await crypto.hkdf(masterKey, "vault", 32);

        // Same key-separation model as login:
        // - masterPasswordHash: authentication secret sent to server.
        // - vaultKey: local encryption key that never needs to be transmitted.

        // User symmetric key protects private key material at rest.
        const userSymmetricKey = crypto.getRandomBytes(32);
        // protectedSymKey = AES-GCM(vaultKey, userSymmetricKey).
        // During login, vaultKey decrypts this to recover userSymmetricKey.
        const protectedSymKey = await crypto.aesGcmEncrypt(vaultKey, userSymmetricKey);

        submitBtn.innerHTML = '<span class="spinner"></span> Generating keypairs...';
        const [x25519Pair, ed25519Pair] = await Promise.all([
            crypto.generateX25519KeyPair(),
            crypto.generateEd25519KeyPair()
        ]);

        const x25519Public = await crypto.exportX25519Public(x25519Pair.publicKey);
        const ed25519Public = await crypto.exportEd25519Public(ed25519Pair.publicKey);

        const [x25519PrivateDer, ed25519PrivateDer] = await Promise.all([
            crypto.exportX25519Private(x25519Pair.privateKey),
            crypto.exportEd25519Private(ed25519Pair.privateKey)
        ]);

        // Private keys are encrypted with userSymmetricKey before upload/storage.
        // Server stores only ciphertext and cannot directly use plaintext private keys.
        const [encryptedX25519, encryptedEd25519] = await Promise.all([
            crypto.aesGcmEncrypt(userSymmetricKey, x25519PrivateDer),
            crypto.aesGcmEncrypt(userSymmetricKey, ed25519PrivateDer)
        ]);

        submitBtn.innerHTML = '<span class="spinner"></span> Creating signature...';

        // Signature binds email to the generated public key bundle.
        // This allows login-time verification that public keys were not replaced.
        const registrationData = crypto.strToBytes(email + "||" + x25519Public + "||" + ed25519Public);
        const registrationSig = await crypto.ed25519Sign(ed25519Pair.privateKey, registrationData);

        submitBtn.innerHTML = '<span class="spinner"></span> Creating account...';
        await api(
            "POST",
            "/api/register",
            {
                email: email,
                masterPasswordHash: crypto.b64encode(masterPasswordHash),
                protectedSymKey: protectedSymKey.nonce + "|" + protectedSymKey.ciphertext,
                x25519Public: x25519Public,
                ed25519Public: ed25519Public,
                registrationSig: registrationSig,
                encryptedX25519: encryptedX25519.nonce + "|" + encryptedX25519.ciphertext,
                encryptedEd25519: encryptedEd25519.nonce + "|" + encryptedEd25519.ciphertext
            },
            false
        );

        toast("Account created! Redirecting to login...", "success");
        setTimeout(() => window.location.href = "/login.html", 1500);
    } catch (err) {
        toast(err.message, "error");
        submitBtn.disabled = false;
        submitBtn.innerHTML = "Create Account";
    }
}