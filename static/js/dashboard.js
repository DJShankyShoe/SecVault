import { api, toast } from "./api.js";

import { state, clearState, isAuthenticated } from "./state.js";

import { loadFiles, handleFileUpload } from "./files.js";

import { decryptKeysWithPin, hasKeysInMemory, getKeysFromMemory, hasEncryptedKeys, clearEncryptedKeys } from "./keystore.js";

/*
 * DASHBOARD OVERVIEW
 * - Validates session state before any file interaction.
 * - Restores keys from memory or PIN-unlocks encrypted key blob.
 * - Wires upload/logout UI handlers after auth checks pass.
 */

// Clears server session and local key/session state.
async function clearSessionData() {
    try {
        await api("POST", "/api/logout");
    } catch (err) {
        console.error("Server logout failed:", err);
    }
    clearEncryptedKeys();
    clearState();
}

// Verifies whether the backend session is still valid.
async function checkSessionValid() {
    try {
        await api("GET", "/api/files");
        return true;
    } catch (err) {
        if (err.message.includes("401") || err.message.includes("Unauthorized") || err.message.includes("expired")) {
            return false;
        }
        return true;
    }
}

// Initializes dashboard UI, validates auth/session, and loads files.
export async function initDashboard() {
    if (!isAuthenticated()) {
        window.location.href = "/login.html";
        return;
    }
    // Guard against stale browser state when server session has expired.
    const sessionValid = await checkSessionValid();
    if (!sessionValid) {
        toast("Session expired - please login again", "info");
        await clearSessionData();
        setTimeout(() => {
            window.location.href = "/login.html";
        }, 1e3);
        return;
    }
    const emailEl = document.getElementById("user-email");
    if (emailEl) emailEl.textContent = state.email;
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) logoutBtn.addEventListener("click", handleLogout);
    await checkAndPromptForPin();
    if (hasKeysInMemory()) {
        loadFiles();
    } else {}
    const uploadForm = document.getElementById("upload-form");
    if (uploadForm) uploadForm.addEventListener("submit", handleFileUpload);
}

// Restores in-memory keys or prompts the user for PIN unlock.
async function checkAndPromptForPin() {
    const memoryKeys = getKeysFromMemory();
    if (memoryKeys) {
        state.userSymKey = memoryKeys.userSymKey;
        state.x25519Priv = memoryKeys.x25519Priv;
        state.x25519Pub = memoryKeys.x25519Pub;
        state.ed25519Priv = memoryKeys.ed25519Priv;
        state.ed25519Pub = memoryKeys.ed25519Pub;
        return;
    }
    if (!hasEncryptedKeys()) {
        toast("Session expired - please login again", "info");
        setTimeout(() => {
            window.location.href = "/login.html";
        }, 2e3);
        return;
    }
    showPinPrompt();
}

// Shows the PIN unlock modal for decrypting stored key material.
function showPinPrompt() {
    const email = state.email;
    const modal = document.createElement("div");
    modal.className = "modal-overlay";
    modal.id = "pin-prompt";
    modal.innerHTML = `\n        <div class="modal" style="max-width: 480px;">\n            <div class="modal-header">\n                <h2>🔐 Enter PIN</h2>\n            </div>\n            <div class="modal-body">\n                <p style="color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem;">\n                    Enter your session PIN to decrypt your encryption keys.\n                </p>\n                \n                <div id="pin-error" style="display: none; background: rgba(231, 76, 60, 0.1); border: 1px solid rgba(231, 76, 60, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;">\n                    <span style="color: #e74c3c; font-size: 0.85rem; font-weight: 600;">\n                        ✕ <span id="pin-error-message">Wrong PIN</span>\n                    </span>\n                </div>\n                \n                <form id="pin-form">\n                    <div class="field">\n                        <label for="unlock-pin">Session PIN</label>\n                        <input type="password" id="unlock-pin" name="pin" required minlength="11" maxlength="32" autocomplete="off" autofocus>\n                        <small style="color: var(--muted); font-size: 0.75rem;">\n                            11-32 characters (uppercase, lowercase, numbers, special characters)\n                        </small>\n                    </div>\n                    <button type="submit" class="btn btn-primary" id="unlock-btn">\n                        🔓 Unlock Keys\n                    </button>\n                </form>\n                <p style="color: var(--muted); margin-top: 1.5rem; font-size: 0.8rem; text-align: center;">\n                    Forgot PIN? <a href="#" id="forgot-pin-link" style="color: var(--accent);">Re-login</a> to create a new one\n                </p>\n            </div>\n        </div>\n    `;
    document.body.appendChild(modal);
    document.getElementById("pin-form").addEventListener("submit", unlockWithPin);
    document.getElementById("forgot-pin-link").addEventListener("click", e => {
        e.preventDefault();
        forgotPin();
    });
}

let pinAttempts = 0;

const MAX_PIN_ATTEMPTS = 3;

// Decrypts locally protected keys with PIN and loads files on success.
async function unlockWithPin(e) {
    e.preventDefault();
    const form = e.target;
    const pinInput = form.pin;
    const pin = pinInput.value;
    const unlockBtn = document.getElementById("unlock-btn");
    const errorDiv = document.getElementById("pin-error");
    const errorMsg = document.getElementById("pin-error-message");
    const email = state.email;
    if (errorDiv) errorDiv.style.display = "none";
    unlockBtn.disabled = true;
    unlockBtn.innerHTML = '<span class="spinner"></span> Decrypting (Argon2id 32MB)...';
    try {
        // PIN unlock decrypts keys that were re-encrypted at login time.
        const keys = await decryptKeysWithPin(pin, email, api);
        if (!keys) {
            throw new Error("Wrong PIN");
        }
        pinAttempts = 0;
        state.userSymKey = keys.userSymKey;
        state.x25519Priv = keys.x25519Priv;
        state.x25519Pub = keys.x25519Pub;
        state.x25519PubB64 = keys.x25519PubB64;
        state.ed25519Priv = keys.ed25519Priv;
        state.ed25519Pub = keys.ed25519Pub;
        state.ed25519PubB64 = keys.ed25519PubB64;
        const modal = document.getElementById("pin-prompt");
        if (modal) {
            modal.remove();
        }
        toast("Keys unlocked successfully!", "success");
        await loadFiles();
    } catch (err) {
        console.error("❌ Unlock error:", err);
        pinAttempts++;
        if (pinAttempts >= MAX_PIN_ATTEMPTS) {
            if (errorDiv && errorMsg) {
                errorMsg.textContent = `Too many failed attempts (${MAX_PIN_ATTEMPTS}). Clearing session for security...`;
                errorDiv.style.display = "block";
            }
            setTimeout(async () => {
                await clearSessionData();
                window.location.href = "/login.html";
            }, 2e3);
            return;
        }
        let errorText = "Decryption failed";
        const remaining = MAX_PIN_ATTEMPTS - pinAttempts;
        if (err.message && err.message.includes("Wrong PIN")) {
            errorText = `Wrong PIN. ${remaining} attempt${remaining !== 1 ? "s" : ""} remaining.`;
        } else if (err.message && err.message.includes("hashwasm")) {
            errorText = "Crypto library not loaded - please refresh page";
        } else {
            errorText = "Decryption failed: " + (err.message || "Unknown error");
        }
        if (errorDiv && errorMsg) {
            errorMsg.textContent = errorText;
            errorDiv.style.display = "block";
        }
        unlockBtn.disabled = false;
        unlockBtn.innerHTML = "🔓 Unlock Keys";
        pinInput.value = "";
        pinInput.focus();
    }
}

// Handles forgot-PIN flow by clearing session and redirecting to login.
async function forgotPin() {
    if (confirm("Forgot PIN? You need to re-login to set a new PIN. This will end your current session. Continue?")) {
        await clearSessionData();
        toast("Session cleared - please login again", "info");
        setTimeout(() => {
            window.location.href = "/login.html";
        }, 1e3);
    }
}

// Logs the user out and redirects to login page.
async function handleLogout() {
    await clearSessionData();
    toast("Logged out successfully", "info");
    setTimeout(() => {
        window.location.href = "/login.html";
    }, 500);
}

// Exposes a global helper used by the UI to force re-login.
window.relogin = function() {
    clearSessionData().then(() => {
        window.location.href = "/login.html";
    });
};