/**
 * SecVault v3.0 - Dashboard with Session Management
 */

import { api, toast } from './api.js';
import { state, clearState, isAuthenticated } from './state.js';
import { loadFiles, handleFileUpload } from './files.js';
import { decryptKeysWithPin, hasKeysInMemory, getKeysFromMemory, hasEncryptedKeys, getStoredEmail, clearEncryptedKeys } from './keystore.js';

/**
 * Clear all session data (keys, state, server session)
 */
async function clearSessionData() {
    
    // Clear encrypted keys
    clearEncryptedKeys();
    
    // Clear application state
    clearState();
    
    // Try to logout from server
    try {
        await api('POST', '/api/logout');
    } catch (err) {
    }
    
}

/**
 * Check if session is valid on server
 */
async function checkSessionValid() {
    try {
        await api('GET', '/api/files');
        return true;
    } catch (err) {
        if (err.message.includes('401') || err.message.includes('Unauthorized') || err.message.includes('expired')) {
            return false;
        }
        return true;
    }
}

export async function initDashboard() {
    // Check if authenticated
    if (!isAuthenticated()) {
        window.location.href = '/login.html';
        return;
    }
    
    // Check if session is still valid on server
    const sessionValid = await checkSessionValid();
    if (!sessionValid) {
        toast('Session expired - please login again', 'info');
        await clearSessionData();
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 1000);
        return;
    }
    
    
    // Set email display
    const emailEl = document.getElementById('user-email');
    if (emailEl) emailEl.textContent = state.email;
    
    // Attach logout handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
    
    // Check if keys are in memory or need PIN
    await checkAndPromptForPin();
    
    // Load files if keys available
    if (hasKeysInMemory()) {
        loadFiles();
    } else {
    }
    
    // Attach upload handler
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) uploadForm.addEventListener('submit', handleFileUpload);
}

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
        toast('Session expired - please login again', 'info');
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 2000);
        return;
    }
    
    showPinPrompt();
}

function showPinPrompt() {
    const email = getStoredEmail();
    
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'pin-prompt';
    modal.innerHTML = `
        <div class="modal" style="max-width: 480px;">
            <div class="modal-header">
                <h2>🔐 Enter PIN</h2>
            </div>
            <div class="modal-body">
                <p style="color: var(--muted); margin-bottom: 1.5rem; font-size: 0.9rem;">
                    Enter your session PIN to decrypt your encryption keys.
                </p>
                
                <div id="pin-error" style="display: none; background: rgba(231, 76, 60, 0.1); border: 1px solid rgba(231, 76, 60, 0.3); border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem;">
                    <span style="color: #e74c3c; font-size: 0.85rem; font-weight: 600;">
                        ✕ <span id="pin-error-message">Wrong PIN</span>
                    </span>
                </div>
                
                <form id="pin-form">
                    <div class="field">
                        <label for="unlock-pin">Session PIN</label>
                        <input type="password" id="unlock-pin" name="pin" required minlength="6" maxlength="32" autocomplete="off" autofocus>
                        <small style="color: var(--muted); font-size: 0.75rem;">
                            6-32 characters (alphanumeric)
                        </small>
                    </div>
                    <button type="submit" class="btn btn-primary" id="unlock-btn">
                        🔓 Unlock Keys
                    </button>
                </form>
                <p style="color: var(--muted); margin-top: 1.5rem; font-size: 0.8rem; text-align: center;">
                    Forgot PIN? <a href="#" id="forgot-pin-link" style="color: var(--accent);">Re-login</a> to create a new one
                </p>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    document.getElementById('pin-form').addEventListener('submit', unlockWithPin);
    document.getElementById('forgot-pin-link').addEventListener('click', (e) => {
        e.preventDefault();
        forgotPin();
    });
}

async function unlockWithPin(e) {
    e.preventDefault();
    
    const form = e.target;
    const pinInput = form.pin;
    const pin = pinInput.value;
    const unlockBtn = document.getElementById('unlock-btn');
    const errorDiv = document.getElementById('pin-error');
    const errorMsg = document.getElementById('pin-error-message');
    const email = getStoredEmail();
    
    if (errorDiv) errorDiv.style.display = 'none';
    
    unlockBtn.disabled = true;
    unlockBtn.innerHTML = '<span class="spinner"></span> Decrypting (Argon2id 32MB)...';
    
    try {
        const keys = await decryptKeysWithPin(pin, email, state.token);
        
        if (!keys) {
            throw new Error('Wrong PIN');
        }
        
        
        state.userSymKey = keys.userSymKey;
        state.x25519Priv = keys.x25519Priv;
        state.x25519Pub = keys.x25519Pub;
        state.x25519PubB64 = keys.x25519PubB64;
        state.ed25519Priv = keys.ed25519Priv;
        state.ed25519Pub = keys.ed25519Pub;
        state.ed25519PubB64 = keys.ed25519PubB64;
        
        const modal = document.getElementById('pin-prompt');
        if (modal) {
            modal.remove();
        }
        
        toast('Keys unlocked successfully!', 'success');
        
        await loadFiles();
        
    } catch (err) {
        console.error('❌ Unlock error:', err);
        
        let errorText = 'Decryption failed';
        if (err.message && err.message.includes('Wrong PIN')) {
            errorText = 'Wrong PIN - please try again';
        } else if (err.message && err.message.includes('hashwasm')) {
            errorText = 'Crypto library not loaded - please refresh page';
        } else {
            errorText = 'Decryption failed: ' + (err.message || 'Unknown error');
        }
        
        if (errorDiv && errorMsg) {
            errorMsg.textContent = errorText;
            errorDiv.style.display = 'block';
        }
        
        unlockBtn.disabled = false;
        unlockBtn.innerHTML = '🔓 Unlock Keys';
        
        pinInput.value = '';
        pinInput.focus();
    }
}

async function forgotPin() {
    if (confirm('Forgot PIN? You need to re-login to set a new PIN. This will end your current session. Continue?')) {
        
        // Clear ALL session data
        await clearSessionData();
        
        toast('Session cleared - please login again', 'info');
        
        setTimeout(() => {
            window.location.href = '/login.html';
        }, 1000);
    }
}

async function handleLogout() {
    
    await clearSessionData();
    
    toast('Logged out successfully', 'info');
    
    setTimeout(() => {
        window.location.href = '/login.html';
    }, 500);
}

window.relogin = function() {
    clearSessionData().then(() => {
        window.location.href = '/login.html';
    });
};
