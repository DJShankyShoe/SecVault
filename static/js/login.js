/**
 * SecVault v3.0 - Login Logic (Email-only)
 */

import * as crypto from './crypto.js';
import { api, toast } from './api.js';
import { state } from './state.js';
import { encryptAndStoreKeys } from './keystore.js';

export async function handleLogin(e) {
    e.preventDefault();
    const form = e.target;
    const submitBtn = form.querySelector('[type=submit]');
    
    const email = form.email.value.trim().toLowerCase();
    const password = form.password.value;
    const pin = form.pin.value;
    
    if (!pin || pin.length < 6) {
        toast('PIN must be at least 6 characters', 'error');
        return;
    }
    
    if (pin.length > 32) {
        toast('PIN must be 32 characters or less', 'error');
        return;
    }
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Fetching params...';
    
    try {
        const preloginData = await api('POST', '/api/prelogin', { email }, false);
        
        submitBtn.innerHTML = '<span class="spinner"></span> Deriving master key (Argon2id 64MB)...';
        // Allow UI to update before heavy computation
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const salt = crypto.strToBytes(email);
        const masterKey = await crypto.argon2id(password, salt, preloginData.kdfMemory, preloginData.kdfIterations, preloginData.kdfParallelism);
        const masterPasswordHash = await crypto.hkdf(masterKey, 'master_password_hash', 32);
        const vaultKey = await crypto.hkdf(masterKey, 'vault', 32);
        
        submitBtn.innerHTML = '<span class="spinner"></span> Authenticating...';
        const loginData = await api('POST', '/api/login', { 
            email, 
            masterPasswordHash: crypto.b64encode(masterPasswordHash)
        }, false);
        
        submitBtn.innerHTML = '<span class="spinner"></span> Unlocking vault...';
        const [pn, pc] = loginData.protectedSymKey.split('|');
        const userSymmetricKey = await crypto.aesGcmDecrypt(vaultKey, pn, pc);
        
        const [xn, xc] = loginData.encryptedX25519.split('|');
        const [en, ec] = loginData.encryptedEd25519.split('|');
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
        
        submitBtn.innerHTML = '<span class="spinner"></span> Verifying signatures...';
        // Signature verification uses email only (no username)
        const registrationData = crypto.strToBytes(email + '||' + loginData.x25519Public + '||' + loginData.ed25519Public);
        const signatureValid = await crypto.ed25519Verify(ed25519Public, loginData.registrationSig, registrationData);
        
        if (!signatureValid) throw new Error('Signature verification failed! Keys may be forged.');
        
        // Store in state (email instead of username)
        state.token = loginData.token;
        state.email = email;
        state.userSymKey = userSymmetricKey;
        state.x25519Priv = x25519Private;
        state.x25519Pub = x25519Public;
        state.x25519PubB64 = loginData.x25519Public;
        state.ed25519Priv = ed25519Private;
        state.ed25519Pub = ed25519Public;
        state.ed25519PubB64 = loginData.ed25519Public;
        
        // Encrypt keys with PIN (Argon2id 32MB - strong!)
        submitBtn.innerHTML = '<span class="spinner"></span> Encrypting with PIN (Argon2id 32MB)...';
        // Allow UI to update before heavy computation
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const encrypted = await encryptAndStoreKeys(pin, email, loginData.token, {
            userSymKey: userSymmetricKey,
            x25519Priv: x25519Private,
            x25519PubB64: loginData.x25519Public,
            ed25519Priv: ed25519Private,
            ed25519PubB64: loginData.ed25519Public
        });
        
        if (!encrypted) {
            throw new Error('Failed to encrypt keys with PIN');
        }
        
        
        toast(`Welcome back!`, 'success');
        setTimeout(() => window.location.href = '/dashboard.html', 500);
    } catch (err) {
        toast(err.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Unlock Vault';
    }
}
