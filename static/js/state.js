/**
 * SecVault v3.0 - Application State (Email-only)
 */

export const state = {
    // Session data (persists in sessionStorage)
    get token() {
        return sessionStorage.getItem('token');
    },
    set token(value) {
        if (value) {
            sessionStorage.setItem('token', value);
        } else {
            sessionStorage.removeItem('token');
        }
    },
    
    get email() {
        return sessionStorage.getItem('email');
    },
    set email(value) {
        if (value) {
            sessionStorage.setItem('email', value);
        } else {
            sessionStorage.removeItem('email');
        }
    },
    
    get x25519PubB64() {
        return sessionStorage.getItem('x25519PubB64');
    },
    set x25519PubB64(value) {
        if (value) sessionStorage.setItem('x25519PubB64', value);
        else sessionStorage.removeItem('x25519PubB64');
    },
    
    get ed25519PubB64() {
        return sessionStorage.getItem('ed25519PubB64');
    },
    set ed25519PubB64(value) {
        if (value) sessionStorage.setItem('ed25519PubB64', value);
        else sessionStorage.removeItem('ed25519PubB64');
    },
    
    // Crypto keys (in-memory only)
    userSymKey: null,
    x25519Priv: null,
    x25519Pub: null,
    ed25519Priv: null,
    ed25519Pub: null
};

export function clearState() {
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('email');
    sessionStorage.removeItem('x25519PubB64');
    sessionStorage.removeItem('ed25519PubB64');
    
    state.userSymKey = null;
    state.x25519Priv = null;
    state.x25519Pub = null;
    state.ed25519Priv = null;
    state.ed25519Pub = null;
    
}

export function isAuthenticated() {
    const hasToken = !!state.token;
    return hasToken;
}
