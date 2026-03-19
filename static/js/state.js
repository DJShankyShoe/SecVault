/*
 * APP STATE OVERVIEW
 * - sessionStorage fields store lightweight non-secret session identifiers.
 * - private key objects remain in memory only for active operations.
 */
export const state = {
    // Persists the logged-in email in session storage.
    get email() {
        return sessionStorage.getItem("email");
    },

    set email(value) {
        if (value) {
            sessionStorage.setItem("email", value);
        } else {
            sessionStorage.removeItem("email");
        }
    },

    // Persists the user's X25519 public key in base64 form for session use.
    get x25519PubB64() {
        return sessionStorage.getItem("x25519PubB64");
    },

    set x25519PubB64(value) {
        if (value) {
            sessionStorage.setItem("x25519PubB64", value);
        } else {
            sessionStorage.removeItem("x25519PubB64");
        }
    },

    // Persists the user's Ed25519 public key in base64 form for session use.
    get ed25519PubB64() {
        return sessionStorage.getItem("ed25519PubB64");
    },

    set ed25519PubB64(value) {
        if (value) {
            sessionStorage.setItem("ed25519PubB64", value);
        } else {
            sessionStorage.removeItem("ed25519PubB64");
        }
    },

    // Keeps decrypted key material in memory only.
    userSymKey: null,
    x25519Priv: null,
    x25519Pub: null,
    ed25519Priv: null,
    ed25519Pub: null
};

// Clears all persisted session identifiers and in-memory key state.
export function clearState() {
    sessionStorage.removeItem("email");
    sessionStorage.removeItem("x25519PubB64");
    sessionStorage.removeItem("ed25519PubB64");

    state.userSymKey = null;
    state.x25519Priv = null;
    state.x25519Pub = null;
    state.ed25519Priv = null;
    state.ed25519Pub = null;
}

// Uses the presence of session email as a lightweight auth marker.
export function isAuthenticated() {
    const hasEmail = !!state.email;
    return hasEmail;
}