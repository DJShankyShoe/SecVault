# 🔐 SecVault — Zero-Knowledge End-to-End Encrypted File Vault

A zero-knowledge file storage and sharing system where the server never has access to plaintext files, passwords, or encryption keys. All cryptographic operations — key derivation, encryption, and signing — happen client-side, so even a fully compromised server cannot read stored data or forge access grants.

## 🎯 Overview

SecVault lets users upload, store, and securely share files without trusting the server with their data. Every file is encrypted in the browser before it ever leaves the client, using per-file key ratcheting so each new version derives fresh keys without exposing old ones. Access control is enforced through cryptographically signed, replay-protected ACL operations rather than server-trusted permission flags.

**Key Properties:**
- Zero-knowledge architecture — server stores only ciphertext, hashes, and wrapped keys
- Per-version key ratcheting for forward secrecy on file updates
- Signed, nonce-protected ACL operations (grant / revoke / update permissions)
- Tamper-evident hash-chained audit log for all access changes
- TOFU key pinning to detect impersonation or key-substitution attacks

## ✨ Key Features

**Zero-Knowledge Encryption**
- Master password never leaves the client — only a hash-of-hash is sent for authentication
- Files encrypted with AES-GCM before upload; filenames encrypted separately
- Per-user key wrapping via X25519 so shared files are decryptable only by authorized recipients

**File Version Ratcheting**
- Each file update derives new content/chain keys from the previous version's chain key
- Users can be granted access up to a specific version (`max_version`), enabling scoped historical access
- Full version history retained with content hashes for integrity verification

**Signed Access Control**
- Every grant, revoke, and permission update requires an Ed25519 signature from the acting user
- Nonce + timestamp validation prevents replay of captured ACL requests
- Granular permissions (`read`, `modify`) enforced per user, per file

**Tamper-Evident Audit Trail**
- ACL actions are appended to a hash-chained log (`previous_hash` → `entry_hash`)
- Any retroactive edit to the log breaks the chain and is detectable on verification

**Key Pinning (TOFU)**
- On first contact, a recipient's public key fingerprint is pinned locally
- Future interactions are checked against the pinned fingerprint to flag unexpected key changes (e.g., account takeover or MITM)

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip

### Quick Start

```bash
# Linux / macOS
chmod +x run.sh
./run.sh
```

```bat
:: Windows
run.bat
```

This installs dependencies (Flask, Flask-Limiter, Flask-CORS, cryptography), initializes the SQLite database, and starts the server.

**Manual setup:**

```bash
pip install -r requirements.txt
cd server
python3 server.py
```

Then open **http://127.0.0.1:5000** in your browser.

## 🔧 Configuration

- `SESSION_TTL` - session token lifetime (default: 2 hours)
- `ACL_TIMESTAMP_WINDOW` - allowed freshness window for signed ACL requests (default: 5 minutes)
- `MAX_CONTENT_LENGTH` - max upload size (default: 16 MB)
- Security headers (CSP, X-Frame-Options, Referrer-Policy, etc.) are applied globally via Flask's `after_request` hook

## 🧩 Project Structure

```
SecVault/
├── server/
│   ├── server.py          # Flask API, auth, ACL, file storage
│   └── secvault.db        # SQLite database
├── static/
│   ├── css/main.css
│   └── js/
│       ├── crypto.js       # Client-side crypto primitives + ratchet
│       ├── keystore.js     # Session key management
│       ├── key-pinning.js  # TOFU public key pinning
│       ├── acl.js          # Signed access-control requests
│       ├── files.js        # File upload/download/versioning
│       ├── api.js          # API client
│       ├── state.js        # Client session state
│       ├── dashboard.js
│       ├── login.js
│       └── register.js
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
├── requirements.txt
├── run.sh
└── run.bat
```

## 📝 License

This project is licensed under the MIT License.
