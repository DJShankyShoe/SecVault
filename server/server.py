#!/usr/bin/env python3
"""
SecVault - Zero-Knowledge End-to-End Encrypted File Sharing
Server-side API
"""


import os, json, time, sqlite3, base64, hashlib, hmac, re
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, 
            static_folder='../static',
            static_url_path='/static',
            template_folder='../templates')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max request size

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

DB_PATH = os.path.join(os.path.dirname(__file__), "secvault.db")
SESSION_TTL = 7200  # 2 hours
ACL_TIMESTAMP_WINDOW = 300  # 5 minutes for ACL signature freshness

# Valid permissions whitelist
VALID_PERMISSIONS = {'read', 'modify'}

# Email format validation used for registration/login inputs.
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Security headers applied on every response.
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "  # unsafe-eval for hash-wasm, unsafe-inline for HTML templates
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "  # Google Fonts
        "font-src 'self' https://fonts.gstatic.com; "  # Google Fonts
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ════════════════════════════════════════════════════════════
# Static page routes
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return redirect('/login.html')

@app.route("/login.html")
def login_page():
    return send_from_directory(app.template_folder, "login.html")

@app.route("/register.html")
def register_page():
    return send_from_directory(app.template_folder, "register.html")

@app.route("/dashboard.html")
def dashboard_page():
    return send_from_directory(app.template_folder, "dashboard.html")

# ════════════════════════════════════════════════════════════
# Database
# ════════════════════════════════════════════════════════════

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        email               TEXT PRIMARY KEY,
        master_pw_hash_hash TEXT NOT NULL,
        kdf_type            TEXT NOT NULL DEFAULT 'argon2id',
        kdf_memory          INTEGER NOT NULL DEFAULT 65536,
        kdf_iterations      INTEGER NOT NULL DEFAULT 15,
        kdf_parallelism     INTEGER NOT NULL DEFAULT 4,
        protected_sym_key   TEXT NOT NULL,
        x25519_public       TEXT NOT NULL,
        ed25519_public      TEXT NOT NULL,
        registration_sig    TEXT NOT NULL,
        encrypted_x25519    TEXT NOT NULL,
        encrypted_ed25519   TEXT NOT NULL
    )""")
    
    # Session table stores only token hashes, never raw tokens.
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        email       TEXT PRIMARY KEY,
        token_hash  TEXT NOT NULL,
        expires_at  REAL NOT NULL
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS files (
        file_id         TEXT PRIMARY KEY,
        owner           TEXT NOT NULL,
        version         INTEGER NOT NULL DEFAULT 1,
        filename_nonce  TEXT NOT NULL,
        filename_enc    TEXT NOT NULL,
        content_nonce   TEXT NOT NULL,
        content_enc     TEXT NOT NULL,
        content_hash    TEXT NOT NULL,
        content_sig     TEXT NOT NULL,
        last_modified_by TEXT NOT NULL,
        uploaded_at     REAL NOT NULL,
        updated_at      REAL NOT NULL,
        
        -- Encrypted chain key used to derive the next file version keys.
        chain_key_enc   TEXT,
        chain_key_nonce TEXT
    )""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS file_keys (
        file_id         TEXT NOT NULL,
        email           TEXT NOT NULL,
        
        -- Wrapped root key for users who can derive readable version keys.
        root_key_wrapped TEXT,
        wrap_nonce      TEXT,
        ephemeral_pub   TEXT,
        
        -- Wrapped chain key for update-only flows.
        user_chain_key_wrapped TEXT,
        user_chain_key_nonce TEXT,
        user_chain_ephemeral_pub TEXT,
        
        -- Highest file version this user is allowed to access.
        max_version     INTEGER NOT NULL DEFAULT 999999,
        
        permissions     TEXT NOT NULL DEFAULT 'read,modify',
        granted_at      REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (file_id, email)
    )""")
    
    # ACL log stores a hash chain to make tampering detectable.
    c.execute("""CREATE TABLE IF NOT EXISTS acl_log (
        log_id          TEXT PRIMARY KEY,
        file_id         TEXT NOT NULL,
        action          TEXT NOT NULL,
        target_user     TEXT NOT NULL,
        performed_by    TEXT NOT NULL,
        acl_sig         TEXT NOT NULL,
        timestamp       REAL NOT NULL,
        previous_hash   TEXT,
        entry_hash      TEXT,
        verified        INTEGER DEFAULT 0
    )""")
    
    # Tracks ACL nonces to reject replayed signed actions.
    c.execute("""CREATE TABLE IF NOT EXISTS acl_nonces (
        nonce           TEXT PRIMARY KEY,
        timestamp       REAL NOT NULL,
        file_id         TEXT NOT NULL,
        action          TEXT NOT NULL,
        actor           TEXT NOT NULL,
        created_at      REAL NOT NULL
    )""")
    
    # Create index for cleanup queries
    c.execute("""CREATE INDEX IF NOT EXISTS idx_nonces_created 
                 ON acl_nonces(created_at)""")
    
    # Version history for auditability and integrity checks.
    c.execute("""CREATE TABLE IF NOT EXISTS file_version_history (
        file_id         TEXT NOT NULL,
        version         INTEGER NOT NULL,
        content_hash    TEXT NOT NULL,
        created_at      REAL NOT NULL,
        created_by      TEXT NOT NULL,
        PRIMARY KEY (file_id, version)
    )""")
    
    db.commit()
    db.close()
    print("[ DOUBLE-RATCHET] ✓ Database initialized with version ratcheting")

# ════════════════════════════════════════════════════════════
# Auth helpers
# ════════════════════════════════════════════════════════════

def _hash_master_pw_hash(master_pw_hash_b64: str) -> str:
    mpw_hash = base64.b64decode(master_pw_hash_b64)
    return hashlib.sha256(mpw_hash).hexdigest()

def _verify_master_pw_hash(stored_hash: str, master_pw_hash_b64: str) -> bool:
    try:
        expected = _hash_master_pw_hash(master_pw_hash_b64)
        return hmac.compare_digest(expected, stored_hash)
    except:
        return False

def _random_token(n=32):
    return base64.urlsafe_b64encode(os.urandom(n)).decode()

# Email validation helper.
def _validate_email(email: str) -> bool:
    """Validate email format to prevent XSS and injection"""
    if not email or len(email) > 255:
        return False
    return EMAIL_REGEX.match(email) is not None

# Replay protection helper for ACL/modify actions.
def _check_and_store_nonce(nonce: str, timestamp: float, file_id: str, action: str, actor: str, db) -> bool:
    """
    Check if nonce has been used before and store it.
    Returns True if nonce is valid (not replayed), False if replayed.
    """
    # Check timestamp freshness (within ACL_TIMESTAMP_WINDOW seconds)
    current_time = time.time()
    if abs(current_time - timestamp) > ACL_TIMESTAMP_WINDOW:
        return False  # Stale timestamp
    
    # Check if nonce already used
    existing = db.execute(
        "SELECT nonce FROM acl_nonces WHERE nonce=?",
        (nonce,)
    ).fetchone()
    
    if existing:
        return False  # Replay attack detected
    
    # Store nonce
    db.execute(
        """INSERT INTO acl_nonces (nonce, timestamp, file_id, action, actor, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (nonce, timestamp, file_id, action, actor, current_time)
    )
    db.commit()
    
    # Cleanup old nonces (older than 2 * ACL_TIMESTAMP_WINDOW)
    cleanup_threshold = current_time - (2 * ACL_TIMESTAMP_WINDOW)
    db.execute("DELETE FROM acl_nonces WHERE created_at < ?", (cleanup_threshold,))
    db.commit()
    
    return True

# Session token hashing helpers.
def _hash_token(token: str) -> str:
    """Hash session token with SHA-256 before storing"""
    return hashlib.sha256(token.encode()).hexdigest()

def _create_session(email: str, db) -> str:
    """Create session and return raw token (store hash in DB)"""
    # Generate random token
    token_raw = _random_token(32)
    token_hash = _hash_token(token_raw)
    expires_at = time.time() + SESSION_TTL
    
    # Delete old session if exists
    db.execute("DELETE FROM sessions WHERE email=?", (email,))
    
    # Store token hash (not raw token)
    db.execute(
        "INSERT INTO sessions (email, token_hash, expires_at) VALUES (?, ?, ?)",
        (email, token_hash, expires_at)
    )
    db.commit()
    
    return token_raw  # Return raw token to client

def _validate_session(token_raw: str, db):
    """Validate session token and return email"""
    token_hash = _hash_token(token_raw)
    
    row = db.execute(
        "SELECT email, expires_at FROM sessions WHERE token_hash=?",
        (token_hash,)
    ).fetchone()
    
    if not row:
        return None
    
    if time.time() > row["expires_at"]:
        # Session expired
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        db.commit()
        return None
    
    return row["email"]

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Read session token from cookie and validate against hashed DB value.
        token_raw = request.cookies.get('session_token')
        if not token_raw:
            return jsonify({"error": "Unauthorized"}), 401
        
        db = get_db()
        email = _validate_session(token_raw, db)
        
        if not email:
            return jsonify({"error": "Session expired"}), 401
        
        g.email = email
        return f(*args, **kwargs)
    return decorated

# ════════════════════════════════════════════════════════════
# ACL signature verification
# ════════════════════════════════════════════════════════════

def _verify_acl_signature(file_id: str, action: str, target_user: str, 
                          signature_b64: str, actor_email: str, timestamp: int, db, permissions: list = None, nonce: str = None) -> bool:
    """Verify Ed25519 signature on ACL action"""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        # Get actor's Ed25519 public key
        row = db.execute(
            "SELECT ed25519_public FROM users WHERE email=?", (actor_email,)
        ).fetchone()
        
        if not row:
            return False
        
        # Import public key
        public_key_bytes = base64.b64decode(row["ed25519_public"])
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Reconstruct signed message using the exact canonical field order.
        # Include nonce and timestamp so signatures are bound to a single request.
        # For grant/modify/update_permissions actions: include permissions AND nonce
        if action in ["grant", "modify", "update_permissions"] and permissions:
            perms_str = ",".join(sorted(permissions))
            message_str = f"{action}||{file_id}||{target_user}||{perms_str}||{nonce}||{timestamp}"
        else:
            # For revoke/delete: include nonce but no permissions
            message_str = f"{action}||{file_id}||{target_user}||{nonce}||{timestamp}"
        
        message = message_str.encode()
        
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Verify signature
        public_key.verify(signature, message)
        return True
    except Exception as e:
        print(f"[ACL VERIFY] Signature verification failed: {e}")
        return False

# ════════════════════════════════════════════════════════════
# ACL audit hash chain
# ════════════════════════════════════════════════════════════

def _compute_entry_hash(file_id: str, action: str, target_user: str, 
                        performed_by: str, signature: str, timestamp: float, 
                        previous_hash: str) -> str:
    """Compute hash of audit log entry"""
    entry_data = {
        'file_id': file_id,
        'action': action,
        'target_user': target_user,
        'performed_by': performed_by,
        'signature': signature,
        'timestamp': timestamp,
        'previous_hash': previous_hash or '0' * 64
    }
    entry_json = json.dumps(entry_data, sort_keys=True)
    return hashlib.sha256(entry_json.encode()).hexdigest()

def _log_acl_action(file_id: str, action: str, target_user: str, 
                    performed_by: str, signature: str, timestamp: float, 
                    verified: bool, db) -> str:
    """Log ACL action with hash chain"""
    # Get previous hash
    row = db.execute(
        """SELECT entry_hash FROM acl_log 
           WHERE file_id=? 
           ORDER BY timestamp DESC 
           LIMIT 1""",
        (file_id,)
    ).fetchone()
    
    previous_hash = row["entry_hash"] if row else None
    
    # Compute entry hash
    entry_hash = _compute_entry_hash(
        file_id, action, target_user, performed_by,
        signature, timestamp, previous_hash
    )
    
    # Generate log ID
    log_id = _random_token(16)
    
    # Insert with hash chain
    db.execute(
        """INSERT INTO acl_log 
           (log_id, file_id, action, target_user, performed_by, acl_sig, 
            timestamp, previous_hash, entry_hash, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (log_id, file_id, action, target_user, performed_by, signature,
         timestamp, previous_hash, entry_hash, 1 if verified else 0)
    )
    
    return log_id

# ════════════════════════════════════════════════════════════
# Permission validation helpers
# ════════════════════════════════════════════════════════════

def _validate_permissions(permissions_list) -> bool:
    """Validate permission list against whitelist"""
    if not permissions_list or len(permissions_list) == 0:
        return False
    
    perms_set = set(permissions_list)
    
    # All permissions must be valid
    if not perms_set.issubset(VALID_PERMISSIONS):
        return False
    
    return True

def _has_permission(file_id: str, user_email: str, required_permission: str, db) -> bool:
    """Centralized permission check"""
    # Check ownership first
    file_row = db.execute(
        "SELECT owner FROM files WHERE file_id=?", (file_id,)
    ).fetchone()
    
    if not file_row:
        return False
    
    # Owner has all permissions
    if file_row["owner"] == user_email:
        return True
    
    # Check file_keys
    access_row = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, user_email)
    ).fetchone()
    
    if not access_row:
        return False
    
    permissions_str = access_row["permissions"]
    
    # Validate permission string format
    perms_list = permissions_str.split(',') if permissions_str else []
    if not _validate_permissions(perms_list):
        return False
    
    # IMPORTANT: 'modify' permission implicitly grants 'read' permission
    # You can't modify what you can't read
    if required_permission == 'read' and 'modify' in perms_list:
        return True
    
    # Check if required permission is present
    return required_permission in perms_list

# ════════════════════════════════════════════════════════════
# Auth endpoints
# ════════════════════════════════════════════════════════════

@app.route("/api/register", methods=["POST"])
@limiter.limit("3 per hour")  # Rate limit registration attempts.
def register():
    d = request.get_json(force=True)
    required = ["email","masterPasswordHash","protectedSymKey",
                "x25519Public","ed25519Public","registrationSig",
                "encryptedX25519","encryptedEd25519"]
    for f in required:
        if not d.get(f): return jsonify({"error": f"Missing: {f}"}), 400

    email = d["email"].strip().lower()
    
    # Validate email format early to reject malformed identifiers.
    if not _validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    # Guard against unexpectedly large auth/key fields.
    if len(d["masterPasswordHash"]) > 100:
        return jsonify({"error": "Invalid masterPasswordHash length"}), 400
    if len(d["x25519Public"]) > 100 or len(d["ed25519Public"]) > 100:
        return jsonify({"error": "Invalid public key length"}), 400
    if len(d["registrationSig"]) > 200:
        return jsonify({"error": "Invalid signature length"}), 400
    
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify({"error": "Email already registered"}), 409

    mpw_hash_hash = _hash_master_pw_hash(d["masterPasswordHash"])

    db.execute(
        """INSERT INTO users
           (email, master_pw_hash_hash, kdf_type, kdf_memory, kdf_iterations, kdf_parallelism,
            protected_sym_key, x25519_public, ed25519_public, registration_sig,
            encrypted_x25519, encrypted_ed25519)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (email, mpw_hash_hash,
         "argon2id", 65536, 15, 4,
         d["protectedSymKey"], d["x25519Public"], d["ed25519Public"], d["registrationSig"],
         d["encryptedX25519"], d["encryptedEd25519"])
    )
    db.commit()
    return jsonify({"message": "Account created"}), 201

@app.route("/api/prelogin", methods=["POST"])
@limiter.limit("10 per minute")  # Rate limit KDF-parameter probing.
def prelogin():
    d = request.get_json(force=True)
    email = d.get("email","").strip().lower()
    db = get_db()
    row = db.execute(
        "SELECT email, kdf_type, kdf_memory, kdf_iterations, kdf_parallelism FROM users WHERE email=?",
        (email,)
    ).fetchone()
    if not row:
        return jsonify({
            "kdfType": "argon2id",
            "kdfMemory": 65536,
            "kdfIterations": 15,
            "kdfParallelism": 4
        }), 200
    return jsonify({
        "email": row["email"],
        "kdfType": row["kdf_type"],
        "kdfMemory": row["kdf_memory"],
        "kdfIterations": row["kdf_iterations"],
        "kdfParallelism": row["kdf_parallelism"]
    }), 200

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")  # Rate limit login attempts.
def login():
    d = request.get_json(force=True)
    email = d.get("email","").strip().lower()
    mpw_hash = d.get("masterPasswordHash","")
    
    db = get_db()
    row = db.execute(
        """SELECT email, master_pw_hash_hash, protected_sym_key,
           x25519_public, ed25519_public, registration_sig,
           encrypted_x25519, encrypted_ed25519
           FROM users WHERE email=?""",
        (email,)
    ).fetchone()
    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    if not _verify_master_pw_hash(row["master_pw_hash_hash"], mpw_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    # Create a new session token and persist only its hash in DB.
    token = _create_session(email, db)
    
    # Session token is delivered via HttpOnly cookie, not JSON body.
    response = jsonify({
        "message": "Login successful",
        "email": row["email"],
        "protectedSymKey": row["protected_sym_key"],
        "x25519Public": row["x25519_public"],
        "ed25519Public": row["ed25519_public"],
        "registrationSig": row["registration_sig"],
        "encryptedX25519": row["encrypted_x25519"],
        "encryptedEd25519": row["encrypted_ed25519"]
    })
    
    # HttpOnly cookie prevents JavaScript access to the session token.
    response.set_cookie(
        'session_token',
        token,
        httponly=True,      # JavaScript cannot read this cookie (XSS protection)
        secure=False,       # Set to True in production with HTTPS
        samesite='Lax',     # CSRF protection
        max_age=86400       # 24 hours
    )
    
    return response, 200

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    """Invalidate server-side session and clear auth/key cookies."""
    # Read token from session cookie and delete matching DB session.
    token_raw = request.cookies.get('session_token')
    if not token_raw:
        return jsonify({"error": "No session"}), 401
    
    token_hash = _hash_token(token_raw)
    
    db = get_db()
    # Delete session from database
    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    db.commit()
    
    # Clear the cookies
    response = jsonify({"message": "Logged out successfully"})
    response.set_cookie('session_token', '', expires=0, httponly=True, samesite='Lax')
    response.set_cookie('encrypted_keys', '', expires=0, httponly=True, samesite='Lax')
    
    return response, 200

@app.route("/api/store-encrypted-keys", methods=["POST"])
@require_auth
def store_encrypted_keys():
    """Store PIN-encrypted key blob in an HttpOnly cookie."""
    d = request.get_json(force=True)
    encrypted_blob = d.get("encryptedBlob")
    
    if not encrypted_blob:
        return jsonify({"error": "Missing encryptedBlob"}), 400
    
    # Keep encrypted key blob outside JavaScript-accessible storage.
    response = jsonify({"message": "Keys stored securely"})
    response.set_cookie(
        'encrypted_keys',
        json.dumps(encrypted_blob),
        httponly=True,      # JavaScript cannot access (XSS protection)
        secure=False,       # Set True in production with HTTPS
        samesite='Lax',
        max_age=86400       # 24 hours
    )
    
    return response, 200

@app.route("/api/encrypted-keys", methods=["GET"])
@require_auth
def get_encrypted_keys():
    """Return PIN-encrypted key blob from HttpOnly cookie."""
    encrypted_keys = request.cookies.get('encrypted_keys')
    
    if not encrypted_keys:
        return jsonify({"error": "No encrypted keys found"}), 404
    
    try:
        encrypted_blob = json.loads(encrypted_keys)
        return jsonify(encrypted_blob), 200
    except:
        return jsonify({"error": "Invalid encrypted keys"}), 400

@app.route("/api/users/<email>/public-keys", methods=["GET"])
@require_auth
def get_user_public_keys(email):
    email = email.strip().lower()
    db = get_db()
    # Include registration signature so clients can verify key authenticity.
    row = db.execute(
        "SELECT x25519_public, ed25519_public, registration_sig FROM users WHERE email=?",
        (email,)
    ).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "email": email,
        "x25519Public": row["x25519_public"],
        "ed25519Public": row["ed25519_public"],
        "registrationSig": row["registration_sig"]
    }), 200

# ════════════════════════════════════════════════════════════
# File endpoints
# ════════════════════════════════════════════════════════════

@app.route("/api/files", methods=["POST"])
@require_auth
def upload_file():
    d = request.get_json(force=True)
    required = ["fileId","filename_nonce","filename_enc",
                "content_nonce","content_enc","contentHash",
                "contentSig","wrappedKey","wrapNonce","ephemeralPub"]
    for f in required:
        if not d.get(f): return jsonify({"error": f"Missing: {f}"}), 400
    
    file_id = d["fileId"]
    db = get_db()
    
    if db.execute("SELECT 1 FROM files WHERE file_id=?", (file_id,)).fetchone():
        return jsonify({"error": "File ID collision"}), 409
    
    now = time.time()
    
    # Optional chain key fields used for subsequent version updates.
    chain_key_enc = d.get("chainKeyEnc")
    chain_key_nonce = d.get("chainKeyNonce")
    
    db.execute(
        """INSERT INTO files
           (file_id,owner,version,filename_nonce,filename_enc,content_nonce,content_enc,
            content_hash,content_sig,last_modified_by,uploaded_at,updated_at,
            chain_key_enc,chain_key_nonce)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (file_id, g.email, 1,
         d["filename_nonce"], d["filename_enc"],
         d["content_nonce"], d["content_enc"],
         d["contentHash"], d["contentSig"],
         g.email, now, now,
         chain_key_enc, chain_key_nonce)
    )
    
    # Store wrapped root key and metadata for the owner's initial access.
    db.execute(
        """INSERT INTO file_keys(file_id,email,root_key_wrapped,wrap_nonce,ephemeral_pub,
                                   max_version,permissions,granted_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (file_id, g.email, d["wrappedKey"], d["wrapNonce"], d["ephemeralPub"],
         999999, "read,modify", now)
    )
    
    # Record initial version in version history.
    db.execute(
        """INSERT INTO file_version_history(file_id,version,content_hash,created_at,created_by)
           VALUES(?,?,?,?,?)""",
        (file_id, 1, d["contentHash"], now, g.email)
    )
    
    db.commit()
    
    return jsonify({"message": "File uploaded", "fileId": file_id, "version": 1}), 201

@app.route("/api/files", methods=["GET"])
@require_auth
def list_files():
    db = get_db()
    
    # Get all file IDs user has access to
    file_id_rows = db.execute(
        "SELECT file_id FROM file_keys WHERE email=? ORDER BY file_id",
        (g.email,)
    ).fetchall()
    
    files = []
    for row in file_id_rows:
        file_id = row["file_id"]
        
        # Get file metadata
        file_row = db.execute(
            "SELECT * FROM files WHERE file_id=?", (file_id,)
        ).fetchone()
        
        if not file_row:
            continue
        
        # Get user's key info for this file
        key_row = db.execute(
            "SELECT root_key_wrapped, wrap_nonce, ephemeral_pub, permissions FROM file_keys WHERE file_id=? AND email=?",
            (file_id, g.email)
        ).fetchone()
        
        if not key_row:
            continue
        
        files.append({
            "file_id": file_row["file_id"],
            "owner": file_row["owner"],
            "version": file_row["version"],
            "filename_nonce": file_row["filename_nonce"],
            "filename_enc": file_row["filename_enc"],
            "uploaded_at": file_row["uploaded_at"],
            "updated_at": file_row["updated_at"],
            "rootKey": key_row["root_key_wrapped"],
            "wrapNonce": key_row["wrap_nonce"],
            "ephemeralPub": key_row["ephemeral_pub"],
            "permissions": key_row["permissions"]
        })
    
    return jsonify({"files": files}), 200

@app.route("/api/files/<file_id>", methods=["GET"])
@require_auth
def get_file_metadata(file_id):
    db = get_db()
    
    # Check if user has access
    access = db.execute(
        "SELECT 1 FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    
    if not access:
        return jsonify({"error": "Access denied"}), 403
    
    # Get file metadata
    file_row = db.execute(
        "SELECT * FROM files WHERE file_id=?", (file_id,)
    ).fetchone()
    
    if not file_row:
        return jsonify({"error": "Not found"}), 404
    
    # Get wrapped key
    key_row = db.execute(
        "SELECT root_key_wrapped, wrap_nonce, ephemeral_pub, permissions, max_version FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    
    return jsonify({
        "fileId": file_row["file_id"],
        "owner": file_row["owner"],
        "version": file_row["version"],
        "rootKey": key_row["root_key_wrapped"],
        "wrapNonce": key_row["wrap_nonce"],
        "ephemeralPub": key_row["ephemeral_pub"],
        "maxVersion": key_row["max_version"],
        "permissions": key_row["permissions"].split(",") if key_row["permissions"] else ["read", "modify"]
    }), 200

@app.route("/api/files/<file_id>/download", methods=["GET"])
@require_auth
def download_file(file_id):
    db = get_db()
    
    # Centralized permission check keeps read/modify logic consistent.
    # Users need 'read' OR 'modify' permission to download (modify needs keys to update)
    if not (_has_permission(file_id, g.email, 'read', db) or 
            _has_permission(file_id, g.email, 'modify', db)):
        return jsonify({"error": "Permission denied - no read or modify access"}), 403
    
    file_row = db.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row:
        return jsonify({"error": "Not found"}), 404
    
    key_row = db.execute(
        "SELECT root_key_wrapped, wrap_nonce, ephemeral_pub, max_version FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    
    if not key_row:
        return jsonify({"error": "Access denied"}), 403
    
    # Enforce per-user max_version access control.
    if file_row["version"] > key_row["max_version"]:
        return jsonify({"error": f"Access denied - version {file_row['version']} exceeds your max_version {key_row['max_version']}"}), 403
    
    return jsonify({
        "owner": file_row["owner"],
        "filename_nonce": file_row["filename_nonce"],
        "filename_enc": file_row["filename_enc"],
        "content_nonce": file_row["content_nonce"],
        "content_enc": file_row["content_enc"],
        "content_hash": file_row["content_hash"],
        "content_sig": file_row["content_sig"],
        "version": file_row["version"],
        "rootKey": key_row["root_key_wrapped"],
        "wrapNonce": key_row["wrap_nonce"],
        "ephemeralPub": key_row["ephemeral_pub"],
        "maxVersion": key_row["max_version"],
        "chain_key_enc": file_row["chain_key_enc"],
        "chain_key_nonce": file_row["chain_key_nonce"],
        "last_modified_by": file_row["last_modified_by"]
    }), 200

@app.route("/api/files/<file_id>", methods=["DELETE"])
@require_auth
def delete_file(file_id):
    db = get_db()
    
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row:
        return jsonify({"error": "Not found"}), 404
    
    if file_row["owner"] != g.email:
        return jsonify({"error": "Owner only"}), 403
    
    db.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    db.execute("DELETE FROM file_keys WHERE file_id=?", (file_id,))
    db.commit()
    
    return jsonify({"message": "File deleted"}), 200

@app.route("/api/files/<file_id>", methods=["PUT"])
@require_auth
def update_file(file_id):
    d = request.get_json(force=True)
    db = get_db()
    
    file_row = db.execute("SELECT owner, version FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row:
        return jsonify({"error": "Not found"}), 404
    
    # Single centralized permission check avoids duplicated authorization logic.
    if not _has_permission(file_id, g.email, 'modify', db):
        return jsonify({"error": "Permission denied - no modify access"}), 403
    
    # Update file content and increment version
    new_version = file_row["version"] + 1
    now = time.time()
    
    # Optional next-version chain key provided by client.
    chain_key_enc = d.get("chainKeyEnc")
    chain_key_nonce = d.get("chainKeyNonce")
    
    db.execute(
        """UPDATE files 
           SET filename_nonce=?, filename_enc=?, content_nonce=?, content_enc=?,
               content_hash=?, content_sig=?, version=?, updated_at=?, last_modified_by=?,
               chain_key_enc=?, chain_key_nonce=?
           WHERE file_id=?""",
        (d["filename_nonce"], d["filename_enc"],
         d["content_nonce"], d["content_enc"],
         d["contentHash"], d["contentSig"],
         new_version, now, g.email,
         chain_key_enc, chain_key_nonce,
         file_id)
    )
    
    # Record new version in immutable history table.
    db.execute(
        """INSERT INTO file_version_history(file_id,version,content_hash,created_at,created_by)
           VALUES(?,?,?,?,?)""",
        (file_id, new_version, d["contentHash"], now, g.email)
    )
    
    # Modify action must include a valid signed request payload.
    if not d.get("modifySig"):
        db.rollback()
        return jsonify({"error": "Missing modifySig"}), 400
    
    timestamp = d.get("timestamp")
    if not timestamp:
        db.rollback()
        return jsonify({"error": "Missing timestamp"}), 400
    
    nonce = d.get("nonce")
    if not nonce:
        db.rollback()
        return jsonify({"error": "Missing nonce"}), 400
    
    # Check for replay attack
    if not _check_and_store_nonce(nonce, timestamp / 1000, file_id, "modify", g.email, db):
        db.rollback()
        return jsonify({"error": "Replay attack detected or stale timestamp"}), 401
    
    # Verify signature (no permissions for modify action)
    sig_valid = _verify_acl_signature(
        file_id, "modify", g.email, d["modifySig"], g.email, timestamp, db, None, nonce
    )
    
    if not sig_valid:
        db.rollback()
        return jsonify({"error": "Invalid modify signature"}), 401
    
    # Log the modification in ACL log
    _log_acl_action(
        file_id, "modify", g.email, g.email, 
        d["modifySig"], timestamp / 1000, sig_valid, db
    )
    
    db.commit()
    
    return jsonify({
        "message": "File updated",
        "fileId": file_id,
        "version": new_version
    }), 200

# ════════════════════════════════════════════════════════════
# ACL endpoints
# ════════════════════════════════════════════════════════════

@app.route("/api/files/<file_id>/access", methods=["GET"])
@require_auth
def get_acl(file_id):
    db = get_db()
    
    # Get file info
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row:
        return jsonify({"error": "Not found"}), 404
    
    owner = file_row["owner"]
    
    # Allow owner and shared users to read ACL details.
    if owner != g.email:
        # Check if user has access as shared user
        shared_access = db.execute(
            "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
            (file_id, g.email)
        ).fetchone()
        
        if not shared_access:
            # Not owner and not shared user
            return jsonify({"error": "Access denied"}), 403
    
    # Authorized - return ACL
    users_rows = db.execute(
        "SELECT email, permissions, granted_at FROM file_keys WHERE file_id=?", (file_id,)
    ).fetchall()
    
    users = []
    for row in users_rows:
        perms = row["permissions"].split(",") if row["permissions"] else ["read", "modify"]
        users.append({
            "email": row["email"],
            "permissions": perms,
            "granted_at": row["granted_at"] if row["granted_at"] else 0
        })
    
    # Sort users: owner first, then others alphabetically
    users.sort(key=lambda u: (u["email"] != owner, u["email"]))
    
    logs = [dict(r) for r in db.execute(
        "SELECT * FROM acl_log WHERE file_id=? ORDER BY timestamp DESC",
        (file_id,)
    ).fetchall()]
    
    return jsonify({"users": users, "aclLog": logs}), 200

@app.route("/api/files/<file_id>/access", methods=["POST"])
@require_auth
def grant_access(file_id):
    d = request.get_json(force=True)
    db = get_db()
    
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row: return jsonify({"error": "Not found"}), 404
    if file_row["owner"] != g.email: return jsonify({"error": "Owner only"}), 403
    
    target = d.get("targetEmail","").strip().lower()
    if not target: return jsonify({"error": "Missing targetEmail"}), 400
    
    # Get permissions
    permissions = d.get("permissions", ["read", "modify"])
    
    # Reject unknown/empty permission sets.
    if not _validate_permissions(permissions):
        return jsonify({"error": "Invalid permissions - must be 'read' and/or 'modify'"}), 400
    
    # Convert to comma-separated string for storage
    perms_str = ",".join(sorted(permissions))
    
    user_exists = db.execute("SELECT 1 FROM users WHERE email=?", (target,)).fetchone()
    if not user_exists: return jsonify({"error": "User not found"}), 404
    
    # Get timestamp
    timestamp = d.get("timestamp", int(time.time() * 1000))
    
    # Signature is required for ACL mutation requests.
    if not d.get("aclSig"):
        return jsonify({"error": "Missing aclSig"}), 400
    
    # Nonce + timestamp replay protection.
    nonce = d.get("nonce") or d["aclSig"][:32]  # Use first part of signature as nonce
    if not _check_and_store_nonce(nonce, timestamp / 1000, file_id, "grant", g.email, db):
        return jsonify({"error": "Replay attack detected or stale timestamp"}), 401
    
    sig_valid = _verify_acl_signature(
        file_id, "grant", target, d["aclSig"], g.email, timestamp, db, permissions, nonce
    )
    
    if not sig_valid:
        return jsonify({"error": "Invalid signature"}), 401
    
    # Signature valid - proceed
    now = time.time()
    db.execute(
        """INSERT OR REPLACE INTO file_keys(
            file_id, email, root_key_wrapped, wrap_nonce, ephemeral_pub,
            user_chain_key_wrapped, user_chain_key_nonce, user_chain_ephemeral_pub,
            max_version, permissions, granted_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (file_id, target, 
         d.get("wrappedKey"), d.get("wrapNonce"), d.get("ephemeralPub"),
         d.get("wrappedChainKey"), d.get("chainKeyNonce"), d.get("chainKeyEphemeralPub"),
         999999, perms_str, now)
    )
    
    # Append operation to tamper-evident ACL log chain.
    _log_acl_action(
        file_id, "grant", target, g.email,
        d["aclSig"], timestamp / 1000, sig_valid, db
    )
    
    db.commit()
    
    return jsonify({"message": "Access granted", "permissions": permissions}), 200

@app.route("/api/files/<file_id>/access/<target_email>", methods=["DELETE"])
@require_auth
def revoke_access(file_id, target_email):
    d = request.get_json(force=True)
    target_email = target_email.strip().lower()
    db = get_db()
    
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row: return jsonify({"error": "Not found"}), 404
    if file_row["owner"] != g.email: return jsonify({"error": "Owner only"}), 403
    if target_email == g.email: return jsonify({"error": "Cannot revoke owner"}), 400
    
    # Get timestamp
    timestamp = d.get("timestamp", int(time.time() * 1000))
    
    # Signature is required for revoke operations.
    if not d.get("aclSig"):
        return jsonify({"error": "Missing aclSig"}), 400
    
    # Nonce + timestamp replay protection.
    nonce = d.get("nonce") or d["aclSig"][:32]
    if not _check_and_store_nonce(nonce, timestamp / 1000, file_id, "revoke", g.email, db):
        return jsonify({"error": "Replay attack detected or stale timestamp"}), 401
    
    sig_valid = _verify_acl_signature(
        file_id, "revoke", target_email, d["aclSig"], g.email, timestamp, db, None, nonce
    )
    
    if not sig_valid:
        return jsonify({"error": "Invalid signature"}), 401
    
    # Delete access
    db.execute("DELETE FROM file_keys WHERE file_id=? AND email=?", (file_id, target_email))
    
    # Append operation to tamper-evident ACL log chain.
    _log_acl_action(
        file_id, "revoke", target_email, g.email,
        d["aclSig"], timestamp / 1000, sig_valid, db
    )
    
    db.commit()
    
    return jsonify({"message": "Access revoked"}), 200

@app.route("/api/files/<file_id>/access/<target_email>", methods=["PATCH"])
@require_auth
def update_permissions(file_id, target_email):
    """Update permissions for a user without revoking access"""
    d = request.get_json(force=True)
    target_email = target_email.strip().lower()
    db = get_db()
    
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row: return jsonify({"error": "Not found"}), 404
    if file_row["owner"] != g.email: return jsonify({"error": "Owner only"}), 403
    
    # Get new permissions
    permissions = d.get("permissions", [])
    
    # Reject unknown/empty permission sets.
    if not _validate_permissions(permissions):
        return jsonify({"error": "Invalid permissions - must be 'read' and/or 'modify'"}), 400
    
    # Convert to comma-separated string
    perms_str = ",".join(sorted(permissions))
    
    # Check if user has access
    access = db.execute(
        "SELECT 1 FROM file_keys WHERE file_id=? AND email=?",
        (file_id, target_email)
    ).fetchone()
    if not access:
        return jsonify({"error": "User does not have access to this file"}), 404
    
    # Get timestamp
    timestamp = d.get("timestamp", int(time.time() * 1000))
    
    # Signature is required for permission update operations.
    if not d.get("updateSig"):
        return jsonify({"error": "Missing updateSig"}), 400
    
    # Nonce + timestamp replay protection.
    nonce = d.get("nonce") or d["updateSig"][:32]
    if not _check_and_store_nonce(nonce, timestamp / 1000, file_id, "update_permissions", g.email, db):
        return jsonify({"error": "Replay attack detected or stale timestamp"}), 401
    
    sig_valid = _verify_acl_signature(
        file_id, "update_permissions", target_email, 
        d["updateSig"], g.email, timestamp, db, permissions, nonce
    )
    
    if not sig_valid:
        return jsonify({"error": "Invalid signature"}), 401
    
    # Update permissions
    db.execute(
        "UPDATE file_keys SET permissions=? WHERE file_id=? AND email=?",
        (perms_str, file_id, target_email)
    )
    
    # Append operation to tamper-evident ACL log chain.
    _log_acl_action(
        file_id, "update_permissions", target_email, g.email,
        d["updateSig"], timestamp / 1000, sig_valid, db
    )
    
    db.commit()
    
    return jsonify({"message": "Permissions updated", "permissions": permissions}), 200

if __name__ == "__main__":
    init_db()
    print("SecVault")
    print("http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)