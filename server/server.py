"""
server.py — SecVault v3.0: Email-only (Clean)
"""

import os, json, time, sqlite3, base64, hashlib, hmac
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g, redirect

app = Flask(__name__, 
            static_folder='../static',
            static_url_path='/static',
            template_folder='../templates')

DB_PATH = os.path.join(os.path.dirname(__file__), "secvault_v3.db")
SESSION_TTL = 7200
# ════════════════════════════════════════════════════════════
# Serve HTML files
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
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token       TEXT PRIMARY KEY,
        email       TEXT NOT NULL,
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
        updated_at      REAL NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS file_keys (
        file_id         TEXT NOT NULL,
        email           TEXT NOT NULL,
        wrapped_key     TEXT NOT NULL,
        wrap_nonce      TEXT NOT NULL,
        ephemeral_pub   TEXT NOT NULL,
        permissions     TEXT NOT NULL DEFAULT 'read,modify',
        PRIMARY KEY (file_id, email)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS acl_log (
        log_id          TEXT PRIMARY KEY,
        file_id         TEXT NOT NULL,
        action          TEXT NOT NULL,
        target_user     TEXT NOT NULL,
        performed_by    TEXT NOT NULL,
        acl_sig         TEXT NOT NULL,
        timestamp       REAL NOT NULL
    )""")
    db.commit()
    db.close()
    print("[v3.0] ✓ Database initialized")
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

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth[7:]
        db = get_db()
        row = db.execute(
            "SELECT email, expires_at FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if not row or time.time() > row["expires_at"]:
            if row: db.execute("DELETE FROM sessions WHERE token=?", (token,)); db.commit()
            return jsonify({"error": "Session expired"}), 401
        g.email = row["email"]
        return f(*args, **kwargs)
    return decorated
# ════════════════════════════════════════════════════════════
# Auth endpoints
# ════════════════════════════════════════════════════════════

@app.route("/api/register", methods=["POST"])
def register():
    d = request.get_json(force=True)
    required = ["email","masterPasswordHash","protectedSymKey",
                "x25519Public","ed25519Public","registrationSig",
                "encryptedX25519","encryptedEd25519"]
    for f in required:
        if not d.get(f): return jsonify({"error": f"Missing: {f}"}), 400

    email = d["email"].strip().lower()
    
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

    db.execute("DELETE FROM sessions WHERE email=?", (email,))
    token = _random_token(32)
    db.execute("INSERT INTO sessions(token,email,expires_at) VALUES(?,?,?)",
               (token, email, time.time() + SESSION_TTL))
    db.commit()

    return jsonify({
        "token": token,
        "email": email,
        "protectedSymKey": row["protected_sym_key"],
        "x25519Public": row["x25519_public"],
        "ed25519Public": row["ed25519_public"],
        "registrationSig": row["registration_sig"],
        "encryptedX25519": row["encrypted_x25519"],
        "encryptedEd25519": row["encrypted_ed25519"],
        "expiresIn": SESSION_TTL,
    }), 200
@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization","")[7:]
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()
    return jsonify({"message": "Logged out"}), 200
@app.route("/api/users/<email>/public-keys", methods=["GET"])
@require_auth
def get_pubkeys(email):
    email = email.strip().lower()
    db = get_db()
    row = db.execute(
        "SELECT x25519_public, ed25519_public, registration_sig FROM users WHERE email=?",
        (email,)
    ).fetchone()
    if not row: return jsonify({"error": "User not found"}), 404
    return jsonify({
        "x25519Public": row["x25519_public"],
        "ed25519Public": row["ed25519_public"],
        "registrationSig": row["registration_sig"]
    }), 200
# ════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════
# Files
# ════════════════════════════════════════════════════════════

@app.route("/api/files", methods=["GET"])
@require_auth
def list_files():
    db = get_db()
    rows = db.execute(
        """SELECT f.file_id, f.filename_nonce, f.filename_enc, f.owner, f.version,
                  f.content_hash, f.content_sig, f.last_modified_by, f.uploaded_at, f.updated_at,
                  fk.wrapped_key, fk.wrap_nonce, fk.ephemeral_pub, fk.permissions
           FROM files f JOIN file_keys fk
           ON f.file_id=fk.file_id AND fk.email=?
           ORDER BY f.updated_at DESC""",
        (g.email,)
    ).fetchall()
    return jsonify({"files": [dict(r) for r in rows]}), 200
@app.route("/api/files", methods=["POST"])
@require_auth
def upload_file():
    d = request.get_json(force=True)
    for f in ["fileId","filename_nonce","filename_enc","content_nonce","content_enc",
              "contentHash","contentSig","wrapped_key","wrap_nonce","ephemeral_pub"]:
        if not d.get(f): return jsonify({"error": f"Missing: {f}"}), 400

    file_id = d["fileId"]
    now = time.time()
    db = get_db()
    
    existing = db.execute("SELECT 1 FROM files WHERE file_id=?", (file_id,)).fetchone()
    if existing:
        return jsonify({"error": "File ID collision"}), 409
    
    db.execute(
        """INSERT INTO files(file_id,owner,version,filename_nonce,filename_enc,
           content_nonce,content_enc,content_hash,content_sig,last_modified_by,uploaded_at,updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (file_id, g.email, 1,
         d["filename_nonce"], d["filename_enc"],
         d["content_nonce"], d["content_enc"],
         d["contentHash"], d["contentSig"], 
         g.email, now, now)
    )
    db.execute(
        """INSERT INTO file_keys(file_id,email,wrapped_key,wrap_nonce,ephemeral_pub)
           VALUES(?,?,?,?,?)""",
        (file_id, g.email, d["wrapped_key"], d["wrap_nonce"], d["ephemeral_pub"])
    )
    db.commit()
    return jsonify({"fileId": file_id, "version": 1}), 201
@app.route("/api/files/<file_id>", methods=["GET"])
@require_auth
def get_file(file_id):
    db = get_db()
    wk = db.execute(
        "SELECT wrapped_key, wrap_nonce, ephemeral_pub, permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not wk: return jsonify({"error": "Access denied"}), 403
    
    # User must have at least one permission (read or modify)
    # This allows modify-only users to get metadata for updating
    perms = wk["permissions"].split(",") if wk["permissions"] else []
    if len(perms) == 0:
        return jsonify({"error": "Access denied - no permissions"}), 403
    
    row = db.execute(
        """SELECT file_id,owner,version,last_modified_by,filename_nonce,filename_enc,
           content_nonce,content_enc,content_hash,content_sig,uploaded_at,updated_at
           FROM files WHERE file_id=?""", (file_id,)
    ).fetchone()
    if not row: return jsonify({"error": "Not found"}), 404
    
    return jsonify({
        **dict(row),
        "wrapped_key": wk["wrapped_key"],
        "wrap_nonce": wk["wrap_nonce"],
        "ephemeral_pub": wk["ephemeral_pub"],
        "permissions": wk["permissions"]
    }), 200
@app.route("/api/files/<file_id>", methods=["DELETE"])

@app.route("/api/files/<file_id>/download", methods=["GET"])
@require_auth
def download_file(file_id):
    """Download file - requires READ permission"""
    db = get_db()
    wk = db.execute(
        "SELECT wrapped_key, wrap_nonce, ephemeral_pub, permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not wk: return jsonify({"error": "Access denied"}), 403
    
    # ENFORCE: Must have READ permission to download
    perms = wk["permissions"].split(",") if wk["permissions"] else []
    if "read" not in perms:
        return jsonify({"error": "Access denied - you do not have read permission"}), 403
    
    row = db.execute(
        """SELECT file_id,owner,version,last_modified_by,filename_nonce,filename_enc,
           content_nonce,content_enc,content_hash,content_sig,uploaded_at,updated_at
           FROM files WHERE file_id=?""", (file_id,)
    ).fetchone()
    if not row: return jsonify({"error": "Not found"}), 404
    
    return jsonify({
        **dict(row),
        "wrapped_key": wk["wrapped_key"],
        "wrap_nonce": wk["wrap_nonce"],
        "ephemeral_pub": wk["ephemeral_pub"],
        "permissions": wk["permissions"]
    }), 200

@app.route("/api/files/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    db = get_db()
    row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not row: return jsonify({"error": "Not found"}), 404
    if row["owner"] != g.email: return jsonify({"error": "Owner only"}), 403
    db.execute("DELETE FROM file_keys WHERE file_id=?", (file_id,))
    db.execute("DELETE FROM files WHERE file_id=?", (file_id,))
    db.execute("DELETE FROM acl_log WHERE file_id=?", (file_id,))
    db.commit()
    return jsonify({"message": "Deleted"}), 200

@app.route("/api/files/<file_id>", methods=["PUT"])
@require_auth
def update_file(file_id):
    """Update/modify file - requires access (not just owner)"""
    d = request.get_json(force=True)
    
    # Check required fields
    for f in ["filename_nonce","filename_enc","content_nonce","content_enc",
              "contentHash","contentSig"]:
        if not d.get(f): return jsonify({"error": f"Missing: {f}"}), 400
    
    db = get_db()
    
    # Check if file exists
    file_row = db.execute("SELECT owner, version FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row: return jsonify({"error": "File not found"}), 404
    
    # Check if user has MODIFY permission
    access = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not access: 
        return jsonify({"error": "Access denied - you do not have access to this file"}), 403
    
    # Check if user has modify permission
    perms = access["permissions"].split(",") if access["permissions"] else []
    if "modify" not in perms:
        return jsonify({"error": "Access denied - you only have read permission"}), 403
    # Check if user has MODIFY permission
    access = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not access: 
        return jsonify({"error": "Access denied - you do not have access to this file"}), 403
    
    # Check if user has modify permission
    perms = access["permissions"].split(",") if access["permissions"] else []
    if "modify" not in perms:
        return jsonify({"error": "Access denied - you only have read permission"}), 403
    # Check if user has MODIFY permission
    access = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not access: 
        return jsonify({"error": "Access denied - you do not have access to this file"}), 403
    
    # Check if user has modify permission
    perms = access["permissions"].split(",") if access["permissions"] else []
    if "modify" not in perms:
        return jsonify({"error": "Access denied - you only have read permission"}), 403
    # Check if user has MODIFY permission
    access = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not access: 
        return jsonify({"error": "Access denied - you do not have access to this file"}), 403
    
    # Check if user has modify permission
    perms = access["permissions"].split(",") if access["permissions"] else []
    if "modify" not in perms:
        return jsonify({"error": "Access denied - you only have read permission"}), 403
    # Check if user has MODIFY permission
    access = db.execute(
        "SELECT permissions FROM file_keys WHERE file_id=? AND email=?",
        (file_id, g.email)
    ).fetchone()
    if not access: 
        return jsonify({"error": "Access denied - you do not have access to this file"}), 403
    
    # Check if user has modify permission
    perms = access["permissions"].split(",") if access["permissions"] else []
    if "modify" not in perms:
        return jsonify({"error": "Access denied - you only have read permission"}), 403
    if not access: return jsonify({"error": "Access denied - no modify permission"}), 403
    
    # Update file content and increment version
    new_version = file_row["version"] + 1
    now = time.time()
    
    db.execute(
        """UPDATE files 
           SET filename_nonce=?, filename_enc=?, content_nonce=?, content_enc=?,
               content_hash=?, content_sig=?, version=?, updated_at=?, last_modified_by=?
           WHERE file_id=?""",
        (d["filename_nonce"], d["filename_enc"],
         d["content_nonce"], d["content_enc"],
         d["contentHash"], d["contentSig"],
         new_version, now, g.email, file_id)
    )
    
    # Log the modification in ACL log
    log_id = _random_token(16)
    
    # Sign the modification
    if d.get("modifySig"):
        db.execute(
            """INSERT INTO acl_log(log_id,file_id,action,target_user,performed_by,acl_sig,timestamp)
               VALUES(?,?,?,?,?,?,?)""",
            (log_id, file_id, "modify", g.email, g.email, d["modifySig"], now)
        )
    
    db.commit()
    
    return jsonify({
        "message": "File updated",
        "fileId": file_id,
        "version": new_version
    }), 200
# ACL
# ════════════════════════════════════════════════════════════

@app.route("/api/files/<file_id>/access", methods=["GET"])
@require_auth
def get_acl(file_id):
    db = get_db()
    file_row = db.execute("SELECT owner FROM files WHERE file_id=?", (file_id,)).fetchone()
    if not file_row: return jsonify({"error": "Not found"}), 404
    
    # Get users with their permissions
    users_rows = db.execute(
        "SELECT email, permissions FROM file_keys WHERE file_id=?", (file_id,)
    ).fetchall()
    
    users = []
    for row in users_rows:
        perms = row["permissions"].split(",") if row["permissions"] else ["read", "modify"]
        users.append({
            "email": row["email"],
            "permissions": perms
        })
    
    # Sort users: owner first, then others alphabetically
    owner_email = file_row["owner"]
    users.sort(key=lambda u: (u["email"] != owner_email, u["email"]))
    
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
    
    # Get permissions (default to both)
    permissions = d.get("permissions", ["read", "modify"])
    if not permissions or len(permissions) == 0:
        return jsonify({"error": "At least one permission required"}), 400
    
    # Validate permissions
    valid_perms = ["read", "modify"]
    for p in permissions:
        if p not in valid_perms:
            return jsonify({"error": f"Invalid permission: {p}"}), 400
    
    # Convert to comma-separated string for storage
    perms_str = ",".join(sorted(permissions))
    
    user_exists = db.execute("SELECT 1 FROM users WHERE email=?", (target,)).fetchone()
    if not user_exists: return jsonify({"error": "User not found"}), 404
    
    db.execute(
        """INSERT OR REPLACE INTO file_keys(file_id,email,wrapped_key,wrap_nonce,ephemeral_pub,permissions)
           VALUES(?,?,?,?,?,?)""",
        (file_id, target, d["wrappedKey"], d["wrapNonce"], d["ephemeralPub"], perms_str)
    )
    
    log_id = _random_token(16)
    db.execute(
        """INSERT INTO acl_log(log_id,file_id,action,target_user,performed_by,acl_sig,timestamp)
           VALUES(?,?,?,?,?,?,?)""",
        (log_id, file_id, "grant", target, g.email, d["aclSig"], time.time())
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
    
    db.execute("DELETE FROM file_keys WHERE file_id=? AND email=?", (file_id, target_email))
    
    log_id = _random_token(16)
    db.execute(
        """INSERT INTO acl_log(log_id,file_id,action,target_user,performed_by,acl_sig,timestamp)
           VALUES(?,?,?,?,?,?,?)""",
        (log_id, file_id, "revoke", target_email, g.email, d["aclSig"], time.time())
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
    if not permissions or len(permissions) == 0:
        return jsonify({"error": "At least one permission required"}), 400
    
    # Validate permissions
    valid_perms = ["read", "modify"]
    for p in permissions:
        if p not in valid_perms:
            return jsonify({"error": f"Invalid permission: {p}"}), 400
    
    # Convert to comma-separated string
    perms_str = ",".join(sorted(permissions))
    
    # Check if user has access
    access = db.execute(
        "SELECT 1 FROM file_keys WHERE file_id=? AND email=?",
        (file_id, target_email)
    ).fetchone()
    if not access:
        return jsonify({"error": "User does not have access to this file"}), 404
    
    # Update permissions
    db.execute(
        "UPDATE file_keys SET permissions=? WHERE file_id=? AND email=?",
        (perms_str, file_id, target_email)
    )
    
    # Log the update
    log_id = _random_token(16)
    db.execute(
        """INSERT INTO acl_log(log_id,file_id,action,target_user,performed_by,acl_sig,timestamp)
           VALUES(?,?,?,?,?,?,?)""",
        (log_id, file_id, "update_permissions", target_email, g.email, d.get("updateSig", ""), time.time())
    )
    db.commit()
    
    return jsonify({"message": "Permissions updated", "permissions": permissions}), 200
if __name__ == "__main__":
    init_db()
    print("[v3.0] SecVault v3.0")
    print("[v3.0] http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
