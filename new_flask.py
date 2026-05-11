# ---------------------------------------------------------------------------- #
#  SnapHire – Photography Booking & Portfolio Platform                        #
#  SECURITY-HARDENED VERSION                                                   #
#                                                                              #
#  New dependencies (add to requirements.txt):                                 #
#    bcrypt>=4.0.0                                                              #
#    flask-limiter>=3.5.0                                                       #
#                                                                              #
#  TEMPLATE CHANGE REQUIRED – add to every HTML <form>:                        #
#    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">        #
#  For AJAX POST calls add header:  X-CSRF-Token: {{ csrf_token() }}           #
# ---------------------------------------------------------------------------- #

from flask import (Flask, render_template, request, redirect,
                   session, g, jsonify, flash, abort)
import mysql.connector
from mysql.connector import Error
import cloudinary
import cloudinary.uploader
import cloudinary.api
import hashlib
import hmac
import uuid
import secrets
import re
import os
import logging
from datetime import datetime, timedelta
from time import time
from functools import wraps
from werkzeug.utils import secure_filename

import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# =============================================================================
#  LOGGING  – structured security log; never log passwords
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("snaphire")

app = Flask(__name__)

# =============================================================================
#  SECURITY: Secret Key & Session Cookie Configuration
# =============================================================================
_secret = os.getenv("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(64)
    log.warning("SECRET_KEY env var not set – using random key (local dev only).")
elif len(_secret) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters.")

app.secret_key = _secret

ON_RENDER = os.getenv("DB_HOST") is not None
SESSION_LIFETIME_HOURS = int(os.getenv("SESSION_LIFETIME_HOURS", "24"))

# Maximum upload size – 200 MB for videos; raise 413 if exceeded
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=ON_RENDER,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_LIFETIME_HOURS),
    SESSION_COOKIE_NAME='__Host-sn' if ON_RENDER else 'sn',
    # Prevent browsers from MIME-sniffing (set via after_request too)
    WTF_CSRF_ENABLED=False,   # We use our own CSRF; disable WTF if present
)

# =============================================================================
#  RATE LIMITER
# =============================================================================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri="memory://",       # swap for "redis://localhost" in production
)

# =============================================================================
#  SECURITY HEADERS – applied to every response
# =============================================================================
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]       = "geolocation=(), microphone=(), camera=()"
    if ON_RENDER:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # Tight CSP – updated to allow FontAwesome and other CDN resources
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://code.jquery.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://res.cloudinary.com; "
        "media-src 'self' https://res.cloudinary.com; "
        "connect-src 'self';"
    )
    return response

# =============================================================================
#  CSRF PROTECTION
# =============================================================================
# Every response gets a signed CSRF token stored in the session.
# Every state-changing request (POST/PUT/DELETE) must echo it back.
# Add to every HTML <form>:
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# For AJAX: set header  X-CSRF-Token: <token>
# =============================================================================

def _get_csrf_token() -> str:
    """Return (and lazily create) the per-session CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

# Make csrf_token() callable inside Jinja2 templates
app.jinja_env.globals["csrf_token"] = _get_csrf_token


def csrf_protect(f):
    """Decorator: reject POST/PUT/DELETE requests whose CSRF token doesn't match."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            submitted = (
                request.form.get("csrf_token")
                or request.headers.get("X-CSRF-Token")
            )
            stored = session.get("csrf_token")
            # hmac.compare_digest prevents timing-oracle attacks
            if not submitted or not stored or not hmac.compare_digest(submitted, stored):
                log.warning("CSRF check failed | ip=%s path=%s", request.remote_addr, request.path)
                abort(403)
        return f(*args, **kwargs)
    return decorated

# =============================================================================
#  Cloudinary Configuration
# =============================================================================
cloudinary.config(cloudinary_url=os.getenv("CLOUDINARY_URL"))

# =============================================================================
#  Local Upload Folders (fallback when Cloudinary is unavailable)
# =============================================================================
UPLOAD_FOLDER = "static/uploads/videos"
POSTER_FOLDER = "static/uploads/posters"

ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "ogg", "mov"}
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

# Magic-byte signatures for allowed image types
_IMAGE_MAGIC: list[tuple[bytes, bytes | None]] = [
    (b"\xff\xd8\xff", None),              # JPEG
    (b"\x89PNG\r\n\x1a\n", None),         # PNG
    (b"RIFF", b"WEBP"),                   # WebP  (bytes 0-3 = RIFF, 8-11 = WEBP)
    (b"GIF87a", None),                    # GIF87
    (b"GIF89a", None),                    # GIF89
]

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["POSTER_FOLDER"] = POSTER_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(POSTER_FOLDER, exist_ok=True)

# =============================================================================
#  INPUT VALIDATION HELPERS
# =============================================================================
_EMAIL_RE    = re.compile(r'^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]{2,}$')
_MOBILE_RE   = re.compile(r'^\+?[0-9\s\-]{7,15}$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
_NAME_RE     = re.compile(r'^[a-zA-Z\s\'\-]{1,50}$')

VALID_GENDERS = {"male", "female", "other"}
VALID_ORDER_STATUSES = {"Pending", "Confirmed", "Processing", "Completed", "Cancelled", "Refunded"}
VALID_PHOT_STATUSES  = {"active", "inactive", "suspended"}


def _v_email(v: str) -> bool:
    return bool(v) and bool(_EMAIL_RE.match(v.strip())) and len(v) <= 120


def _v_mobile(v: str) -> bool:
    return bool(v) and bool(_MOBILE_RE.match(v.strip()))


def _v_username(v: str) -> bool:
    return bool(v) and bool(_USERNAME_RE.match(v)) and v.lower() != "admin"


def _v_name(v: str) -> bool:
    return bool(v) and bool(_NAME_RE.match(v.strip()))


def _v_password(v: str) -> bool:
    """Minimum 8 chars; at least one letter and one digit."""
    return (
        bool(v)
        and len(v) >= 8
        and len(v) <= 128
        and any(c.isalpha() for c in v)
        and any(c.isdigit() for c in v)
    )


def _safe_str(v, max_len: int = 255) -> str:
    """Strip and truncate a string; return empty string if None."""
    return (v or "").strip()[:max_len]


# =============================================================================
#  FILE VALIDATION & UPLOAD HELPERS
# =============================================================================
def _check_image_magic(file_storage) -> bool:
    """Read the first 12 bytes and verify the file is a real image."""
    header = file_storage.stream.read(12)
    file_storage.stream.seek(0)     # rewind for later use
    for sig, extra in _IMAGE_MAGIC:
        if header.startswith(sig):
            if extra is None:
                return True
            # WebP: RIFF????WEBP
            if len(header) >= 12 and header[8:12] == extra:
                return True
    return False


def allowed_video_file(filename: str) -> bool:
    return ("." in filename
            and filename.rsplit(".", 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS)


def allowed_image_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS


def upload_to_cloudinary(file, folder="videos", resource_type="video"):
    """Upload a file to Cloudinary. Returns the secure URL or None on failure."""
    try:
        result = cloudinary.uploader.upload(
            file,
            folder=folder,
            resource_type=resource_type,
            use_filename=True,
            unique_filename=True,
        )
        return result["secure_url"]
    except Exception as e:
        log.error("Cloudinary upload error: %s", e)
        return None


# =============================================================================
#  Database Configuration
# =============================================================================
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT")

if not all([DB_HOST, DB_NAME, DB_USER, DB_PASS]):
    log.warning("Cloud DB vars not set – using localhost (local dev only).")
    DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_PORT = "localhost", "sumedh", "root", "sumedh2004", 3306
    ON_RENDER = False
else:
    DB_PORT = int(DB_PORT) if DB_PORT else 3306
    log.info("Cloud DB: %s:%s | %s", DB_HOST, DB_PORT, DB_NAME)


# =============================================================================
#  PASSWORD HASHING  – bcrypt with transparent SHA-256 migration
# =============================================================================
def hash_password(plain: str) -> str:
    """Hash with bcrypt (work factor 12). Always use for new/updated passwords."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, stored: str) -> bool:
    """
    Verify plain against stored hash.
    Handles both bcrypt (new) and legacy 64-char SHA-256 (old) hashes.
    Uses constant-time comparison in all branches.
    """
    if not plain or not stored:
        return False
    try:
        if stored.startswith(("$2b$", "$2a$", "$2y$")):
            return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
        # Legacy SHA-256
        if len(stored) == 64:
            expected = hashlib.sha256(plain.encode()).hexdigest()
            return hmac.compare_digest(expected, stored)
    except Exception:
        pass
    return False


def _maybe_upgrade_hash(user_id: int, plain: str, stored: str):
    """
    If the stored hash is legacy SHA-256, transparently upgrade it to bcrypt
    after a successful login.  This is called once per user; after the upgrade
    all future logins use bcrypt.
    """
    if stored.startswith(("$2b$", "$2a$", "$2y$")):
        return  # already bcrypt – nothing to do
    new_hash = hash_password(plain)
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_hash, user_id))
        db.commit()
        log.info("Upgraded password hash for user_id=%s", user_id)
    except Exception as e:
        log.error("Hash upgrade failed: %s", e)
        db.rollback()
    finally:
        cursor.close()


# =============================================================================
#  Database Connection with Retry Logic
# =============================================================================
def get_db():
    if "db" not in g:
        cfg = {
            "host": DB_HOST, "user": DB_USER, "password": DB_PASS,
            "database": DB_NAME, "port": DB_PORT,
            "autocommit": False, "use_pure": True, "connection_timeout": 30,
        }
        if ON_RENDER:
            cfg["ssl_ca"] = "/etc/ssl/certs/ca-certificates.crt"
        for attempt in range(3):
            try:
                g.db = mysql.connector.connect(**cfg)
                break
            except Error as e:
                log.error("DB connect attempt %d failed: %s", attempt + 1, e)
                if attempt == 2:
                    return None
                import time as _t; _t.sleep(2)
            except Exception as e:
                log.error("Unexpected DB error: %s", e)
                return None
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None and db.is_connected():
        db.close()


# =============================================================================
#  SERVER-SIDE SESSION HELPERS
# =============================================================================
def _generate_token() -> str:
    return secrets.token_hex(48)    # 384 bits


def _create_db_session(user_id: int, role: str = "user") -> str | None:
    db = get_db()
    if not db:
        return None
    token      = _generate_token()
    expires_at = datetime.now() + timedelta(hours=SESSION_LIFETIME_HOURS)
    ip = (request.remote_addr or "unknown")[:45]
    ua = (request.user_agent.string or "")[:512]
    cursor = db.cursor()
    try:
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id=%s AND role=%s AND expires_at < NOW()",
            (user_id, role),
        )
        cursor.execute(
            """INSERT INTO user_sessions
               (user_id, role, session_token, expires_at, ip_address, user_agent, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
            (user_id, role, token, expires_at, ip, ua),
        )
        db.commit()
        return token
    except Exception as e:
        log.error("Create session error: %s", e)
        db.rollback()
        return None
    finally:
        cursor.close()


def _validate_db_session(token: str, role: str = "user") -> bool:
    if not token:
        return False
    db = get_db()
    if not db:
        return False
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM user_sessions WHERE session_token=%s AND role=%s AND expires_at > NOW()",
            (token, role),
        )
        return cursor.fetchone() is not None
    except Exception as e:
        log.error("Validate session error: %s", e)
        return False
    finally:
        cursor.close()


def _destroy_db_session(token: str, role: str = "user"):
    if not token:
        return
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute(
            "DELETE FROM user_sessions WHERE session_token=%s AND role=%s",
            (token, role),
        )
        db.commit()
    except Exception as e:
        log.error("Destroy session error: %s", e)
        db.rollback()
    finally:
        cursor.close()


def _destroy_all_user_sessions(user_id: int, role: str = "user"):
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute(
            "DELETE FROM user_sessions WHERE user_id=%s AND role=%s",
            (user_id, role),
        )
        db.commit()
    except Exception as e:
        log.error("Destroy all sessions error: %s", e)
        db.rollback()
    finally:
        cursor.close()


# =============================================================================
#  ACCESS-CONTROL DECORATORS
# =============================================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        token   = session.get("session_token")
        if not user_id or not token:
            flash("Please login to access this page.", "error")
            return redirect("/")
        if not _validate_db_session(token, role="user"):
            session.clear()
            flash("Your session has expired. Please login again.", "error")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get("admin_id")
        token    = session.get("admin_session_token")
        if not admin_id or not token:
            flash("Please login as admin.", "error")
            return redirect("/admin/login")
        if not _validate_db_session(token, role="admin"):
            session.clear()
            flash("Your admin session has expired.", "error")
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated


# =============================================================================
#  Startup helpers – create tables / seed default admin
# =============================================================================
def create_admin_user():
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE role = 'admin'")
        if not cursor.fetchone():
            cursor.execute(
                """INSERT INTO users
                   (first_name, last_name, email, mobile, gender, username, password, role, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                ("Admin", "User", "admin@snaphire.com", "0000000000", "other",
                 "admin", hash_password("admin123"), "admin", datetime.now()),
            )
            db.commit()
            log.info("Default admin user created. Change the password immediately!")
    except Exception as e:
        log.error("Admin creation error: %s", e)
    finally:
        cursor.close()


def create_video_tables():
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS videos (
                id INT PRIMARY KEY AUTO_INCREMENT,
                photographer_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                duration_seconds DECIMAL(5,2),
                poster_image_url VARCHAR(500),
                width SMALLINT,
                height SMALLINT,
                is_short_loop BOOLEAN DEFAULT FALSE,
                sort_order INT DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (photographer_id) REFERENCES photographers(id) ON DELETE CASCADE,
                INDEX idx_photographer (photographer_id),
                INDEX idx_active_order (is_active, sort_order)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS video_files (
                id INT PRIMARY KEY AUTO_INCREMENT,
                video_id INT NOT NULL,
                format VARCHAR(20) NOT NULL,
                file_url VARCHAR(500) NOT NULL,
                file_size_bytes BIGINT,
                bitrate INT,
                is_default BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
                UNIQUE KEY unique_video_format (video_id, format),
                INDEX idx_video (video_id)
            )
        """)
        db.commit()
        log.info("Video tables created/verified.")
    except Exception as e:
        log.error("Video tables creation error: %s", e)
    finally:
        cursor.close()


def create_sessions_table():
    db = get_db()
    if not db:
        return
    cursor = db.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id            INT PRIMARY KEY AUTO_INCREMENT,
                user_id       INT NOT NULL,
                role          ENUM('user','admin') NOT NULL DEFAULT 'user',
                session_token VARCHAR(128) NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at    TIMESTAMP NOT NULL,
                ip_address    VARCHAR(45),
                user_agent    TEXT,
                UNIQUE KEY uq_token (session_token),
                INDEX idx_user_role (user_id, role),
                INDEX idx_expires  (expires_at)
            )
        """)
        db.commit()
        log.info("user_sessions table created/verified.")
    except Exception as e:
        log.error("Sessions table creation error: %s", e)
    finally:
        cursor.close()


# =============================================================================
#  ERROR HANDLERS  – never expose stack traces to the browser
# =============================================================================
@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message="Bad request."), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Maximum upload size is 200 MB.", "error")
    return redirect(request.referrer or "/"), 413

@app.errorhandler(429)
def too_many(e):
    return render_template("error.html", code=429,
                           message="Too many requests. Please slow down."), 429

@app.errorhandler(500)
def server_error(e):
    log.error("500 error: %s", e)
    return render_template("error.html", code=500,
                           message="An internal error occurred."), 500


# =============================================================================
#  ROUTES – Public & Authentication
# =============================================================================

# ---------- Admin Login ----------
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@csrf_protect
def admin_login():
    if request.method == "POST":
        username = _safe_str(request.form.get("username", ""), 30)
        password = request.form.get("password", "")

        db = get_db()
        if not db:
            flash("System error. Please try again.", "error")
            return render_template("admin_login.html")

        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT * FROM users WHERE username=%s AND role='admin'",
                (username,),
            )
            admin = cursor.fetchone()
        except Exception as e:
            log.error("Admin login DB error: %s", e)
            admin = None
        finally:
            cursor.close()

        # Always verify (even if admin is None) to prevent timing oracle
        if admin and verify_password(password, admin["password"]):
            _maybe_upgrade_hash(admin["id"], password, admin["password"])
            session.clear()
            token = _create_db_session(admin["id"], role="admin")
            if not token:
                flash("Session creation failed. Try again.", "error")
                return render_template("admin_login.html")
            session["admin_id"]            = admin["id"]
            session["admin_username"]      = admin["username"]
            session["admin_session_token"] = token
            session.permanent = True
            log.info("Admin login: user_id=%s ip=%s", admin["id"], request.remote_addr)
            flash("Welcome back, Admin!", "success")
            return redirect("/admin/dashboard")

        # Generic error – don't reveal whether username or password was wrong
        log.warning("Failed admin login attempt: username=%s ip=%s", username, request.remote_addr)
        flash("Invalid credentials.", "error")
        return render_template("admin_login.html")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    token = session.get("admin_session_token")
    if token:
        _destroy_db_session(token, role="admin")
    session.clear()
    flash("Logged out.", "success")
    return redirect("/admin/login")


# ---------- User Signup ----------
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
@csrf_protect
def signup():
    if request.method == "POST":
        fn       = _safe_str(request.form.get("first_name", ""), 50)
        ln       = _safe_str(request.form.get("last_name", ""), 50)
        email    = _safe_str(request.form.get("email", ""), 120)
        mobile   = _safe_str(request.form.get("mobile", ""), 20)
        gender   = _safe_str(request.form.get("gender", ""), 10).lower()
        username = _safe_str(request.form.get("username", ""), 30)
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # ── Validation ──────────────────────────────────────────────────────
        errors = []
        if not _v_name(fn):
            errors.append("Invalid first name.")
        if not _v_name(ln):
            errors.append("Invalid last name.")
        if not _v_email(email):
            errors.append("Invalid email address.")
        if not _v_mobile(mobile):
            errors.append("Invalid mobile number.")
        if gender not in VALID_GENDERS:
            errors.append("Invalid gender selection.")
        if not _v_username(username):
            errors.append("Username must be 3-30 alphanumeric/underscore characters and cannot be 'admin'.")
        if not _v_password(password):
            errors.append("Password must be at least 8 characters with at least one letter and one digit.")
        if password != confirm:
            errors.append("Passwords do not match.")

        for err in errors:
            flash(err, "error")
        if errors:
            return redirect("/signup")

        db = get_db()
        if not db:
            flash("Database error. Please try again.", "error")
            return redirect("/signup")
        cursor = db.cursor()
        try:
            cursor.execute(
                "SELECT id FROM users WHERE username=%s OR email=%s",
                (username, email),
            )
            if cursor.fetchone():
                flash("Username or email already in use.", "error")
                return redirect("/signup")
            cursor.execute(
                """INSERT INTO users
                   (first_name, last_name, email, mobile, gender, username, password, role)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,'user')""",
                (fn, ln, email, mobile, gender, username, hash_password(password)),
            )
            db.commit()
            flash("Signup successful! Please login.", "success")
            return redirect("/")
        except Exception as e:
            db.rollback()
            log.error("Signup error: %s", e)
            flash("Signup failed. Please try again.", "error")
            return redirect("/signup")
        finally:
            cursor.close()
    return render_template("signup.html")


# ---------- User Login ----------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
@csrf_protect
def login():
    if request.method == "POST":
        username = _safe_str(request.form.get("username", ""), 30)
        password = request.form.get("password", "")

        db = get_db()
        if not db:
            flash("System error. Please try again.", "error")
            return render_template("login.html")

        cursor = db.cursor(dictionary=True)
        try:
            # Fetch by username only – compare password in Python (not SQL)
            cursor.execute(
                "SELECT * FROM users WHERE username=%s",
                (username,),
            )
            user = cursor.fetchone()
        except Exception as e:
            log.error("Login DB error: %s", e)
            user = None
        finally:
            cursor.close()

        # Constant-time path: always call verify_password to prevent timing oracle
        if user and verify_password(password, user["password"]):
            _maybe_upgrade_hash(user["id"], password, user["password"])
            _destroy_all_user_sessions(user["id"], role="user")
            session.clear()
            token = _create_db_session(user["id"], role="user")
            if not token:
                flash("Session creation failed. Please try again.", "error")
                return render_template("login.html")
            session["user_id"]       = user["id"]
            session["username"]      = user["username"]
            session["user_name"]     = f"{user['first_name']} {user['last_name']}"
            session["session_token"] = token
            session.permanent = True
            log.info("User login: user_id=%s ip=%s", user["id"], request.remote_addr)
            flash(f"Welcome back, {user['first_name']}!", "success")
            return redirect("/home")

        log.warning("Failed login: username=%s ip=%s", username, request.remote_addr)
        flash("Invalid username or password.", "error")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    token = session.get("session_token")
    if token:
        _destroy_db_session(token, role="user")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/")


# ---------- Home Page ----------
@app.route("/home")
@login_required
def home():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM packages")
        packages = cursor.fetchall()
        cursor.execute("""
            SELECT p.package_name,
                   CONCAT(u.first_name,' ',u.last_name) AS user_full_name,
                   r.rating, r.comment, r.created_at
            FROM package_reviews r
            JOIN users     u ON r.user_id    = u.id
            JOIN packages  p ON r.package_id = p.package_id
            ORDER BY r.created_at DESC LIMIT 10
        """)
        package_reviews = cursor.fetchall()
        cursor.execute(
            "SELECT order_id, total_price, status, created_at FROM orders "
            "WHERE user_id=%s ORDER BY created_at DESC LIMIT 5",
            (session["user_id"],),
        )
        orders = cursor.fetchall()
    except Exception as e:
        log.error("Home error: %s", e)
        packages = package_reviews = orders = []
    finally:
        cursor.close()
    return render_template("home.html", packages=packages,
                           package_reviews=package_reviews, orders=orders)


# =============================================================================
#  PORTFOLIO (IMAGES)
# =============================================================================
@app.route("/api/portfolio")
def get_portfolio():
    db = get_db()
    if not db:
        return jsonify([])
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SHOW TABLES LIKE 'portfolio_images'")
        if not cursor.fetchone():
            return jsonify([])
        cursor.execute("""
            SELECT p.id AS photographer_id, p.first_name, p.last_name,
                   p.profile_image, p.rating,
                   pi.id AS image_id, pi.image_url, pi.location,
                   pi.shoot_date, pi.description
            FROM photographers p
            JOIN portfolio_images pi ON p.id = pi.photographer_id
            WHERE p.status = 'active'
            ORDER BY p.id, pi.shoot_date DESC
        """)
        rows = cursor.fetchall()
        portfolio: dict = {}
        for row in rows:
            pid = row["photographer_id"]
            if pid not in portfolio:
                portfolio[pid] = {
                    "photographer_id": pid,
                    "name": f"{row['first_name']} {row['last_name']}",
                    "profile_image": row["profile_image"],
                    "rating": row["rating"],
                    "images": [],
                }
            portfolio[pid]["images"].append({
                "id": row["image_id"],
                "url": row["image_url"],
                "location": row["location"],
                "shoot_date": row["shoot_date"].strftime("%Y-%m-%d") if row["shoot_date"] else None,
                "description": row["description"],
            })
        return jsonify(list(portfolio.values()))
    except Exception as e:
        log.error("Portfolio API error: %s", e)
        return jsonify([])
    finally:
        cursor.close()


@app.route("/portfolio")
def portfolio_page():
    return render_template("portfolio.html")


@app.route("/admin/portfolio")
@admin_required
def admin_portfolio():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT p.*,
                   COUNT(DISTINCT pi.id) AS image_count,
                   COUNT(DISTINCT v.id)  AS video_count
            FROM photographers p
            LEFT JOIN portfolio_images pi ON p.id = pi.photographer_id
            LEFT JOIN videos           v  ON p.id = v.photographer_id
            GROUP BY p.id
            ORDER BY p.id DESC
        """)
        photographers = cursor.fetchall()
    except Exception as e:
        log.error("Admin Portfolio error: %s", e)
        photographers = []
    finally:
        cursor.close()
    return render_template("admin_portfolio.html", photographers=photographers)


@app.route("/admin/portfolio/images/<int:photographer_id>")
@admin_required
def admin_portfolio_images(photographer_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name FROM photographers WHERE id=%s",
                       (photographer_id,))
        photographer = cursor.fetchone()
        if not photographer:
            flash("Photographer not found.", "error")
            return redirect("/admin/portfolio")
        cursor.execute(
            "SELECT * FROM portfolio_images WHERE photographer_id=%s ORDER BY shoot_date DESC",
            (photographer_id,),
        )
        images = cursor.fetchall()
    finally:
        cursor.close()
    return render_template("admin_portfolio_images.html",
                           photographer=photographer, images=images)


@app.route("/admin/portfolio/add/<int:photographer_id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_add_portfolio_image(photographer_id):
    db = get_db()
    if request.method == "POST":
        image_url   = _safe_str(request.form.get("image_url", ""), 500)
        location    = _safe_str(request.form.get("location", ""), 255)
        shoot_date  = request.form.get("shoot_date") or None
        description = _safe_str(request.form.get("description", ""), 500)

        cursor = db.cursor()
        try:
            cursor.execute(
                """INSERT INTO portfolio_images
                   (photographer_id, image_url, location, shoot_date, description)
                   VALUES (%s,%s,%s,%s,%s)""",
                (photographer_id, image_url, location, shoot_date, description),
            )
            db.commit()
            flash("Image added to portfolio.", "success")
        except Exception as e:
            log.error("Add portfolio image: %s", e)
            db.rollback()
            flash("Error adding image.", "error")
        finally:
            cursor.close()
        return redirect("/admin/portfolio")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name FROM photographers WHERE id=%s",
                       (photographer_id,))
        photographer = cursor.fetchone()
    finally:
        cursor.close()
    if not photographer:
        flash("Photographer not found.", "error")
        return redirect("/admin/portfolio")
    return render_template("admin_add_portfolio_image.html", photographer=photographer)


@app.route("/admin/portfolio/edit/<int:image_id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_edit_portfolio_image(image_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        if request.method == "POST":
            image_url   = _safe_str(request.form.get("image_url", ""), 500)
            location    = _safe_str(request.form.get("location", ""), 255)
            shoot_date  = request.form.get("shoot_date") or None
            description = _safe_str(request.form.get("description", ""), 500)
            cursor.execute(
                """UPDATE portfolio_images
                   SET image_url=%s, location=%s, shoot_date=%s, description=%s
                   WHERE id=%s""",
                (image_url, location, shoot_date, description, image_id),
            )
            db.commit()
            flash("Portfolio image updated.", "success")
            cursor.execute("SELECT photographer_id FROM portfolio_images WHERE id=%s", (image_id,))
            row = cursor.fetchone()
            return redirect(f"/admin/portfolio/images/{row['photographer_id']}" if row else "/admin/portfolio")

        cursor.execute("SELECT * FROM portfolio_images WHERE id=%s", (image_id,))
        image = cursor.fetchone()
        if not image:
            flash("Image not found.", "error")
            return redirect("/admin/portfolio")
        cursor.execute("SELECT id, first_name, last_name FROM photographers WHERE id=%s",
                       (image["photographer_id"],))
        photographer = cursor.fetchone()
    except Exception as e:
        log.error("Edit portfolio image: %s", e)
        db.rollback()
        flash("Error.", "error")
        return redirect("/admin/portfolio")
    finally:
        cursor.close()
    return render_template("admin_edit_portfolio_image.html",
                           image=image, photographer=photographer)


@app.route("/admin/portfolio/delete/<int:image_id>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_portfolio_image(image_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM portfolio_images WHERE id=%s", (image_id,))
        db.commit()
        flash("Image deleted.", "success")
    except Exception as e:
        log.error("Delete portfolio image: %s", e)
        db.rollback()
        flash("Error deleting image.", "error")
    finally:
        cursor.close()
    return redirect("/admin/portfolio")


# =============================================================================
#  VIDEO MANAGEMENT (CLOUDINARY)
# =============================================================================
@app.route("/admin/videos")
@admin_required
def admin_videos():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/admin/dashboard")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT v.*, CONCAT(p.first_name,' ',p.last_name) AS photographer_name
            FROM videos v
            JOIN photographers p ON v.photographer_id = p.id
            ORDER BY v.sort_order ASC, v.created_at DESC
        """)
        videos = cursor.fetchall()
        for video in videos:
            cursor.execute(
                "SELECT format, file_url, is_default FROM video_files WHERE video_id=%s",
                (video["id"],),
            )
            video["formats"] = cursor.fetchall()
    except Exception as e:
        log.error("Admin videos: %s", e)
        videos = []
    finally:
        cursor.close()
    return render_template("admin_videos.html", videos=videos)


def _handle_video_upload(photographer_id, title, description, duration_seconds,
                          is_short_loop, sort_order, poster_file, video_files_list,
                          video_id=None):
    """
    Internal helper: insert/update video + upload files.
    Returns (video_id_or_None, poster_url_or_None).
    """
    db = get_db()
    poster_url = None

    if poster_file and allowed_image_file(poster_file.filename):
        if _check_image_magic(poster_file):
            cloud_url = upload_to_cloudinary(poster_file, folder="posters", resource_type="image")
            if cloud_url:
                poster_url = cloud_url
            else:
                fname     = secure_filename(f"{uuid.uuid4().hex}_{poster_file.filename}")
                fpath     = os.path.join(app.config["POSTER_FOLDER"], fname)
                poster_file.save(fpath)
                poster_url = f"/static/uploads/posters/{fname}"
        else:
            flash("Poster image has an invalid file type.", "error")

    cursor = db.cursor()
    try:
        if video_id is None:
            cursor.execute(
                """INSERT INTO videos
                   (photographer_id, title, description, duration_seconds,
                    poster_image_url, is_short_loop, sort_order)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (photographer_id, title, description, duration_seconds,
                 poster_url, is_short_loop, sort_order),
            )
            video_id = cursor.lastrowid
        else:
            if poster_url:
                cursor.execute(
                    """UPDATE videos SET title=%s, description=%s, duration_seconds=%s,
                       is_short_loop=%s, sort_order=%s, poster_image_url=%s, updated_at=NOW()
                       WHERE id=%s""",
                    (title, description, duration_seconds, is_short_loop,
                     sort_order, poster_url, video_id),
                )
            else:
                cursor.execute(
                    """UPDATE videos SET title=%s, description=%s, duration_seconds=%s,
                       is_short_loop=%s, sort_order=%s, updated_at=NOW()
                       WHERE id=%s""",
                    (title, description, duration_seconds, is_short_loop, sort_order, video_id),
                )

        for idx, vfile in enumerate(video_files_list or []):
            if not vfile or not vfile.filename:
                continue
            if not allowed_video_file(vfile.filename):
                continue
            ext       = vfile.filename.rsplit(".", 1)[1].lower()
            cloud_url = upload_to_cloudinary(vfile, folder="videos", resource_type="video")
            if cloud_url:
                file_url  = cloud_url
                file_size = 0
            else:
                fname     = secure_filename(f"video_{video_id}_{uuid.uuid4().hex}.{ext}")
                fpath     = os.path.join(app.config["UPLOAD_FOLDER"], fname)
                vfile.save(fpath)
                file_url  = f"/static/uploads/videos/{fname}"
                file_size = os.path.getsize(fpath)
            cursor.execute(
                """INSERT INTO video_files
                   (video_id, format, file_url, file_size_bytes, is_default)
                   VALUES (%s,%s,%s,%s,%s)
                   ON DUPLICATE KEY UPDATE file_url=%s, file_size_bytes=%s""",
                (video_id, ext, file_url, file_size, idx == 0, file_url, file_size),
            )

        db.commit()
        return video_id
    except Exception as e:
        db.rollback()
        raise e
    finally:
        cursor.close()


@app.route("/admin/videos/add", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_add_video():
    db = get_db()
    if request.method == "POST":
        try:
            vid = _handle_video_upload(
                photographer_id  = int(request.form.get("photographer_id", 0)),
                title            = _safe_str(request.form.get("title", ""), 255),
                description      = _safe_str(request.form.get("description", ""), 2000),
                duration_seconds = request.form.get("duration_seconds") or None,
                is_short_loop    = 1 if request.form.get("is_short_loop") else 0,
                sort_order       = int(request.form.get("sort_order") or 0),
                poster_file      = request.files.get("poster_image"),
                video_files_list = request.files.getlist("video_files"),
            )
            flash("Video added successfully.", "success")
            return redirect("/admin/videos")
        except Exception as e:
            log.error("Add video: %s", e)
            flash("Error adding video.", "error")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name FROM photographers ORDER BY first_name")
        photographers = cursor.fetchall()
    finally:
        cursor.close()
    return render_template("admin_add_video.html", photographers=photographers)


@app.route("/admin/videos/edit/<int:video_id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_edit_video(video_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        try:
            vf = request.files.get("video_file")
            _handle_video_upload(
                photographer_id  = None,
                title            = _safe_str(request.form.get("title", ""), 255),
                description      = _safe_str(request.form.get("description", ""), 2000),
                duration_seconds = request.form.get("duration_seconds") or None,
                is_short_loop    = 1 if request.form.get("is_short_loop") else 0,
                sort_order       = int(request.form.get("sort_order") or 0),
                poster_file      = request.files.get("poster_image"),
                video_files_list = [vf] if vf and vf.filename else [],
                video_id         = video_id,
            )
            flash("Video updated.", "success")
            return redirect("/admin/videos")
        except Exception as e:
            log.error("Edit video: %s", e)
            flash("Error updating video.", "error")
            return redirect(f"/admin/videos/edit/{video_id}")
        finally:
            cursor.close()

    try:
        cursor.execute("SELECT * FROM videos WHERE id=%s", (video_id,))
        video = cursor.fetchone()
        if not video:
            flash("Video not found.", "error")
            return redirect("/admin/videos")
        cursor.execute("SELECT * FROM video_files WHERE video_id=%s", (video_id,))
        video["formats"] = cursor.fetchall()
        cursor.execute("SELECT id, first_name, last_name FROM photographers ORDER BY first_name")
        photographers = cursor.fetchall()
    except Exception as e:
        log.error("Fetch video: %s", e)
        video = None
        photographers = []
    finally:
        cursor.close()
    return render_template("admin_edit_video.html", video=video, photographers=photographers)


@app.route("/admin/videos/delete_format/<int:file_id>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_video_format(file_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT file_url FROM video_files WHERE id=%s", (file_id,))
        row = cursor.fetchone()
        if row and not row[0].startswith("http"):
            local = row[0].lstrip("/")
            if os.path.exists(local):
                os.remove(local)
        cursor.execute("DELETE FROM video_files WHERE id=%s", (file_id,))
        db.commit()
        flash("Video format deleted.", "success")
    except Exception as e:
        log.error("Delete video format: %s", e)
        db.rollback()
        flash("Error deleting format.", "error")
    finally:
        cursor.close()
    return redirect(request.referrer or "/admin/videos")


@app.route("/admin/videos/delete/<int:video_id>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_video(video_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT photographer_id FROM videos WHERE id=%s", (video_id,))
        row = cursor.fetchone()
        photographer_id = row[0] if row else None

        cursor.execute("SELECT poster_image_url FROM videos WHERE id=%s", (video_id,))
        poster = cursor.fetchone()
        if poster and poster[0] and not poster[0].startswith("http"):
            lp = poster[0].lstrip("/")
            if os.path.exists(lp):
                os.remove(lp)

        cursor.execute("SELECT file_url FROM video_files WHERE video_id=%s", (video_id,))
        for r in cursor.fetchall():
            if not r[0].startswith("http"):
                lp = r[0].lstrip("/")
                if os.path.exists(lp):
                    os.remove(lp)

        cursor.execute("DELETE FROM videos WHERE id=%s", (video_id,))
        db.commit()
        flash("Video deleted.", "success")
        return redirect(f"/admin/photographer_videos/{photographer_id}" if photographer_id else "/admin/videos")
    except Exception as e:
        log.error("Delete video: %s", e)
        db.rollback()
        flash("Error deleting video.", "error")
        return redirect("/admin/videos")
    finally:
        cursor.close()


@app.route("/api/videos")
def get_videos():
    db = get_db()
    if not db:
        return jsonify([])
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT v.*,
                   CONCAT(p.first_name,' ',p.last_name) AS photographer_name,
                   (SELECT file_url FROM video_files
                    WHERE video_id=v.id AND is_default=TRUE LIMIT 1) AS video_url
            FROM videos v
            JOIN photographers p ON v.photographer_id = p.id
            WHERE v.is_active=1
            ORDER BY v.sort_order, v.created_at DESC
        """)
        videos = cursor.fetchall()
    except Exception as e:
        log.error("API videos: %s", e)
        videos = []
    finally:
        cursor.close()
    return jsonify(videos)


# =============================================================================
#  PER-PHOTOGRAPHER VIDEO MANAGEMENT
# =============================================================================
@app.route("/admin/photographer_videos/<int:photographer_id>")
@admin_required
def admin_photographer_videos(photographer_id):
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/admin/photographers")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name FROM photographers WHERE id=%s",
                       (photographer_id,))
        photographer = cursor.fetchone()
        if not photographer:
            flash("Photographer not found.", "error")
            return redirect("/admin/photographers")
        cursor.execute("""
            SELECT v.*,
                   (SELECT GROUP_CONCAT(format)
                    FROM video_files WHERE video_id=v.id) AS formats
            FROM videos v WHERE v.photographer_id=%s
            ORDER BY v.sort_order ASC, v.created_at DESC
        """, (photographer_id,))
        videos = cursor.fetchall()
    except Exception as e:
        log.error("Admin photographer videos: %s", e)
        videos = []
        photographer = None
    finally:
        cursor.close()
    return render_template("admin_photographer_videos.html",
                           photographer=photographer, videos=videos)


@app.route("/admin/photographer_videos/add/<int:photographer_id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_add_photographer_video(photographer_id):
    db = get_db()
    if request.method == "POST":
        try:
            _handle_video_upload(
                photographer_id  = photographer_id,
                title            = _safe_str(request.form.get("title", ""), 255),
                description      = _safe_str(request.form.get("description", ""), 2000),
                duration_seconds = request.form.get("duration_seconds") or None,
                is_short_loop    = 1 if request.form.get("is_short_loop") else 0,
                sort_order       = int(request.form.get("sort_order") or 0),
                poster_file      = request.files.get("poster_image"),
                video_files_list = request.files.getlist("video_files"),
            )
            flash("Video added.", "success")
            return redirect(f"/admin/photographer_videos/{photographer_id}")
        except Exception as e:
            log.error("Add photographer video: %s", e)
            flash("Error adding video.", "error")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, first_name, last_name FROM photographers WHERE id=%s",
                       (photographer_id,))
        photographer = cursor.fetchone()
    finally:
        cursor.close()
    if not photographer:
        flash("Photographer not found.", "error")
        return redirect("/admin/photographers")
    return render_template("admin_add_photographer_video.html", photographer=photographer)


# =============================================================================
#  PHOTOGRAPHER EDITING
# =============================================================================
@app.route("/admin/edit_photographer/<int:id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def edit_photographer(id):
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/admin/photographers")
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        status = _safe_str(request.form.get("status", ""), 20)
        if status not in VALID_PHOT_STATUSES:
            flash("Invalid status value.", "error")
            cursor.close()
            return redirect(f"/admin/edit_photographer/{id}")
        try:
            cursor.execute(
                """UPDATE photographers
                   SET first_name=%s, last_name=%s, email=%s, phone=%s,
                       experience=%s, rating=%s, status=%s, profile_image=%s
                   WHERE id=%s""",
                (
                    _safe_str(request.form.get("first_name", ""), 50),
                    _safe_str(request.form.get("last_name", ""), 50),
                    _safe_str(request.form.get("email", ""), 120),
                    _safe_str(request.form.get("phone", ""), 20),
                    _safe_str(request.form.get("experience", ""), 100),
                    request.form.get("rating") or None,
                    status,
                    _safe_str(request.form.get("profile_image", ""), 500),
                    id,
                ),
            )
            db.commit()
            flash("Photographer updated.", "success")
            return redirect("/admin/photographers")
        except Exception as e:
            log.error("Update photographer: %s", e)
            db.rollback()
            flash("Error updating photographer.", "error")
            return redirect(f"/admin/edit_photographer/{id}")
        finally:
            cursor.close()

    try:
        cursor.execute("SELECT * FROM photographers WHERE id=%s", (id,))
        photographer = cursor.fetchone()
    except Exception as e:
        log.error("Fetch photographer: %s", e)
        photographer = None
    finally:
        cursor.close()
    if not photographer:
        flash("Photographer not found.", "error")
        return redirect("/admin/photographers")
    return render_template("admin_edit_photographer.html", photographer=photographer)


# =============================================================================
#  CART & ORDER ROUTES
# =============================================================================
@app.route("/cart", methods=["GET", "POST"])
@login_required
@csrf_protect
def cart():
    user_id = session["user_id"]
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/home")
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        try:
            for key, value in request.form.items():
                if key.startswith("photographer_") and key[len("photographer_"):].isdigit():
                    cart_item_id    = int(key.split("_")[1])
                    photographer_id = int(value) if value and value.isdigit() else None
                    location        = _safe_str(request.form.get(f"location_{cart_item_id}", ""), 255)
                    scheduled_date  = request.form.get(f"date_{cart_item_id}") or None
                    cursor.execute(
                        """UPDATE user_packages
                           SET photographer_id=%s, location=%s, scheduled_date=%s
                           WHERE id=%s AND user_id=%s""",
                        (photographer_id, location, scheduled_date, cart_item_id, user_id),
                    )
            db.commit()
            flash("Cart updated.", "success")
        except Exception as e:
            log.error("Cart update: %s", e)
            db.rollback()
            flash("Error updating cart.", "error")
        finally:
            cursor.close()
        return redirect("/cart")

    try:
        cursor.execute("""
            SELECT up.*, p.package_name, p.package_price, p.duration,
                   ph.id AS photographer_id,
                   CONCAT(ph.first_name,' ',ph.last_name) AS photographer_name,
                   ph.rating AS photographer_rating
            FROM user_packages up
            JOIN packages p ON up.package_id = p.package_id
            LEFT JOIN photographers ph ON up.photographer_id = ph.id
            WHERE up.user_id=%s
        """, (user_id,))
        cart_items = cursor.fetchall()
        cursor.execute(
            "SELECT id, CONCAT(first_name,' ',last_name) AS name, rating, status "
            "FROM photographers WHERE status='active' ORDER BY rating DESC"
        )
        photographers = cursor.fetchall()
        total = sum(float(i["package_price"]) * int(i["quantity"]) for i in cart_items)
    except Exception as e:
        log.error("Cart fetch: %s", e)
        cart_items = photographers = []
        total = 0
    finally:
        cursor.close()
    return render_template("cart.html", cart_items=cart_items,
                           total=total, photographers=photographers)


@app.route("/add_package/<int:package_id>", methods=["POST"])
@login_required
@csrf_protect
def add_package(package_id):
    db = get_db()
    if not db:
        return jsonify({"status": "error", "message": "Database error"})
    cursor = db.cursor(dictionary=True)
    try:
        # Verify package exists (prevents adding ghost packages)
        cursor.execute("SELECT package_id FROM packages WHERE package_id=%s", (package_id,))
        if not cursor.fetchone():
            return jsonify({"status": "error", "message": "Package not found"}), 404

        cursor.execute(
            "SELECT id FROM user_packages WHERE user_id=%s AND package_id=%s",
            (session["user_id"], package_id),
        )
        if cursor.fetchone():
            cursor.execute(
                "UPDATE user_packages SET quantity=quantity+1 WHERE user_id=%s AND package_id=%s",
                (session["user_id"], package_id),
            )
        else:
            cursor.execute(
                "INSERT INTO user_packages (user_id, package_id, quantity) VALUES (%s,%s,1)",
                (session["user_id"], package_id),
            )
        db.commit()
        return jsonify({"status": "success", "message": "Package added to cart"})
    except Exception as e:
        log.error("Add to cart: %s", e)
        db.rollback()
        return jsonify({"status": "error", "message": "Internal error"}), 500
    finally:
        cursor.close()


@app.route("/remove/<int:id>", methods=["POST"])
@login_required
@csrf_protect
def remove(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT quantity FROM user_packages WHERE id=%s AND user_id=%s",
                       (id, session["user_id"]))
        item = cursor.fetchone()
        if item:
            if item["quantity"] > 1:
                cursor.execute(
                    "UPDATE user_packages SET quantity=quantity-1 WHERE id=%s AND user_id=%s",
                    (id, session["user_id"]),
                )
            else:
                cursor.execute("DELETE FROM user_packages WHERE id=%s AND user_id=%s",
                               (id, session["user_id"]))
        db.commit()
        flash("Item removed.", "success")
    except Exception as e:
        log.error("Remove cart item: %s", e)
        db.rollback()
        flash("Error removing item.", "error")
    finally:
        cursor.close()
    return redirect("/cart")


@app.route("/empty_cart", methods=["POST"])
@login_required
@csrf_protect
def empty_cart():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))
        db.commit()
        flash("Cart emptied.", "success")
    except Exception as e:
        log.error("Empty cart: %s", e)
        db.rollback()
        flash("Error emptying cart.", "error")
    finally:
        cursor.close()
    return redirect("/cart")


@app.route("/update_item/<int:item_id>", methods=["POST"])
@login_required
@csrf_protect
def update_item(item_id):
    db = get_db()
    cursor = db.cursor()
    try:
        photographer_id = request.form.get(f"photographer_{item_id}")
        location        = _safe_str(request.form.get(f"location_{item_id}", ""), 255)
        scheduled_date  = request.form.get(f"date_{item_id}") or None
        photographer_id = int(photographer_id) if photographer_id and photographer_id.isdigit() else None
        cursor.execute(
            """UPDATE user_packages
               SET photographer_id=%s, location=%s, scheduled_date=%s
               WHERE id=%s AND user_id=%s""",
            (photographer_id, location, scheduled_date, item_id, session["user_id"]),
        )
        db.commit()
        flash("Package details updated.", "success")
    except Exception as e:
        log.error("Update cart item: %s", e)
        db.rollback()
        flash("Error updating package details.", "error")
    finally:
        cursor.close()
    return redirect("/cart")


@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
@csrf_protect
def edit_profile():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/home")
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        fn     = _safe_str(request.form.get("first_name", ""), 50)
        ln     = _safe_str(request.form.get("last_name", ""), 50)
        email  = _safe_str(request.form.get("email", ""), 120)
        mobile = _safe_str(request.form.get("mobile", ""), 20)
        gender = _safe_str(request.form.get("gender", ""), 10).lower()

        errors = []
        if not _v_name(fn):      errors.append("Invalid first name.")
        if not _v_name(ln):      errors.append("Invalid last name.")
        if not _v_email(email):  errors.append("Invalid email.")
        if not _v_mobile(mobile): errors.append("Invalid mobile.")
        if gender not in VALID_GENDERS: errors.append("Invalid gender.")
        for e in errors:
            flash(e, "error")
        if errors:
            cursor.close()
            return redirect("/edit-profile")

        try:
            cursor.execute(
                """UPDATE users
                   SET first_name=%s, last_name=%s, email=%s, mobile=%s, gender=%s
                   WHERE id=%s""",
                (fn, ln, email, mobile, gender, session["user_id"]),
            )
            db.commit()
            flash("Profile updated.", "success")
            return redirect("/home")
        except Exception as e:
            log.error("Edit profile: %s", e)
            db.rollback()
            flash("Error updating profile.", "error")
        finally:
            cursor.close()
    else:
        try:
            cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
            user = cursor.fetchone()
        except Exception as e:
            log.error("Fetch profile: %s", e)
            user = None
        finally:
            cursor.close()
        return render_template("edit_profile.html", user=user)


# Static pages
@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/about")
def about():
    return render_template("about-us.html")

@app.route("/get-hired")
def get_hired():
    return render_template("get_hired.html")


# =============================================================================
#  ORDER MANAGEMENT (User)
# =============================================================================
@app.route("/orders")
@login_required
def orders():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/home")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT order_id, total_price, status, created_at, location, scheduled_date "
            "FROM orders WHERE user_id=%s ORDER BY created_at DESC",
            (session["user_id"],),
        )
        orders = cursor.fetchall()
    except Exception as e:
        log.error("Orders: %s", e)
        orders = []
    finally:
        cursor.close()
    return render_template("orders.html", orders=orders)


@app.route("/order_details/<string:order_id>")
@login_required
def order_details(order_id):
    # Sanitise order_id (UUID-like short string)
    order_id = re.sub(r"[^a-zA-Z0-9\-]", "", order_id)[:36]
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/orders")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """SELECT order_id, total_price, location, scheduled_date,
                      payment_method, status, created_at
               FROM orders WHERE order_id=%s AND user_id=%s""",
            (order_id, session["user_id"]),
        )
        order = cursor.fetchone()
        items = subtotal = gst_amount = service_charge = grand_total = 0
        if order:
            cursor.execute(
                """SELECT oi.package_name, oi.price, oi.duration, oi.quantity, oi.location,
                          CONCAT(ph.first_name,' ',ph.last_name) AS photographer_name,
                          ph.rating AS photographer_rating
                   FROM order_items oi
                   LEFT JOIN photographers ph ON oi.photographer_id = ph.id
                   WHERE oi.order_id=%s""",
                (order_id,),
            )
            items          = cursor.fetchall()
            subtotal       = sum(float(i["price"]) * int(i["quantity"]) for i in items)
            gst_amount     = subtotal * 0.18
            service_charge = subtotal * 0.05
            grand_total    = subtotal + gst_amount + service_charge
    except Exception as e:
        log.error("Order details: %s", e)
        order = None; items = []; subtotal = gst_amount = service_charge = grand_total = 0
    finally:
        cursor.close()
    return render_template("order_details.html", order=order, items=items,
                           subtotal=subtotal, gst_amount=gst_amount,
                           service_charge=service_charge, grand_total=grand_total)


# =============================================================================
#  PHOTOGRAPHER APPLICATION
# =============================================================================
@app.route("/photographer/apply", methods=["POST"])
@limiter.limit("3 per hour")
@csrf_protect
def apply_photographer():
    fn    = _safe_str(request.form.get("first_name", ""), 50)
    ln    = _safe_str(request.form.get("last_name", ""), 50)
    email = _safe_str(request.form.get("email", ""), 120)
    phone = _safe_str(request.form.get("phone", ""), 20)
    addr  = _safe_str(request.form.get("address", ""), 300)

    if not (_v_name(fn) and _v_name(ln) and _v_email(email)):
        flash("Invalid application data.", "error")
        return redirect("/get-hired")

    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/get-hired")
    cursor = db.cursor()
    try:
        cursor.execute(
            """INSERT INTO photographers_applications
               (first_name, last_name, email, phone, address, years_exp, months_exp)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (fn, ln, email, phone, addr,
             request.form.get("years", 0),
             request.form.get("months", 0)),
        )
        db.commit()
        flash("Application submitted!", "success")
    except Exception as e:
        log.error("Photographer application: %s", e)
        db.rollback()
        flash("Error submitting application.", "error")
    finally:
        cursor.close()
    return redirect("/photographer/submitted")


@app.route("/photographer/submitted")
def photographer_submitted():
    return render_template("photographer_submitted.html")


# =============================================================================
#  ADMIN ROUTES
# =============================================================================
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/admin/login")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) AS count FROM orders")
        total_orders = cursor.fetchone()["count"]
        cursor.execute("SELECT COALESCE(SUM(total_price),0) AS total FROM orders WHERE status='Confirmed'")
        revenue = cursor.fetchone()["total"] or 0
        cursor.execute("SELECT COUNT(*) AS count FROM users")
        total_users = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) AS count FROM photographers")
        total_photographers = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) AS count FROM videos")
        total_videos = cursor.fetchone()["count"]
        cursor.execute("""
            SELECT o.order_id, o.total_price, o.status, o.created_at,
                   u.first_name, u.last_name
            FROM orders o JOIN users u ON o.user_id=u.id
            ORDER BY o.created_at DESC LIMIT 10
        """)
        recent_orders = cursor.fetchall()
        cursor.execute(
            "SELECT id, first_name, last_name, email, phone, years_exp, months_exp "
            "FROM photographers_applications ORDER BY id DESC"
        )
        applications = cursor.fetchall()
    except Exception as e:
        log.error("Admin dashboard: %s", e)
        total_orders = revenue = total_users = total_photographers = total_videos = 0
        recent_orders = applications = []
    finally:
        cursor.close()
    return render_template("admin_dashboard.html",
                           total_orders=total_orders, revenue=revenue,
                           total_users=total_users,
                           total_photographers=total_photographers,
                           total_videos=total_videos,
                           recent_orders=recent_orders,
                           applications=applications)


@app.route("/admin/order_details/<string:order_id>")
@admin_required
def admin_order_details(order_id):
    order_id = re.sub(r"[^a-zA-Z0-9\-]", "", order_id)[:36]
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/admin/dashboard")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT o.order_id, o.total_price, o.location, o.scheduled_date,
                   o.payment_method, o.status, o.created_at,
                   u.first_name, u.last_name, u.email, u.mobile
            FROM orders o JOIN users u ON o.user_id=u.id WHERE o.order_id=%s
        """, (order_id,))
        order = cursor.fetchone()
        items = []
        if order:
            cursor.execute("""
                SELECT oi.package_name, oi.price, oi.duration, oi.quantity,
                       CONCAT(ph.first_name,' ',ph.last_name) AS photographer_name,
                       ph.rating AS photographer_rating
                FROM order_items oi
                LEFT JOIN photographers ph ON oi.photographer_id=ph.id
                WHERE oi.order_id=%s
            """, (order_id,))
            items = cursor.fetchall()
    except Exception as e:
        log.error("Admin order details: %s", e)
        order = None; items = []
    finally:
        cursor.close()
    return render_template("admin_order_details.html", order=order, items=items)


@app.route("/admin/photographers")
@admin_required
def admin_photographers():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM photographers ORDER BY id DESC")
        photographers = cursor.fetchall()
    except Exception as e:
        log.error("Admin photographers: %s", e)
        photographers = []
    finally:
        cursor.close()
    return render_template("admin_photographers.html", photographers=photographers)


@app.route("/admin/approve/<int:id>", methods=["POST"])
@admin_required
@csrf_protect
def approve_photographer(id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO photographers
                (first_name, last_name, email, phone, address, status, rating)
            SELECT first_name, last_name, email, phone, address, 'active', 0
            FROM photographers_applications WHERE id=%s
        """, (id,))
        cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
        db.commit()
        flash("Photographer approved.", "success")
    except Exception as e:
        log.error("Approve photographer: %s", e)
        db.rollback()
        flash("Error approving photographer.", "error")
    finally:
        cursor.close()
    return redirect("/admin/dashboard")


@app.route("/admin/reject/<int:id>", methods=["POST"])
@admin_required
@csrf_protect
def reject_photographer(id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM photographers_applications WHERE id=%s", (id,))
        db.commit()
        flash("Application rejected.", "success")
    except Exception as e:
        log.error("Reject photographer: %s", e)
        db.rollback()
        flash("Error rejecting application.", "error")
    finally:
        cursor.close()
    return redirect("/admin/dashboard")


@app.route("/admin/orders")
@admin_required
def admin_orders():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT o.order_id, o.total_price, o.status, o.created_at,
                   u.first_name, u.last_name
            FROM orders o JOIN users u ON o.user_id=u.id ORDER BY o.created_at DESC
        """)
        orders = cursor.fetchall()
    except Exception as e:
        log.error("Admin orders: %s", e)
        orders = []
    finally:
        cursor.close()
    return render_template("admin_orders.html", orders=orders)


@app.route("/admin/update_order_status/<string:order_id>", methods=["POST"])
@admin_required
@csrf_protect
def update_order_status(order_id):
    order_id   = re.sub(r"[^a-zA-Z0-9\-]", "", order_id)[:36]
    new_status = _safe_str(request.form.get("status", ""), 20)
    # Allowlist – never trust user-supplied status strings
    if new_status not in VALID_ORDER_STATUSES:
        flash("Invalid status value.", "error")
        return redirect(f"/admin/order_details/{order_id}")
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE orders SET status=%s WHERE order_id=%s", (new_status, order_id))
        db.commit()
        flash(f"Order status updated to {new_status}.", "success")
    except Exception as e:
        log.error("Update order status: %s", e)
        db.rollback()
        flash("Error updating order status.", "error")
    finally:
        cursor.close()
    return redirect(f"/admin/order_details/{order_id}")


@app.route("/admin/packages", methods=["GET", "POST"])
@admin_required
@csrf_protect
def admin_packages():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == "POST":
        try:
            cursor.execute(
                "INSERT INTO packages (package_name, package_price, duration, image_filename) "
                "VALUES (%s,%s,%s,%s)",
                (
                    _safe_str(request.form.get("package_name", ""), 150),
                    request.form.get("package_price"),
                    _safe_str(request.form.get("duration", ""), 100),
                    _safe_str(request.form.get("image_filename", ""), 255),
                ),
            )
            db.commit()
            flash("Package added.", "success")
        except Exception as e:
            log.error("Add package: %s", e)
            db.rollback()
            flash("Error adding package.", "error")
        finally:
            cursor.close()
        return redirect("/admin/packages")
    try:
        cursor.execute("SELECT * FROM packages ORDER BY package_id DESC")
        packages = cursor.fetchall()
    except Exception as e:
        log.error("Fetch packages: %s", e)
        packages = []
    finally:
        cursor.close()
    return render_template("admin_packages.html", packages=packages)


@app.route("/admin/delete_package/<int:id>", methods=["POST"])
@admin_required
@csrf_protect
def delete_package(id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM user_packages WHERE package_id=%s", (id,))
        cursor.execute("DELETE FROM packages WHERE package_id=%s", (id,))
        db.commit()
        flash("Package deleted.", "success")
    except Exception as e:
        log.error("Delete package: %s", e)
        db.rollback()
        flash("Cannot delete package.", "error")
    finally:
        cursor.close()
    return redirect("/admin/packages")


@app.route("/admin/edit_package/<int:id>", methods=["GET", "POST"])
@admin_required
@csrf_protect
def edit_package(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    if request.method == "POST":
        try:
            cursor.execute(
                """UPDATE packages SET package_name=%s, package_price=%s,
                   duration=%s, image_filename=%s WHERE package_id=%s""",
                (
                    _safe_str(request.form.get("package_name", ""), 150),
                    request.form.get("package_price"),
                    _safe_str(request.form.get("duration", ""), 100),
                    _safe_str(request.form.get("image_filename", ""), 255),
                    id,
                ),
            )
            db.commit()
            flash("Package updated.", "success")
            return redirect("/admin/packages")
        except Exception as e:
            log.error("Edit package: %s", e)
            db.rollback()
            flash("Error updating package.", "error")
        finally:
            cursor.close()
        return redirect("/admin/packages")

    try:
        cursor.execute("SELECT * FROM packages WHERE package_id=%s", (id,))
        package = cursor.fetchone()
    except Exception as e:
        log.error("Fetch package: %s", e)
        package = None
    finally:
        cursor.close()
    return render_template("edit_package.html", package=package)


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, first_name, last_name, email, mobile, username, role, created_at "
            "FROM users ORDER BY id DESC"
        )
        users = cursor.fetchall()
    except Exception as e:
        log.error("Admin users: %s", e)
        users = []
    finally:
        cursor.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/delete_user/<int:id>", methods=["POST"])
@admin_required
@csrf_protect
def delete_user(id):
    db = get_db()
    cursor = db.cursor()
    try:
        _destroy_all_user_sessions(id, role="user")
        cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (id,))
        cursor.execute("DELETE FROM orders WHERE user_id=%s", (id,))
        cursor.execute("DELETE FROM users WHERE id=%s", (id,))
        db.commit()
        flash("User deleted.", "success")
    except Exception as e:
        log.error("Delete user: %s", e)
        db.rollback()
        flash("Error deleting user.", "error")
    finally:
        cursor.close()
    return redirect("/admin/users")


@app.route("/admin/delete_photographer/<int:id>", methods=["POST"])
@admin_required
@csrf_protect
def delete_photographer(id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM photographers WHERE id=%s", (id,))
        db.commit()
        flash("Photographer deleted.", "success")
    except Exception as e:
        log.error("Delete photographer: %s", e)
        db.rollback()
        flash("Error deleting photographer.", "error")
    finally:
        cursor.close()
    return redirect("/admin/photographers")


@app.route("/admin/view_user/<int:user_id>")
@admin_required
def view_user(user_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect("/admin/users")
        cursor.execute(
            "SELECT order_id, total_price, status, created_at FROM orders "
            "WHERE user_id=%s ORDER BY created_at DESC",
            (user_id,),
        )
        user["orders"] = cursor.fetchall()
    except Exception as e:
        log.error("View user: %s", e)
        user = None
    finally:
        cursor.close()
    return render_template("admin_view_user.html", user=user)


# =============================================================================
#  CHECKOUT & PAYMENT
#  Prices are always re-fetched from the DB at order creation time –
#  never trust client-submitted or session-stored prices.
# =============================================================================
@app.route("/checkout", methods=["GET"])
@login_required
def checkout():
    db = get_db()
    if not db:
        flash("Database error.", "error")
        return redirect("/cart")
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT up.id AS cart_id, up.quantity, up.location, up.scheduled_date,
                   p.package_name, p.package_price, p.duration,
                   CONCAT(ph.first_name,' ',ph.last_name) AS photographer_name,
                   up.photographer_id
            FROM user_packages up
            JOIN packages p ON up.package_id=p.package_id
            LEFT JOIN photographers ph ON up.photographer_id=ph.id
            WHERE up.user_id=%s
        """, (session["user_id"],))
        items = cursor.fetchall()
    finally:
        cursor.close()

    for item in items:
        if not item["photographer_id"] or not item["location"] or not item["scheduled_date"]:
            flash("Please complete all package details before checkout.", "error")
            return redirect("/cart")

    if not items:
        flash("Your cart is empty.", "error")
        return redirect("/cart")

    # Store only IDs in session – prices are re-verified at payment time
    session["checkout_intent"] = {
        "cart_item_ids": [i["cart_id"] for i in items],
        "location":      items[0]["location"],
        "scheduled_date": (
            items[0]["scheduled_date"].strftime("%Y-%m-%d")
            if items[0]["scheduled_date"] else None
        ),
    }
    # Also pass items to the template for display (read-only)
    total = sum(float(i["package_price"]) * int(i["quantity"]) for i in items)
    session["checkout_display"] = {"items": items, "total": total}
    return redirect("/payment")


@app.route("/payment", methods=["GET", "POST"])
@login_required
@csrf_protect
def payment():
    intent = session.get("checkout_intent")
    if not intent:
        flash("No pending checkout. Please add items to cart.", "error")
        return redirect("/cart")

    display = session.get("checkout_display", {})

    if request.method == "POST":
        payment_method = _safe_str(request.form.get("payment_method", "card"), 20)
        if payment_method not in {"card", "upi", "netbanking", "cod"}:
            flash("Invalid payment method.", "error")
            return redirect("/payment")

        if payment_method == "card":
            card_number = re.sub(r"\s", "", request.form.get("card_number", ""))
            if card_number != "4242424242424242":
                flash("Payment declined. Use test card: 4242 4242 4242 4242", "error")
                return redirect("/payment")

        db = get_db()
        if not db:
            flash("Database error.", "error")
            return redirect("/cart")
        cursor = db.cursor(dictionary=True)
        try:
            # ── Re-fetch cart items from DB to get authoritative prices ──────
            cart_ids = intent.get("cart_item_ids", [])
            if not cart_ids:
                raise ValueError("Empty cart intent")

            fmt = ",".join(["%s"] * len(cart_ids))
            cursor.execute(f"""
                SELECT up.id AS cart_id, up.quantity, up.location, up.scheduled_date,
                       p.package_name, p.package_price, p.duration,
                       up.photographer_id
                FROM user_packages up
                JOIN packages p ON up.package_id=p.package_id
                WHERE up.id IN ({fmt}) AND up.user_id=%s
            """, (*cart_ids, session["user_id"]))
            items = cursor.fetchall()

            if not items:
                raise ValueError("Cart items not found or belong to another user")

            # Server-side total calculation
            total = sum(float(i["package_price"]) * int(i["quantity"]) for i in items)

            order_code = str(uuid.uuid4())[:8]
            cursor.execute("""
                INSERT INTO orders
                    (user_id, total_price, location, payment_method, status, order_id, scheduled_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (
                session["user_id"], total, intent["location"],
                payment_method, "Confirmed", order_code, intent["scheduled_date"],
            ))
            for item in items:
                cursor.execute("""
                    INSERT INTO order_items
                        (order_id, package_name, price, duration, location, quantity, photographer_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (
                    order_code, item["package_name"], item["package_price"],
                    item["duration"], item["location"], item["quantity"], item["photographer_id"],
                ))
            cursor.execute("DELETE FROM user_packages WHERE user_id=%s", (session["user_id"],))
            db.commit()

            session.pop("checkout_intent", None)
            session.pop("checkout_display", None)
            flash("Payment successful! Order placed.", "success")
            log.info("Order placed: order_id=%s user_id=%s total=%.2f",
                     order_code, session["user_id"], total)
            return redirect(f"/order-success?order_id={order_code}&total={total:.2f}")
        except Exception as e:
            db.rollback()
            log.error("Payment error: %s", e)
            flash("Error creating order. Please try again.", "error")
            return redirect("/cart")
        finally:
            cursor.close()

    return render_template("payment.html", intent=display)


@app.route("/order-success")
@login_required
def order_success():
    order_id = re.sub(r"[^a-zA-Z0-9\-]", "", request.args.get("order_id", ""))[:36]
    total    = request.args.get("total", "0")
    try:
        total = f"{float(total):.2f}"
    except (ValueError, TypeError):
        total = "0.00"
    return render_template("order_success.html", order_id=order_id, total=total)


# =============================================================================
#  DB HEALTH CHECK  – admin only in production
# =============================================================================
@app.route("/test-db")
@admin_required
def test_db():
    try:
        db = get_db()
        if not db:
            return jsonify({"status": "error", "message": "Connection failed"}), 500
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT 1 AS test")
        result = cursor.fetchone()
        cursor.close()
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": "DB error"}), 500


# =============================================================================
#  App startup
# =============================================================================
with app.app_context():
    create_admin_user()
    create_video_tables()
    create_sessions_table()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)