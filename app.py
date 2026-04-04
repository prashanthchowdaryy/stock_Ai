from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
import sqlite3
import hashlib
import os
import re
import json
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True, origins=[
    "http://localhost:5000", "http://127.0.0.1:5000",
    "http://localhost:5500", "http://127.0.0.1:5500",
    "http://localhost:5501", "http://127.0.0.1:5501",
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:8080", "http://127.0.0.1:8080",
    "null", "*"
])

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rjsfin.db")

# ─── DB SETUP ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            is_active INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT,
            price INTEGER DEFAULT 0,
            original_price INTEGER DEFAULT 0,
            duration TEXT,
            lessons INTEGER DEFAULT 0,
            level TEXT DEFAULT 'Beginner',
            is_free INTEGER DEFAULT 0,
            badge TEXT,
            features TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            course_id INTEGER,
            amount_paid INTEGER,
            payment_id TEXT,
            purchased_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'completed',
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(course_id) REFERENCES courses(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER,
            expires_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # ── NEW: payment_submissions stores every manual UPI/bank payment form ──
    c.execute("""
        CREATE TABLE IF NOT EXISTS payment_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            course_title TEXT NOT NULL,
            student_name TEXT NOT NULL,
            student_email TEXT NOT NULL,
            student_phone TEXT,
            amount INTEGER NOT NULL,
            payment_method TEXT DEFAULT 'UPI',
            transaction_id TEXT,
            utr_number TEXT,
            screenshot_note TEXT,
            status TEXT DEFAULT 'pending',
            submitted_at TEXT DEFAULT (datetime('now')),
            verified_at TEXT,
            notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Seed courses
    courses = [
        ("Starter Plan", "starter-plan", "Your first step into the trading world. Start with the basics.", 0, 0, "4 weeks", 20, "Beginner", 1, "FREE", '["Stock market basics", "Chart reading intro", "Risk management", "5 live sessions"]'),
        ("Technical Analysis + AI Lab", "ta-ai-lab", "Learn trading using charts, patterns, and AI tools.", 1499, 2999, "6 weeks", 35, "Intermediate", 0, "POPULAR", '["Advanced charting", "AI-powered signals", "Pattern recognition", "Live trading sessions", "PDF notes"]'),
        ("Core Course", "core-course", "Complete trading education — from fundamentals to options.", 2999, 5999, "10 weeks", 60, "Intermediate", 0, "BESTSELLER", '["Full market curriculum", "F&O basics", "Sector analysis", "1:1 mentorship session", "Certificate"]'),
        ("Options Mastery", "options-mastery", "Become an expert in options trading. Advanced strategies.", 5999, 9999, "12 weeks", 80, "Advanced", 0, "PREMIUM", '["Greeks & pricing", "Multi-leg strategies", "Hedging techniques", "Live options room", "Lifetime access"]'),
    ]

    for course in courses:
        c.execute("""
            INSERT OR IGNORE INTO courses (title, slug, description, price, original_price, duration, lessons, level, is_free, badge, features)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, course)

    conn.commit()
    conn.close()
    print("✅ Database initialized.")

init_db()   # runs on every startup, including gunicorn/Render

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
    conn = get_db()
    conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)", (token, user_id, expires))
    conn.commit()
    conn.close()
    return token

def validate_session(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token=?", (token,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        return None
    return row["user_id"]

def get_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT id, name, email, phone, created_at FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def serialize_course(row):
    d = dict(row)
    if isinstance(d.get("features"), str):
        try:
            d["features"] = json.loads(d["features"])
        except Exception:
            d["features"] = []
    return d

def generate_reference():
    """Generate a unique RJS reference like RJS04A7B2C1"""
    return "RJS" + secrets.token_hex(4).upper()

# ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not all([name, email, password]):
        return jsonify({"success": False, "message": "Name, email, and password are required"}), 400

    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return jsonify({"success": False, "message": "Please enter a valid email address"}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters long"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": "This email is already registered. Please log in."}), 409

    conn.execute(
        "INSERT INTO users (name, email, phone, password_hash) VALUES (?,?,?,?)",
        (name, email, phone, hash_password(password))
    )
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    conn.close()

    token = create_session(user_id)
    return jsonify({
        "success": True,
        "message": f"Welcome {name}! Your account has been created.",
        "token": token,
        "user": {"id": user_id, "name": name, "email": email}
    }), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "message": "Please enter both email and password"}), 400

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email=? AND password_hash=?",
        (email, hash_password(password))
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "message": "Invalid email or password"}), 401

    token = create_session(user["id"])
    return jsonify({
        "success": True,
        "message": f"Welcome back, {user['name']}!",
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
    })


@app.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return jsonify({"success": True, "message": "Logged out successfully"})


@app.route("/me", methods=["GET"])
def me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = validate_session(token)
    if not user_id:
        return jsonify({"success": False, "message": "Please log in"}), 401
    user = get_user(user_id)
    return jsonify({"success": True, "user": user})

# ─── COURSE ROUTES ────────────────────────────────────────────────────────────

@app.route("/courses", methods=["GET"])
def courses():
    conn = get_db()
    rows = conn.execute("SELECT * FROM courses ORDER BY price ASC").fetchall()
    conn.close()
    return jsonify({
        "success": True,
        "courses": [serialize_course(r) for r in rows]
    })


@app.route("/purchase", methods=["POST"])
def purchase():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = validate_session(token)
    if not user_id:
        return jsonify({"success": False, "message": "Please log in first"}), 401

    data = request.get_json()
    course_id = data.get("course_id")
    payment_id = data.get("payment_id", f"mock_pay_{secrets.token_hex(8)}")

    if not course_id:
        return jsonify({"success": False, "message": "course_id is required"}), 400

    conn = get_db()
    course = conn.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    if not course:
        conn.close()
        return jsonify({"success": False, "message": "Course not found"}), 404

    existing = conn.execute(
        "SELECT id FROM purchases WHERE user_id=? AND course_id=?", (user_id, course_id)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": "You have already purchased this course"}), 409

    conn.execute(
        "INSERT INTO purchases (user_id, course_id, amount_paid, payment_id) VALUES (?,?,?,?)",
        (user_id, course_id, course["price"], payment_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Successfully enrolled in '{course['title']}'! Happy learning.",
        "payment_id": payment_id
    })


@app.route("/my-courses", methods=["GET"])
def my_courses():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = validate_session(token)
    if not user_id:
        return jsonify({"success": False, "message": "Please log in"}), 401

    conn = get_db()
    rows = conn.execute("""
        SELECT c.*, p.purchased_at, p.payment_id
        FROM purchases p
        JOIN courses c ON p.course_id = c.id
        WHERE p.user_id = ?
        ORDER BY p.purchased_at DESC
    """, (user_id,)).fetchall()
    conn.close()
    return jsonify({"success": True, "courses": [serialize_course(r) for r in rows]})


# ─── PAYMENT SUBMISSION ROUTES ────────────────────────────────────────────────

@app.route("/submit-payment", methods=["POST"])
def submit_payment():
    """
    Called by payment.html when a student submits their UPI/bank transfer details.
    Stores everything in payment_submissions table with status='pending'.
    Admin can later verify and flip status to 'verified'.
    """
    data = request.get_json()

    # Required fields
    course_title   = (data.get("course_title") or "").strip()
    student_name   = (data.get("student_name") or "").strip()
    student_email  = (data.get("student_email") or "").strip().lower()
    amount         = data.get("amount", 0)

    if not all([course_title, student_name, student_email]):
        return jsonify({"success": False, "message": "Course, name and email are required"}), 400

    # Optional fields
    student_phone  = (data.get("student_phone") or "").strip()
    payment_method = (data.get("payment_method") or "UPI").strip()
    transaction_id = (data.get("transaction_id") or "").strip()
    utr_number     = (data.get("utr_number") or "").strip()
    screenshot_note= (data.get("screenshot_note") or "").strip()

    # If logged in, link to user account
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = validate_session(token)  # None if not logged in — that's fine

    # Generate unique reference
    ref = generate_reference()
    # Make sure it's unique (extremely unlikely collision but safe)
    conn = get_db()
    while conn.execute("SELECT id FROM payment_submissions WHERE reference_id=?", (ref,)).fetchone():
        ref = generate_reference()

    try:
        conn.execute("""
            INSERT INTO payment_submissions
                (reference_id, user_id, course_title, student_name, student_email,
                 student_phone, amount, payment_method, transaction_id, utr_number,
                 screenshot_note, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending')
        """, (ref, user_id, course_title, student_name, student_email,
              student_phone, int(amount), payment_method, transaction_id,
              utr_number, screenshot_note))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500

    conn.close()

    return jsonify({
        "success": True,
        "message": "Payment submitted! We'll verify and activate your course within 2–4 hours.",
        "reference_id": ref
    }), 201


@app.route("/payment-status/<reference_id>", methods=["GET"])
def payment_status(reference_id):
    """Let frontend poll the status of a submitted payment."""
    conn = get_db()
    row = conn.execute(
        "SELECT reference_id, course_title, student_name, amount, status, submitted_at, verified_at FROM payment_submissions WHERE reference_id=?",
        (reference_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "message": "Reference not found"}), 404
    return jsonify({"success": True, "payment": dict(row)})


@app.route("/admin/payments", methods=["GET"])
def admin_payments():
    """
    Admin endpoint — lists all payment submissions.
    Filter by status: /admin/payments?status=pending
    Protect this in production with an admin token!
    """
    status_filter = request.args.get("status")  # pending | verified | rejected | all
    conn = get_db()
    if status_filter and status_filter != "all":
        rows = conn.execute(
            "SELECT * FROM payment_submissions WHERE status=? ORDER BY submitted_at DESC",
            (status_filter,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM payment_submissions ORDER BY submitted_at DESC"
        ).fetchall()
    conn.close()
    return jsonify({"success": True, "count": len(rows), "payments": [dict(r) for r in rows]})


@app.route("/admin/payments/<int:payment_id>/verify", methods=["POST"])
def verify_payment(payment_id):
    """
    Admin marks a payment as verified → automatically creates a purchase record.
    POST body: { "action": "verify" | "reject", "notes": "optional note" }
    """
    data = request.get_json() or {}
    action = data.get("action", "verify")
    notes  = data.get("notes", "")

    conn = get_db()
    row = conn.execute("SELECT * FROM payment_submissions WHERE id=?", (payment_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "message": "Payment record not found"}), 404

    new_status = "verified" if action == "verify" else "rejected"
    now = datetime.utcnow().isoformat()

    conn.execute(
        "UPDATE payment_submissions SET status=?, verified_at=?, notes=? WHERE id=?",
        (new_status, now, notes, payment_id)
    )

    # If verified and user_id is linked → auto-create purchases record
    if new_status == "verified" and row["user_id"]:
        course = conn.execute(
            "SELECT id FROM courses WHERE title=?", (row["course_title"],)
        ).fetchone()
        if course:
            existing = conn.execute(
                "SELECT id FROM purchases WHERE user_id=? AND course_id=?",
                (row["user_id"], course["id"])
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO purchases (user_id, course_id, amount_paid, payment_id, status) VALUES (?,?,?,?,'completed')",
                    (row["user_id"], course["id"], row["amount"], row["reference_id"])
                )

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Payment {new_status} successfully."})


# ─── PAGE ROUTES ──────────────────────────────────────────────────────────────

@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/payment-page")
def payment_page():
    return render_template("payment.html")

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app": "RJS Fin API", "version": "1.1.0"})

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    allowed = ["http://localhost:5000", "http://127.0.0.1:5000",
               "http://localhost:5500", "http://127.0.0.1:5500",
               "http://localhost:5501", "http://127.0.0.1:5501",
               "http://localhost:3000", "http://127.0.0.1:3000",
               "http://localhost:8080", "http://127.0.0.1:8080", "null"]
    if origin in allowed or not origin:
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
