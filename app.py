import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, date
from pathlib import Path

from flask import Flask, request, redirect, url_for, session, abort, send_from_directory
from flask import render_template_string, flash

# Optional webcam capture
try:
    import cv2
    OPENCV_OK = True
except Exception:
    OPENCV_OK = False

APP_SECRET = os.environ.get("APP_SECRET", "change-this-in-production-please")
DB_PATH = os.environ.get("DB_PATH", "attendance.db")
SNAP_DIR = os.environ.get("SNAP_DIR", "snapshots")

app = Flask(__name__)
app.secret_key = APP_SECRET

Path(SNAP_DIR).mkdir(parents=True, exist_ok=True)

# ----------------------------
# DB helpers
# ----------------------------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            section TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS day_session (
            day TEXT PRIMARY KEY,
            session_code TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('P')),
            checked_in_at TEXT NOT NULL,
            snapshot_path TEXT,
            ip TEXT,
            user_agent TEXT,
            UNIQUE(student_id, day),
            FOREIGN KEY(student_id) REFERENCES students(id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT
        )
        """)

        # Create default admin if none exists
        cur.execute("SELECT COUNT(*) AS c FROM admin")
        if cur.fetchone()["c"] == 0:
            # Default: admin / admin123 (change immediately)
            username = "admin"
            password = "admin123"
            salt = secrets.token_hex(16)
            pass_hash = hash_pw(password, salt)
            cur.execute("INSERT INTO admin(username, pass_hash, salt) VALUES (?,?,?)",
                        (username, pass_hash, salt))
            cur.execute("INSERT INTO audit_log(ts,event,detail) VALUES (?,?,?)",
                        (now(), "INIT_ADMIN", "Default admin created (admin/admin123). Change ASAP."))
        con.commit()

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def today():
    return date.today().isoformat()

def hash_pw(password: str, salt: str) -> str:
    # PBKDF2-like simple approach: sha256(salt + password) iterated.
    # For offline school PC, this is fine. If you want stronger: use passlib/bcrypt.
    h = (salt + password).encode("utf-8")
    for _ in range(150_000):
        h = hashlib.sha256(h).digest()
    return h.hex()

def log(event: str, detail: str = ""):
    with db() as con:
        con.execute("INSERT INTO audit_log(ts,event,detail) VALUES (?,?,?)",
                    (now(), event, detail[:1000]))
        con.commit()

# ----------------------------
# Security / auth helpers
# ----------------------------
def require_admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return None

def rate_limit_key():
    # Simple per-session limiter
    if "rl" not in session:
        session["rl"] = {"count": 0, "ts": now()}
    return session["rl"]

def bump_rate_limit(max_attempts=20):
    rl = rate_limit_key()
    rl["count"] += 1
    session["rl"] = rl
    if rl["count"] > max_attempts:
        abort(429)

# ----------------------------
# Session code (anti-cheat)
# ----------------------------
def get_or_create_session_code():
    d = today()
    with db() as con:
        cur = con.execute("SELECT session_code FROM day_session WHERE day=?", (d,))
        row = cur.fetchone()
        if row:
            return row["session_code"]
        code = secrets.token_hex(3).upper()  # e.g. "A1B2C3"
        con.execute("INSERT INTO day_session(day, session_code, created_at) VALUES (?,?,?)",
                    (d, code, now()))
        con.commit()
        log("NEW_DAY_SESSION", f"day={d}, code={code}")
        return code

# ----------------------------
# Webcam snapshot
# ----------------------------
def capture_snapshot(roll_no: str) -> str | None:
    if not OPENCV_OK:
        return None

    # Capture from default webcam (0)
    cam = cv2.VideoCapture(0)
    if not cam.isOpened():
        return None

    # Warm up frames
    for _ in range(5):
        cam.read()

    ok, frame = cam.read()
    cam.release()
    if not ok or frame is None:
        return None

    # Save snapshot
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{today()}_{roll_no}_{ts}.jpg"
    path = os.path.join(SNAP_DIR, filename)
    cv2.imwrite(path, frame)
    return filename

# ----------------------------
# Templates (kept inline for easy copy)
# ----------------------------
BASE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, Arial, sans-serif; max-width: 900px; margin: 20px auto; padding: 0 14px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 14px; margin: 12px 0; }
    input, select { padding: 10px; border-radius: 10px; border: 1px solid #ccc; width: 100%; margin: 6px 0; }
    button { padding: 10px 14px; border-radius: 10px; border: 0; background: #222; color: #fff; cursor: pointer; }
    a { color: #0b57d0; text-decoration: none; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .muted { color: #666; font-size: 0.95rem; }
    .ok { color: #0a7a28; font-weight: 600; }
    .bad { color: #b00020; font-weight: 600; }
    .flash { background: #fff5cc; padding: 10px; border-radius: 10px; border: 1px solid #ffe08a; margin: 10px 0; }
    code { background: #f3f3f3; padding: 2px 6px; border-radius: 8px; }
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
      <div>
        <div style="font-size:1.4rem; font-weight:700;">{{ title }}</div>
        <div class="muted">{{ subtitle }}</div>
      </div>
      <div>
        {% if admin %}
          <a href="{{ url_for('admin_dashboard') }}">Admin</a> |
          <a href="{{ url_for('admin_logout') }}">Logout</a>
        {% else %}
          <a href="{{ url_for('kiosk') }}">Kiosk</a> |
          <a href="{{ url_for('admin_login') }}">Admin Login</a>
        {% endif %}
      </div>
    </div>
  </div>

  {% with messages = get_flashed_messages() %}
    {% if messages %}
      {% for m in messages %}
        <div class="flash">{{ m }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {{ body|safe }}
</body>
</html>
"""

def page(title, body, subtitle="Offline classroom attendance", admin=False):
    return render_template_string(BASE, title=title, body=body, subtitle=subtitle, admin=admin)

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def home():
    return redirect(url_for("kiosk"))

@app.route("/kiosk", methods=["GET", "POST"])
def kiosk():
    # Student self-check on classroom PC
    code = get_or_create_session_code()

    if request.method == "POST":
        bump_rate_limit()

        roll_no = request.form.get("roll_no", "").strip()
        pin = request.form.get("pin", "").strip()
        session_code = request.form.get("session_code", "").strip().upper()

        if not roll_no or not pin or not session_code:
            flash("Fill all fields.")
            return redirect(url_for("kiosk"))

        # Validate session code
        if session_code != code:
            log("CHECKIN_FAIL", f"roll={roll_no}, reason=bad_session_code")
            flash("Wrong session code. Ask teacher for today’s code.")
            return redirect(url_for("kiosk"))

        # Find student
        with db() as con:
            cur = con.execute("SELECT * FROM students WHERE roll_no=?", (roll_no,))
            stu = cur.fetchone()

        if not stu:
            log("CHECKIN_FAIL", f"roll={roll_no}, reason=unknown_roll")
            flash("Unknown roll number.")
            return redirect(url_for("kiosk"))

        # Verify PIN
        expected = hash_pw(pin, stu["salt"])
        if expected != stu["pin_hash"]:
            log("CHECKIN_FAIL", f"roll={roll_no}, reason=bad_pin")
            flash("Wrong PIN.")
            return redirect(url_for("kiosk"))

        # Capture snapshot (anti-cheat evidence)
        snap_file = capture_snapshot(roll_no)

        # Record attendance
        try:
            with db() as con:
                con.execute("""
                    INSERT INTO attendance(student_id, day, status, checked_in_at, snapshot_path, ip, user_agent)
                    VALUES(?,?,?,?,?,?,?)
                """, (
                    stu["id"], today(), "P", now(),
                    snap_file,
                    request.remote_addr,
                    request.headers.get("User-Agent", "")[:300]
                ))
                con.commit()
            log("CHECKIN_OK", f"roll={roll_no}, snap={snap_file or 'none'}")
            body = f"""
            <div class="card">
              <div class="ok">Checked in ✅</div>
              <p><b>{stu['full_name']}</b> (Roll: <code>{stu['roll_no']}</code>)</p>
              <p>Date: <code>{today()}</code> Time: <code>{now()}</code></p>
              <p class="muted">If someone checked in for a friend, the teacher can verify using the snapshot + logs.</p>
              <a href="{url_for('kiosk')}"><button>Next student</button></a>
            </div>
            """
            return page("Kiosk: Attendance", body, subtitle="Student self-check-in", admin=False)
        except sqlite3.IntegrityError:
            log("CHECKIN_DUP", f"roll={roll_no} already checked today")
            flash("Already checked in today.")
            return redirect(url_for("kiosk"))

    # GET
    body = f"""
    <div class="card">
      <p><b>Today’s teacher session code:</b> <code style="font-size:1.2rem;">{code}</code></p>
      <p class="muted">Teacher should display this code on the board (changes daily).</p>
    </div>

    <div class="card">
      <form method="POST">
        <label>Roll Number</label>
        <input name="roll_no" placeholder="e.g. 12" autocomplete="off" required>

        <label>Personal PIN</label>
        <input name="pin" placeholder="Your secret PIN" type="password" autocomplete="off" required>

        <label>Session Code (from teacher)</label>
        <input name="session_code" placeholder="e.g. A1B2C3" autocomplete="off" required>

        <button type="submit">Check In</button>
      </form>
      <p class="muted">
        Anti-cheat: PIN + daily code + snapshot ({'enabled' if OPENCV_OK else 'NOT enabled (OpenCV missing)'}).
      </p>
    </div>
    """
    return page("Kiosk: Attendance", body, subtitle="Offline student self-check-in", admin=False)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pw = request.form.get("password", "").strip()

        with db() as con:
            row = con.execute("SELECT * FROM admin WHERE username=?", (user,)).fetchone()

        if not row:
            flash("Invalid credentials.")
            return redirect(url_for("admin_login"))

        if hash_pw(pw, row["salt"]) != row["pass_hash"]:
            flash("Invalid credentials.")
            return redirect(url_for("admin_login"))

        session["admin"] = True
        log("ADMIN_LOGIN", user)
        return redirect(url_for("admin_dashboard"))

    body = """
    <div class="card">
      <form method="POST">
        <label>Username</label>
        <input name="username" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
      <p class="muted">Default is <code>admin</code>/<code>admin123</code>. Change it immediately.</p>
    </div>
    """
    return page("Admin Login", body, subtitle="Teacher/Admin only", admin=False)

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin", methods=["GET"])
def admin_dashboard():
    r = require_admin()
    if r: return r

    code = get_or_create_session_code()

    with db() as con:
        total_students = con.execute("SELECT COUNT(*) AS c FROM students").fetchone()["c"]
        today_present = con.execute("""
            SELECT COUNT(*) AS c
            FROM attendance a
            WHERE a.day=?
        """, (today(),)).fetchone()["c"]

        recent = con.execute("""
            SELECT a.checked_in_at, s.roll_no, s.full_name, a.snapshot_path
            FROM attendance a
            JOIN students s ON s.id=a.student_id
            WHERE a.day=?
            ORDER BY a.checked_in_at DESC
            LIMIT 50
        """, (today(),)).fetchall()

    rows = ""
    for x in recent:
        snap_link = f"<a href='{url_for('snapshot', filename=x['snapshot_path'])}'>view</a>" if x["snapshot_path"] else "—"
        rows += f"<tr><td>{x['checked_in_at']}</td><td>{x['roll_no']}</td><td>{x['full_name']}</td><td>{snap_link}</td></tr>"

    body = f"""
    <div class="card">
      <div class="row">
        <div>
          <div><b>Today</b>: <code>{today()}</code></div>
          <div><b>Session code</b>: <code style="font-size:1.1rem;">{code}</code></div>
          <div class="muted">Write this on the board (changes daily).</div>
        </div>
        <div>
          <div><b>Total students</b>: <code>{total_students}</code></div>
          <div><b>Present today</b>: <code>{today_present}</code></div>
          <div class="muted">Use snapshots to detect friend check-ins.</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Add student</h3>
      <form method="POST" action="{url_for('admin_add_student')}">
        <div class="row">
          <div>
            <label>Roll No</label>
            <input name="roll_no" required>
          </div>
          <div>
            <label>Full Name</label>
            <input name="full_name" required>
          </div>
        </div>
        <div class="row">
          <div>
            <label>Class</label>
            <input name="class_name" placeholder="e.g. 10" required>
          </div>
          <div>
            <label>Section</label>
            <input name="section" placeholder="e.g. A" required>
          </div>
        </div>
        <label>Student PIN (give privately)</label>
        <input name="pin" placeholder="e.g. 4-6 digits" required>
        <button type="submit">Add</button>
      </form>
    </div>

    <div class="card">
      <h3>Today check-ins (latest 50)</h3>
      <table border="0" cellpadding="6" cellspacing="0" style="width:100%;">
        <tr><th align="left">Time</th><th align="left">Roll</th><th align="left">Name</th><th align="left">Snapshot</th></tr>
        {rows if rows else "<tr><td colspan='4' class='muted'>No check-ins yet</td></tr>"}
      </table>
      <p class="muted">Cheat detection = compare snapshot with student identity. Suspicious? You have proof.</p>
    </div>

    <div class="card">
      <a href="{url_for('admin_reports')}"><button>Reports</button></a>
      <a href="{url_for('admin_change_password')}"><button style="margin-left:8px;">Change admin password</button></a>
    </div>
    """
    return page("Admin Dashboard", body, subtitle="Offline classroom attendance", admin=True)

@app.route("/admin/add_student", methods=["POST"])
def admin_add_student():
    r = require_admin()
    if r: return r

    roll = request.form.get("roll_no","").strip()
    name = request.form.get("full_name","").strip()
    cls = request.form.get("class_name","").strip()
    sec = request.form.get("section","").strip()
    pin = request.form.get("pin","").strip()

    if not all([roll, name, cls, sec, pin]):
        flash("All fields required.")
        return redirect(url_for("admin_dashboard"))

    salt = secrets.token_hex(16)
    pin_hash = hash_pw(pin, salt)

    try:
        with db() as con:
            con.execute("""
                INSERT INTO students(roll_no, full_name, class_name, section, pin_hash, salt, created_at)
                VALUES(?,?,?,?,?,?,?)
            """, (roll, name, cls, sec, pin_hash, salt, now()))
            con.commit()
        log("ADD_STUDENT", f"roll={roll}, name={name}, class={cls}-{sec}")
        flash("Student added.")
    except sqlite3.IntegrityError:
        flash("Roll number already exists.")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/reports")
def admin_reports():
    r = require_admin()
    if r: return r

    day = request.args.get("day", today()).strip()

    with db() as con:
        # All students + present marker
        rows = con.execute("""
            SELECT s.roll_no, s.full_name, s.class_name, s.section,
                   CASE WHEN a.id IS NULL THEN 'A' ELSE 'P' END AS status,
                   a.checked_in_at, a.snapshot_path
            FROM students s
            LEFT JOIN attendance a
              ON a.student_id=s.id AND a.day=?
            ORDER BY s.class_name, s.section, CAST(s.roll_no AS INT), s.roll_no
        """, (day,)).fetchall()

    tr = ""
    present = 0
    absent = 0
    for x in rows:
        if x["status"] == "P":
            present += 1
        else:
            absent += 1
        snap_link = f"<a href='{url_for('snapshot', filename=x['snapshot_path'])}'>view</a>" if x["snapshot_path"] else "—"
        tr += f"<tr><td>{x['class_name']}</td><td>{x['section']}</td><td>{x['roll_no']}</td><td>{x['full_name']}</td><td>{x['status']}</td><td>{x['checked_in_at'] or '—'}</td><td>{snap_link}</td></tr>"

    body = f"""
    <div class="card">
      <form method="GET">
        <label>Report date (YYYY-MM-DD)</label>
        <input name="day" value="{day}">
        <button type="submit">Load</button>
      </form>
      <p><b>Present:</b> <code>{present}</code> &nbsp; <b>Absent:</b> <code>{absent}</code></p>
      <p class="muted">Absent is inferred when no check-in exists for that student on that day.</p>
    </div>

    <div class="card">
      <table border="0" cellpadding="6" cellspacing="0" style="width:100%;">
        <tr>
          <th align="left">Class</th><th align="left">Sec</th><th align="left">Roll</th><th align="left">Name</th>
          <th align="left">Status</th><th align="left">Time</th><th align="left">Snapshot</th>
        </tr>
        {tr if tr else "<tr><td colspan='7' class='muted'>No students in DB</td></tr>"}
      </table>
    </div>
    """
    return page("Reports", body, subtitle="Daily attendance report", admin=True)

@app.route("/admin/change_password", methods=["GET", "POST"])
def admin_change_password():
    r = require_admin()
    if r: return r

    if request.method == "POST":
        old = request.form.get("old","")
        new = request.form.get("new","")
        new2 = request.form.get("new2","")
        if not new or new != new2:
            flash("New passwords do not match.")
            return redirect(url_for("admin_change_password"))

        with db() as con:
            row = con.execute("SELECT * FROM admin WHERE username='admin'").fetchone()

        if not row or hash_pw(old, row["salt"]) != row["pass_hash"]:
            flash("Old password wrong.")
            return redirect(url_for("admin_change_password"))

        salt = secrets.token_hex(16)
        ph = hash_pw(new, salt)
        with db() as con:
            con.execute("UPDATE admin SET pass_hash=?, salt=? WHERE username='admin'", (ph, salt))
            con.commit()
        log("ADMIN_PW_CHANGE", "admin password changed")
        flash("Password updated.")
        return redirect(url_for("admin_dashboard"))

    body = """
    <div class="card">
      <form method="POST">
        <label>Old password</label>
        <input name="old" type="password" required>
        <label>New password</label>
        <input name="new" type="password" required>
        <label>Repeat new password</label>
        <input name="new2" type="password" required>
        <button type="submit">Change</button>
      </form>
    </div>
    """
    return page("Change Admin Password", body, subtitle="Do this right away", admin=True)

@app.route("/snapshots/<path:filename>")
def snapshot(filename):
    r = require_admin()
    if r: return r
    # Serve snapshots only to admin
    return send_from_directory(SNAP_DIR, filename)

# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    init_db()
    # Host 0.0.0.0 only if you want LAN access. For single PC: 127.0.0.1 is enough.
    app.run(host="127.0.0.1", port=5000, debug=True)


# This is the rest of the file.
init_db()
