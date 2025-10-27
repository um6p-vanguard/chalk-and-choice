import os, io, base64, secrets, argparse, csv, random, functools, time, json, hmac, hashlib
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer

from models import (db, Poll, Vote, Student, User, Form, 
                    FormResponse, LectureQuestion, LectureSignal,
                    StudentStats, Intervention, LearningOutcome,
                    Task, Quest, TaskPrereq, TaskOutcome, QuestBadge,
                    QuestPrereq, QuestOutcome)
import qrcode



# --------------------------------------------------------------------
# Task Config
# --------------------------------------------------------------------

TASK_CONFIG_SCHEMAS = {
    "CODE": {
        "fields": [
            {"key": "language", "label": "Language", "type": "select",
             "choices": ["python", "javascript", "cpp", "java"], "default": "python"},
            {"key": "judge", "label": "Judge", "type": "select",
             "choices": ["io", "unit", "custom"], "default": "io"},
            {"key": "timeout_ms", "label": "Timeout (ms)", "type": "number", "min": 0, "default": 2000},
            {"key": "memory_mb", "label": "Memory (MB)", "type": "number", "min": 16, "default": 256},
            {"key": "allowed_imports", "label": "Allowed imports (comma-separated)", "type": "text", "default": ""},
            {"key": "show_samples", "label": "Show sample testcases", "type": "checkbox", "default": True},
        ]
    },
    "MCQ": {
        "fields": [
            {"key": "options_raw", "label": "Options (one per line, e.g. 'A) Option text')", "type": "textarea",
             "default": "A) ...\nB) ..."},
            {"key": "correct_ids", "label": "Correct IDs (comma-separated, e.g. 'B' or 'A,C')", "type": "text", "default": ""},
            {"key": "randomize", "label": "Randomize options", "type": "checkbox", "default": True},
            {"key": "multiple_correct", "label": "Allow multiple correct", "type": "checkbox", "default": False},
        ]
    },
    "TEXT": {
        "fields": [
            {"key": "min_words", "label": "Min words", "type": "number", "min": 0, "default": 80},
            {"key": "max_words", "label": "Max words", "type": "number", "min": 0, "default": 300},
            {"key": "keywords_csv", "label": "Required keywords (comma-separated)", "type": "text", "default": ""},
        ]
    },
    "REFLECTION": {
        "fields": [
            {"key": "min_words", "label": "Min words", "type": "number", "min": 0, "default": 80},
            {"key": "max_words", "label": "Max words", "type": "number", "min": 0, "default": 300},
        ]
    },
    "VISIT": {
        "fields": [
            {"key": "url", "label": "URL to visit", "type": "text", "default": ""},
            {"key": "min_seconds", "label": "Minimum seconds on page", "type": "number", "min": 0, "default": 60},
            {"key": "require_evidence", "label": "Require evidence (screenshot/link)", "type": "checkbox", "default": True},
        ]
    },
    "FILE_UPLOAD": {
        "fields": [
            {"key": "allowed_mime", "label": "Allowed MIME types (comma-separated)", "type": "text", "default": "application/pdf"},
            {"key": "max_bytes", "label": "Max file size (bytes)", "type": "number", "min": 0, "default": 1048576},
            {"key": "multiple", "label": "Allow multiple files", "type": "checkbox", "default": False},
        ]
    },
}


# --------------------------------------------------------------------
# Utils
# --------------------------------------------------------------------

def parse_dt_local(s):
    """Parse HTML <input type=datetime-local> to UTC naive datetime."""
    if not s: return None
    # Expect 'YYYY-MM-DDTHH:MM' (no timezone). Treat as UTC.
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%dT%H:%M")
    except Exception:
        return None

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------
APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(32)
DB_PATH = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))
DB_URI  = os.environ.get("DATABASE_URL") or f"sqlite:///{DB_PATH}"
SHARE_HOST = os.environ.get("CLASSVOTE_SHARE_HOST")  # optional override for QR links

def create_app(db_path=DB_URI):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = APP_SECRET
    app.config["SQLALCHEMY_DATABASE_URI"] = db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
    app.config["SESSION_COOKIE_NAME"] = "classvote_session"
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    db.init_app(app)
    with app.app_context():
        from sqlalchemy import event
        @event.listens_for(db.engine, "connect")
        def _fk_pragma(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
        db.create_all()
    return app

app = create_app()

# --------------------------------------------------------------------
# CSRF helpers (form + JSON header)
# --------------------------------------------------------------------
def _csrf_key():
    if "csrf_key" not in session:
        session["csrf_key"] = secrets.token_hex(16)
    return session["csrf_key"]

def csrf_token():
    secret = APP_SECRET.encode()
    key = _csrf_key().encode()
    return hmac.new(secret, key, hashlib.sha256).hexdigest()

def verify_csrf(form_field="csrf"):
    sent = request.form.get(form_field, "")
    return hmac.compare_digest(sent, csrf_token())

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

# --------------------------------------------------------------------
# Auth/session helpers
# --------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None

def current_student():
    sid = session.get("student_id")
    return Student.query.get(sid) if sid else None

def logout_everyone():
    session.pop("user_id", None)
    session.pop("user_role", None)
    session.pop("student_id", None)
    session.pop("student_name", None)
    session.pop("must_change_pw", None)

def require_user(role=None):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))

            allowed = None
            if role is None:
                allowed = None
            elif isinstance(role, (list, tuple, set)):
                allowed = set(role)
            else:
                allowed = {role}

            if allowed and u.role not in allowed:
                abort(403)

            if session.get("student_id"):
                logout_everyone()
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return deco


def require_student():
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            s = current_student()
            if not s:
                return redirect(url_for("login", next=request.path))
            if session.get("user_id"):
                logout_everyone()
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return deco

# --------------------------------------------------------------------
# Student "remember me" cookie (optional)
# --------------------------------------------------------------------
signer = URLSafeSerializer(APP_SECRET, salt="student-cookie")
STUDENT_COOKIE = "cv_student"

def set_student_cookie(resp, student):
    token = signer.dumps({"id": student.id, "name": student.name})
    resp.set_cookie(STUDENT_COOKIE, token, max_age=60*60*24*365, httponly=True, samesite="Lax")
    return resp

def try_restore_student_from_cookie():
    if "student_id" in session:
        return
    token = request.cookies.get(STUDENT_COOKIE)
    if not token:
        return
    try:
        data = signer.loads(token)
    except Exception:
        return
    sid, name = data.get("id"), data.get("name")
    if not sid or not name:
        return
    stu = Student.query.get(sid)
    if not stu or stu.name != name:
        return
    session["student_id"] = stu.id
    session["student_name"] = stu.name
    session.permanent = True

@app.before_request
def _restore_student():
    try_restore_student_from_cookie()

# --------------------------------------------------------------------
# Login / Logout / First-login password set
# --------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard_for_role"))
    if current_student():
        return redirect(url_for("student_home"))

    error = None
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        email = (request.form.get("email") or "").strip().lower()
        pw    = request.form.get("password") or ""
        next_url = request.args.get("next") or url_for("index")

        acct_user = User.query.filter_by(email=email).first()
        acct_student = None if acct_user else Student.query.filter_by(email=email).first()

        if acct_user:
            if not acct_user.check_password(pw):
                error = "Invalid credentials"
            else:
                logout_everyone()
                session["user_id"] = acct_user.id
                session["user_role"] = acct_user.role
                acct_user.last_login = datetime.utcnow()
                db.session.commit()
                if acct_user.first_login:
                    session["must_change_pw"] = {"kind": "user", "id": acct_user.id}
                    return redirect(url_for("password_new"))
                return redirect(url_for("dashboard_for_role"))
        elif acct_student:
            if not acct_student.check_password(pw):
                error = "Invalid credentials"
            else:
                logout_everyone()
                session["student_id"] = acct_student.id
                session["student_name"] = acct_student.name
                acct_student.last_login = datetime.utcnow()
                db.session.commit()
                if acct_student.first_login:
                    session["must_change_pw"] = {"kind": "student", "id": acct_student.id}
                    return redirect(url_for("password_new"))
                return redirect(url_for("student_home"))
        else:
            error = "Account not found"

    return render_template("login.html", error=error, user=current_user(), student_name=session.get("student_name"))

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(STUDENT_COOKIE)
    logout_everyone()
    return resp

@app.route("/password/new", methods=["GET","POST"])
def password_new():
    must = session.get("must_change_pw")
    if not must and not (current_user() or current_student()):
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        pw1 = request.form.get("password1") or ""
        pw2 = request.form.get("password2") or ""
        if pw1 != pw2:
            error = "Passwords do not match"
        elif len(pw1) < 8:
            error = "Use at least 8 characters"
        else:
            if must:
                if must["kind"] == "user":
                    u = User.query.get(must["id"]);  assert u
                    u.set_password(pw1); u.first_login = False
                    db.session.commit()
                    session.pop("must_change_pw", None)
                    session["user_id"] = u.id; session["user_role"] = u.role
                    return redirect(url_for("dashboard_for_role"))
                else:
                    s = Student.query.get(must["id"]);  assert s
                    s.set_password(pw1); s.first_login = False
                    db.session.commit()
                    session.pop("must_change_pw", None)
                    session["student_id"] = s.id; session["student_name"] = s.name
                    return redirect(url_for("student_home"))
            else:
                acc = current_user() or current_student()
                acc.set_password(pw1); db.session.commit()
                return redirect(url_for("index"))

    return render_template("password_new.html", error=error, user=current_user(), student_name=session.get("student_name"))

# --------------------------------------------------------------------
# Home
# --------------------------------------------------------------------
@app.route("/")
def index():
    u = current_user()
    polls = Poll.query.order_by(Poll.created_at.desc()).all() if u else []
    return render_template("index.html", user=u, polls=polls, student_name=session.get("student_name"))

# --------------------------------------------------------------------
# Polls
# --------------------------------------------------------------------
def ensure_voter_cookie(resp=None):
    token = request.cookies.get("voter_id")
    if not token:
        token = secrets.token_hex(16)
        if resp is None:
            resp = make_response()
        resp.set_cookie("voter_id", token, max_age=60*60*24*365, httponly=False, samesite="Lax")
    return token, resp

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def gen_code(n=6):
    import string, random
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))

@app.route("/poll/new", methods=["GET","POST"])
@require_user()
def poll_new():
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        question = (request.form.get("question") or "").strip()
        options = [((request.form.get(f"opt{i}") or "").strip()) for i in range(1,9)]
        options = [o for o in options if o]
        correct_raw = request.form.get("correct")
        correct_index = int(correct_raw) if (correct_raw not in (None,"") and correct_raw.isdigit()) else None
        if not question or len(options) < 2:
            return render_template("poll_new.html", error="Enter a question and at least 2 options.", question=question, options=options, user=current_user())
        if correct_index is not None and (correct_index < 0 or correct_index >= len(options)):
            return render_template("poll_new.html", error="Correct answer index out of range.", question=question, options=options, user=current_user())
        code = gen_code()
        while Poll.query.filter_by(code=code).first() is not None:
            code = gen_code()
        p = Poll(code=code, question=question, options=options, correct_index=correct_index, creator_user_id=current_user().id if current_user() else None)
        db.session.add(p); db.session.commit()
        return redirect(url_for("share", code=p.code))
    return render_template("poll_new.html", user=current_user())

@app.route("/polls")
@require_user()
def poll_list():
    u = current_user()
    polls = Poll.query.order_by(Poll.created_at.desc()).all()
    return render_template("poll_list.html", polls=polls, user=u)

@app.route("/poll/<code>/edit", methods=["GET","POST"])
@require_user()
def poll_edit(code):
    p = Poll.query.filter_by(code=code).first_or_404()
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        question = (request.form.get("question") or "").strip()
        options = [((request.form.get(f"opt{i}") or "").strip()) for i in range(1,9)]
        options = [o for o in options if o]
        correct_raw = request.form.get("correct")
        correct_index = int(correct_raw) if (correct_raw not in (None,"") and correct_raw.isdigit()) else None
        if not question or len(options) < 2:
            return render_template("poll_edit.html", poll=p, error="Enter a question and at least 2 options.", user=current_user())
        # IMPORTANT: validate against the *new* options length
        if correct_index is not None and (correct_index < 0 or correct_index >= len(options)):
            return render_template("poll_edit.html", poll=p, error="Correct answer index out of range.", user=current_user())
        p.question, p.options, p.correct_index = question, options, correct_index
        db.session.commit()
        return redirect(url_for("poll_results", code=p.code))
    return render_template("poll_edit.html", poll=p, user=current_user())


@app.route("/poll/<code>/delete", methods=["POST"])
@require_user()
def poll_delete(code):
    if not verify_csrf(): abort(400, "bad csrf")
    p = Poll.query.filter_by(code=code).first_or_404()
    db.session.delete(p); db.session.commit()
    return redirect(url_for("poll_list"))

@app.route("/share/<code>")
@require_user()
def share(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    scheme = "https" if request.is_secure or request.headers.get("X-Forwarded-Proto","").lower()=="https" else "http"
    host = SHARE_HOST or request.host
    link = f"{scheme}://{host}{url_for('poll_view', code=poll.code)}"
    img = qrcode.make(link)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    return render_template("share.html", poll=poll, link=link, data_url=data_url, user=current_user(), student_name=session.get("student_name"))

@app.route("/poll/<code>", methods=["GET", "POST"])
def poll_view(code):
    poll = Poll.query.filter_by(code=code).first_or_404()

    if request.method == "POST" and not poll.is_open:
        return render_template("poll_view.html", poll=poll, error="Voting is closed.", already=False, user=current_user(), student_name=session.get("student_name"))

    if not session.get("student_id"):
        return redirect(url_for("login", next=url_for("poll_view", code=code)))

    if request.method == "POST" and not verify_csrf():
        abort(400, "bad csrf")

    token, _ = ensure_voter_cookie(None)

    if request.method == "POST":
        stu = current_student()

        # cookie- and account-level duplicate protection
        existing_cookie = Vote.query.filter_by(poll_id=poll.id, voter_token_hash=token_hash(token)).first()
        existing_student = Vote.query.filter_by(poll_id=poll.id, student_id=stu.id).first() if stu else None
        if existing_cookie or existing_student:
            return render_template("poll_view.html", poll=poll, already=True, user=current_user(), student_name=session.get("student_name"))

        try:
            choice = int(request.form.get("choice", "-1"))
        except Exception:
            choice = -1
        if choice < 0 or choice >= len(poll.options):
            return render_template("poll_view.html", poll=poll, error="Pick an option", user=current_user(), student_name=session.get("student_name"))

        v = Vote(
            poll_id=poll.id,
            choice=choice,
            voter_token_hash=token_hash(token),
            student_id=stu.id if stu else None,
            student_name=stu.name if stu else None,
        )
        db.session.add(v); db.session.commit()

        r = make_response(redirect(url_for("thanks")))
        _, r = ensure_voter_cookie(r)
        return r

    r = make_response(render_template("poll_view.html", poll=poll, already=False, user=current_user(), student_name=session.get("student_name")))
    _, r = ensure_voter_cookie(r)
    return r

@app.route("/poll/<code>/results")
@require_user()
def poll_results(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    counts = [0]*len(poll.options)
    correct = poll.correct_index
    rows = []
    for v in poll.votes:
        counts[v.choice] += 1
        is_correct = (correct is not None and v.choice == correct)
        rows.append(dict(name=v.student_name or "(anonymous)", choice=v.choice, when=v.created_at, correct=is_correct))
    total = sum(counts)
    accuracy = None
    if correct is not None and total:
        accuracy = sum(1 for r in rows if r["correct"]) / total
    return render_template("poll_results.html", poll=poll, counts=counts, rows=rows, total=total, accuracy=accuracy, user=current_user())

@app.route("/poll/<code>/set-correct", methods=["POST"])
@require_user()
def poll_set_correct(code):
    if not verify_csrf(): abort(400, "bad csrf")
    poll = Poll.query.filter_by(code=code).first_or_404()
    val = request.form.get("correct")
    idx = int(val) if val not in (None,"") and val.isdigit() else None
    if idx is not None and (idx < 0 or idx >= len(poll.options)):
        abort(400, "index out of range")
    poll.correct_index = idx
    db.session.commit()
    return redirect(url_for("poll_results", code=code))

@app.route("/api/poll/<code>/stats")
def poll_stats(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    counts = [0]*len(poll.options)
    for v in poll.votes:
        counts[v.choice] += 1
    return jsonify(dict(counts=counts, total=sum(counts), options=poll.options, question=poll.question, correct_index=poll.correct_index))

@app.route("/poll/<code>/open", methods=["POST"])
@require_user()
def poll_open(code):
    if not verify_csrf(): abort(400, "bad csrf")
    p = Poll.query.filter_by(code=code).first_or_404()
    p.is_open = True
    db.session.commit()
    return redirect(url_for("poll_results", code=code))

@app.route("/poll/<code>/close", methods=["POST"])
@require_user()
def poll_close(code):
    if not verify_csrf(): abort(400, "bad csrf")
    p = Poll.query.filter_by(code=code).first_or_404()
    p.is_open = False
    db.session.commit()
    return redirect(url_for("poll_results", code=code))

from flask import stream_with_context

@app.route("/poll/<code>/stream")
@require_user()
def poll_stream(code):
    @stream_with_context
    def generate():
        # Tell EventSource to retry after 3s if the connection drops
        yield "retry: 3000\n\n"
        last_blob = None
        try:
            while True:
                # Re-fetch each tick; never keep ORM instances across yields
                p = Poll.query.filter_by(code=code).first()
                if not p:
                    yield "event: end\ndata: {}\n\n"
                    return

                # Tally without touching lazy relationships
                counts = [0] * len(p.options)
                for v in Vote.query.filter_by(poll_id=p.id).all():
                    if 0 <= v.choice < len(counts):
                        counts[v.choice] += 1

                payload = {
                    "counts": counts,
                    "total": sum(counts),
                    "correct_index": p.correct_index,
                    "options": p.options,
                }
                blob = json.dumps(payload, separators=(",", ":"))

                if blob != last_blob:
                    yield f"data: {blob}\n\n"
                    last_blob = blob
                else:
                    # heartbeat so proxies don’t kill the stream
                    yield ": keep-alive\n\n"

                time.sleep(2.5)
        except GeneratorExit:
            # client disconnected; exit quietly
            return

    resp = Response(generate(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp

@app.route("/poll/<code>/qr.png")
@require_user()
def poll_qr_png(code):
    # If the QR must be viewable by students without logging in, keep this route public.
    # If you want it gated, add @require_user() above.
    poll_url = url_for("poll_view", code=code, _external=True)
    img = qrcode.make(poll_url, box_size=10, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png",
                     as_attachment=False,
                     download_name=f"{code}.png")

# --------------------------------------------------------------------
# Spotlight
# --------------------------------------------------------------------


# ---------- Fairness helper ----------
def _eligible_students(section=None):
    # Basic: use all students; optionally filter by section if you store it on Student
    q = Student.query
    if section:
        # If you have Student.section, uncomment:
        # q = q.filter_by(section=section)
        pass
    students = q.all()

    # Partition by current_round_done
    stats_map = {s.student_id: s for s in StudentStats.query.filter(StudentStats.student_id.in_([st.id for st in students])).all()}
    pool = []
    for st in students:
        st_stats = stats_map.get(st.id)
        done = bool(st_stats.current_round_done) if st_stats else False
        if not done:
            pool.append((st, st_stats))
    if not pool:
        # Reset round
        for st in students:
            st_stats = stats_map.get(st.id)
            if st_stats:
                st_stats.current_round_done = False
            else:
                db.session.add(StudentStats(student_id=st.id, current_round_done=False))
        db.session.commit()
        pool = [(st, stats_map.get(st.id)) for st in students]

    # Weighted random: weight = 1 / (1 + times_spoken)
    choices = []
    weights = []
    for st, st_stats in pool:
        ts = (st_stats.times_spoken if st_stats else 0)
        w = 1.0 / (1 + ts)
        choices.append((st, st_stats))
        weights.append(w)
    # Normalize weights
    total_w = sum(weights)
    if total_w <= 0:
        weights = [1.0 for _ in weights]
        total_w = sum(weights)
    probs = [w/total_w for w in weights]
    pick_idx = random.choices(range(len(choices)), weights=probs, k=1)[0]
    return choices[pick_idx][0]  # return Student
# -------------------------------------

# ---------- Page ----------
@app.route("/spotlight")
@require_user()
def spotlight_page():
    return render_template("spotlight.html",
                           default_duration=120,
                           user=current_user(),
                           student_name=session.get("student_name"))

# ---------- Get candidate names (for UI display) ----------
@app.route("/api/spotlight/candidates")
@require_user()
def spotlight_candidates():
    section = request.args.get("section") or None
    q = Student.query
    # if using sections on Student, filter here
    names = [s.name or s.email for s in q.order_by(Student.name.asc()).all()]
    return jsonify({"items": names})

# ---------- Pick (server is source of truth) ----------
@app.route("/api/spotlight/pick", methods=["POST"])
@require_user()
def spotlight_pick():
    token = request.headers.get("X-CSRF","")
    if not hmac.compare_digest(token, csrf_token()): abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    section = data.get("section")
    duration = int(data.get("duration_sec") or 120)

    st = _eligible_students(section=section)
    iv = Intervention(student_id=st.id, student_name=(st.name or st.email),
                      section=section, duration_sec=duration, status="picked")
    db.session.add(iv); db.session.commit()
    return jsonify({"intervention_id": iv.id, "student": {"id": st.id, "name": iv.student_name}, "duration_sec": duration})

# ---------- Start timer ----------
@app.route("/api/spotlight/start", methods=["POST"])
@require_user()
def spotlight_start():
    token = request.headers.get("X-CSRF","")
    if not hmac.compare_digest(token, csrf_token()): abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    iv = Intervention.query.get_or_404(int(data.get("intervention_id")))
    if iv.status not in ("picked","running"):
        return jsonify({"ok": False, "error": "bad_state"}), 400
    if not iv.started_at:
        iv.started_at = datetime.utcnow()
    iv.status = "running"
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/spotlight/complete", methods=["POST"])
@require_user()
def spotlight_complete():
    token = request.headers.get("X-CSRF","")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    data = request.get_json(silent=True) or {}
    iv = Intervention.query.get_or_404(int(data.get("intervention_id")))
    if iv.status not in ("picked","running"):
        return jsonify({"ok": False, "error": "bad_state"}), 400

    iv.ended_at = datetime.utcnow()
    iv.status = "completed"

    # Update StudentStats
    ss = StudentStats.query.filter_by(student_id=iv.student_id).first()
    if not ss:
        ss = StudentStats(student_id=iv.student_id, times_spoken=0, current_round_done=False)
        db.session.add(ss)
    ss.times_spoken += 1
    ss.last_spoken_at = datetime.utcnow()
    ss.current_round_done = True

    # Create peer-feedback poll (no correct answer)
    question = f"How did {iv.student_name} do?"
    options = ["Excellent", "Good", "Okay", "Needs improvement"]

    # Use your existing code generator, ensure uniqueness
    code = gen_code()
    while Poll.query.filter_by(code=code).first() is not None:
        code = gen_code()

    p = Poll(code=code, question=question, options=options, correct_index=None, is_open=True)
    db.session.add(p)
    db.session.commit()

    iv.poll_id = p.id
    db.session.commit()

    return jsonify({
        "ok": True,
        "poll_code": p.code,
        "poll_url": url_for("poll_view", code=p.code),
        "qr_url": url_for("share", code=p.code)  # or your QR page if different
    })

# ---------- Skip (no stats) ----------
@app.route("/api/spotlight/skip", methods=["POST"])
@require_user()
def spotlight_skip():
    token = request.headers.get("X-CSRF","")
    if not hmac.compare_digest(token, csrf_token()): abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    iv = Intervention.query.get_or_404(int(data.get("intervention_id")))
    iv.status = "skipped"
    db.session.commit()
    return jsonify({"ok": True})

# --------------------------------------------------------------------
# Forms (SurveyJS)
# --------------------------------------------------------------------
@app.route("/forms")
@require_user()
def forms_list():
    forms = Form.query.order_by(Form.created_at.desc()).all()
    return render_template("forms_list.html", forms=forms, user=current_user(), student_name=session.get("student_name"))

@app.route("/forms/new", methods=["GET", "POST"])
@require_user()
def forms_new():
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        title = (request.form.get("title") or "").strip()
        schema_text = request.form.get("schema_json") or ""
        closes_at = parse_dt_local(request.form.get("closes_at"))
        if not title or not schema_text:
            return render_template("forms_new.html", error="Title and JSON are required.",
                                   schema_json=schema_text, user=current_user(),
                                   student_name=session.get("student_name"))
        try:
            schema = json.loads(schema_text)
        except Exception as e:
            return render_template("forms_new.html", error=f"Invalid JSON: {e}",
                                   schema_json=schema_text, user=current_user(),
                                   student_name=session.get("student_name"))
        code = gen_code()
        while Form.query.filter_by(code=code).first() is not None:
            code = gen_code()
        f = Form(code=code, title=title, schema_json=schema,
                 creator_user_id=current_user().id, closes_at=closes_at)
        db.session.add(f); db.session.commit()
        return redirect(url_for("forms_results", code=f.code))
    return render_template("forms_new.html", schema_json="", user=current_user(),
                           student_name=session.get("student_name"))

@app.route("/f/<code>")
def form_render(code):
    form = Form.query.filter_by(code=code).first_or_404()
    now = datetime.utcnow()
    is_expired = bool(form.closes_at and form.closes_at <= now)
    is_open = bool(form.is_open and not is_expired)
    if not is_open:
        return render_template(
            "form_closed.html",
            form=form,
            user=current_user(),
            student_name=session.get("student_name"),
        ), 403
    u = current_user()
    s = current_student()

    # Require someone authenticated
    if not (u or s):
        return redirect(url_for("login", next=url_for("form_render", code=code)))

    # Find an existing submission if student
    submitted = False
    submitted_payload = None
    if s:
        existing = FormResponse.query.filter_by(form_id=form.id, student_id=s.id)\
                                     .order_by(FormResponse.id.desc()).first()
        if existing:
            # existing.payload_json may already be a dict; if it's a string, parse it
            pj = existing.payload_json
            if isinstance(pj, str):
                try:
                    import json as _json
                    pj = _json.loads(pj)
                except Exception:
                    pj = {}
            submitted = True
            submitted_payload = pj

    # Students cannot open closed forms (unless you prefer to show "closed" page)
    if s and not form.is_open:
        return render_template("form_closed.html", form=form,
                               user=u, student_name=session.get("student_name"))

    # Only students can submit; instructors/admins are always preview
    can_submit = bool(s and form.is_open and not submitted)

    return render_template(
        "form_render.html",
        form=form,
        can_submit=can_submit,
        submitted=submitted,
        submitted_payload=submitted_payload or {},
        user=u,
        student_name=session.get("student_name"),
    )


@app.post("/forms/<code>/open")
@require_user()
def forms_open(code):
    token = request.form.get("csrf","")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    f = Form.query.filter_by(code=code).first_or_404()
    f.is_open = True
    db.session.commit()
    # optional: flash("Form opened.")
    return redirect(url_for("forms_list"))

@app.post("/forms/<code>/close")
@require_user()
def forms_close(code):
    token = request.form.get("csrf","")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    f = Form.query.filter_by(code=code).first_or_404()
    f.is_open = False
    db.session.commit()
    # optional: flash("Form closed.")
    return redirect(url_for("forms_list"))


@app.route("/api/forms/<code>/responses", methods=["POST"])
def form_submit(code):
    form = Form.query.filter_by(code=code).first_or_404()
    
    now = datetime.utcnow()
    if not form.is_open or (form.closes_at and form.closes_at <= now):
        abort(403, description="Form is closed.")
    # Only students can submit
    stu = current_student()
    if not stu:
        abort(401)

    # Must be open for students
    if not form.is_open:
        abort(403, description="Form is closed")

    # CSRF header check
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    # Enforce single submission per student per form
    existing = FormResponse.query.filter_by(form_id=form.id, student_id=stu.id).first()
    if existing:
        return jsonify({"ok": False, "error": "already_submitted"}), 409

    data = request.get_json(silent=True) or {}
    resp = FormResponse(
        form_id=form.id,
        student_id=stu.id,
        student_name=stu.name,
        payload_json=data,
    )
    db.session.add(resp)
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/forms/<code>/qr")
@require_user()  # instructors/admins only
def forms_qr_page(code):
    form = Form.query.filter_by(code=code).first_or_404()
    form_url = request.url_root.rstrip("/") + url_for("form_render", code=form.code)
    return render_template(
        "forms_qr.html",
        form=form,
        form_url=form_url,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/forms/<code>/qr.png")
@require_user()
def forms_qr_png(code):
    form = Form.query.filter_by(code=code).first_or_404()
    target = request.url_root.rstrip("/") + url_for("form_render", code=form.code)

    qr = qrcode.QRCode(
        version=None,  # auto
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,    # tweak for print size
        border=2,
    )
    qr.add_data(target)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png",
                     as_attachment=False,
                     download_name=f"{form.code}.png")


@app.route("/forms/<code>/results")
@require_user()
def forms_results(code):
    form = Form.query.filter_by(code=code).first_or_404()
    rows = [{"name": r.student_name or "(anonymous)", "when": r.created_at, "payload": r.payload_json} for r in form.responses]
    return render_template("forms_results.html", form=form, rows=rows, user=current_user(), student_name=session.get("student_name"))

# --------------------------------------------------------------------
# Lecture interaction dashboard
# --------------------------------------------------------------------

from datetime import datetime, timedelta
from flask import Response, jsonify, render_template, request, abort
import json, time, hmac, hashlib

# ---------- Instructor dashboard page ----------
@app.route("/signals")
@require_user()  # instructor/admin only
def signals_dashboard():
    # how far back the “live” counts look (rolling window)
    window_min = 5
    return render_template(
        "signals.html",
        window_min=window_min,
        user=current_user(),
        student_name=session.get("student_name"),
    )

# ---------- SSE: live counts for OK/Confused + unseen questions count ----------
@app.route("/api/signals/stream")
@require_user()
def signals_stream():
    from models import LectureSignal, LectureQuestion  # avoid circulars

    @stream_with_context
    def generate():
        yield "retry: 3000\n\n"  # polite reconnect hint
        last_blob = None
        try:
            while True:
                now = datetime.utcnow()
                since = now - timedelta(minutes=5)
                ok = LectureSignal.query.filter(
                    LectureSignal.created_at >= since,
                    LectureSignal.kind == "ok"
                ).count()
                confused = LectureSignal.query.filter(
                    LectureSignal.created_at >= since,
                    LectureSignal.kind == "confused"
                ).count()
                unread_q = LectureQuestion.query.filter_by(handled=False).count()

                payload = {"ok": ok, "confused": confused, "unread_questions": unread_q, "window_min": 5}
                blob = json.dumps(payload, separators=(",", ":"))
                if blob != last_blob:
                    yield f"data: {blob}\n\n"
                    last_blob = blob
                else:
                    yield ": keep-alive\n\n"
                time.sleep(2.5)
        except GeneratorExit:
            return

    resp = Response(generate(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp

# ---------- List questions (latest first), optional filters ----------
@app.route("/api/questions", methods=["GET"])
@require_user()
def questions_list():
    from models import LectureQuestion
    only_unhandled = (request.args.get("state") == "open")
    q = LectureQuestion.query
    if only_unhandled:
        q = q.filter_by(handled=False)
    q = q.order_by(LectureQuestion.id.desc()).limit(100)
    items = [{
        "id": it.id,
        "student_name": it.student_name or "",
        "text": it.text,
        "handled": bool(it.handled),
        "when": it.created_at.isoformat(timespec="seconds") + "Z"
    } for it in q.all()]
    return jsonify({"items": items})

# ---------- Mark one question handled/unhandled ----------
@app.route("/api/questions/<int:q_id>/handled", methods=["POST"])
@require_user()
def question_mark_handled(q_id):
    from models import LectureQuestion, db
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    body = request.get_json(silent=True) or {}
    handled = bool(body.get("handled", True))
    it = LectureQuestion.query.get_or_404(q_id)
    it.handled = handled
    db.session.commit()
    return jsonify({"ok": True, "id": it.id, "handled": it.handled})

# ---------- (Optional) Clear signals window (use sparingly) ----------
@app.route("/api/signals/clear", methods=["POST"])
@require_user()
def signals_clear():
    from models import LectureSignal, db
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    # delete older-than-window to “reset” live meters
    LectureSignal.query.filter(LectureSignal.created_at < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({"ok": True})

# --------------------------------------------------------------------
# Lecture interaction
# --------------------------------------------------------------------
@app.route("/api/signal", methods=["POST"])
def signal_post():
    # Students only
    stu = current_student()
    if not stu:
        abort(401)
    # CSRF
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "").lower()
    if kind not in ("ok", "confused"):
        abort(400, "bad kind")

    s = LectureSignal(student_id=stu.id, student_name=stu.name, kind=kind)
    db.session.add(s); db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/question", methods=["POST"])
def question_post():
    # Students only
    stu = current_student()
    if not stu:
        abort(401)
    # CSRF
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        abort(400, "empty")

    # Optional: simple per-student throttle (1 question / 60s)
    recent = LectureQuestion.query.filter(
        LectureQuestion.student_id == stu.id,
        LectureQuestion.created_at >= datetime.utcnow() - timedelta(seconds=60)
    ).first()
    if recent:
        return jsonify({"ok": False, "error": "rate_limited"}), 429

    q = LectureQuestion(student_id=stu.id, student_name=stu.name, text=text)
    db.session.add(q); db.session.commit()
    return jsonify({"ok": True})

# --------------------------------------------------------------------
# Learning Outcomes
# --------------------------------------------------------------------

@app.route("/admin/learning-outcomes")
@require_user(("ADMIN", "MENTOR"))   # if you didn't update require_user yet, temporarily use @require_user("ADMIN")
def admin_lo_list():
    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 20) or 20), 5), 100)

    query = LearningOutcome.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                LearningOutcome.code.like(like),
                LearningOutcome.title.like(like),
            )
        )

    total = query.count()
    items = (query
             .order_by(LearningOutcome.code.asc())
             .limit(per_page)
             .offset((page - 1) * per_page)
             .all())

    last_page = max((total + per_page - 1) // per_page, 1)
    has_prev = page > 1
    has_next = page < last_page

    return render_template(
        "learning_outcomes_list.html",
        items=items, total=total, page=page, per_page=per_page,
        last_page=last_page, has_prev=has_prev, has_next=has_next, q=q
    )

@app.route("/admin/learning-outcomes/new", methods=["GET", "POST"])
@require_user(("ADMIN", "MENTOR"))
def admin_lo_create():
    errors = {}
    code = (request.form.get("code") or "").strip()
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()

    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")

        # server-side validation
        if not code or len(code) > 32:
            errors["code"] = "Code is required (≤ 32 chars)."
        if not title or len(title) > 255:
            errors["title"] = "Title is required (≤ 255 chars)."

        if not errors:
            lo = LearningOutcome(
                code=code,
                title=title,
                description=description or None,
                creator_user_id=current_user().id if current_user() else None,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.session.add(lo)
            try:
                db.session.commit()
                # success → back to list (preserve search if present)
                dest = url_for("admin_lo_list", q=request.args.get("q") or None)
                return redirect(dest)
            except IntegrityError:
                db.session.rollback()
                errors["code"] = "This code already exists."

    return render_template(
        "learning_outcomes_new.html",
        code=code, title=title, description=description, errors=errors
    )


# --------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------

def build_config_from_form(type_val: str, form) -> dict:
    """Turn typed form inputs into a normalized config dict."""
    schema = TASK_CONFIG_SCHEMAS.get(type_val, {})
    fields = schema.get("fields", [])
    cfg = {}

    # simple helpers
    def _csv(s): return [x.strip() for x in (s or "").split(",") if x.strip()]
    def _int(name, default=None):
        raw = form.get(name, "")
        if raw == "" and default is not None:
            return default
        return int(raw)

    for f in fields:
        k = f["key"]; t = f["type"]
        if t == "checkbox":
            cfg[k] = (form.get(k) == "on")
        elif t == "number":
            val = form.get(k)
            cfg[k] = int(val) if val not in (None, "") else f.get("default")
        elif t in ("text", "textarea"):
            cfg[k] = form.get(k, f.get("default", ""))

        elif t == "select":
            v = form.get(k, f.get("default"))
            if "choices" in f and v not in f["choices"]:
                v = f.get("default")
            cfg[k] = v

    # Post-process per type
    if type_val == "CODE":
        if cfg.get("allowed_imports"):
            cfg["allowed_imports"] = _csv(cfg["allowed_imports"])
    elif type_val == "MCQ":
        # options_raw → [{"id":"A","text":"..."}, ...]
        lines = [ln.strip() for ln in (cfg.get("options_raw") or "").splitlines() if ln.strip()]
        options = []
        auto_ids = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        n = 0
        for ln in lines:
            opt_id, text = None, ln
            # Accept "A) ..." or "A. ..." or "A - ..." patterns
            if len(ln) >= 3 and ln[1] in ").-" and ln[0].isalpha():
                opt_id, text = ln[0].upper(), ln[3:].strip()
            else:
                opt_id, text = auto_ids[n], ln
            options.append({"id": opt_id, "text": text})
            n += 1
        cfg["options"] = options
        cfg["correct"] = [cid.strip().upper() for cid in _csv(cfg.get("correct_ids", ""))]
        # cleanup raw helpers
        cfg.pop("options_raw", None)
        cfg.pop("correct_ids", None)
    elif type_val == "TEXT":
        cfg["min_words"] = _int("min_words", 0)
        cfg["max_words"] = _int("max_words", 0)
        cfg["keywords"] = _csv(cfg.get("keywords_csv", ""))
        cfg.pop("keywords_csv", None)
    elif type_val == "REFLECTION":
        cfg["min_words"] = _int("min_words", 0)
        cfg["max_words"] = _int("max_words", 0)
    elif type_val == "VISIT":
        cfg["min_seconds"] = _int("min_seconds", 0)
    elif type_val == "FILE_UPLOAD":
        cfg["max_bytes"] = _int("max_bytes", 0)
        if cfg.get("allowed_mime"):
            cfg["allowed_mime"] = _csv(cfg["allowed_mime"])
    return cfg


@app.route("/admin/tasks")
@require_user(("ADMIN", "MENTOR"))
def admin_task_list():
    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 20) or 20), 5), 100)
    quest_id = request.args.get("quest_id")
    type_filter = (request.args.get("type") or "").strip()

    query = Task.query.join(Quest, Task.quest_id == Quest.id, isouter=True)

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.slug.like(like), Task.title.like(like)))
    if quest_id and quest_id.isdigit():
        query = query.filter(Task.quest_id == int(quest_id))
    if type_filter:
        query = query.filter(Task.type == type_filter)

    total = query.count()
    items = (query
             .order_by(Quest.code.asc(), Task.order_in_quest.asc())
             .limit(per_page)
             .offset((page - 1) * per_page)
             .all())

    last_page = max((total + per_page - 1) // per_page, 1)
    has_prev = page > 1
    has_next = page < last_page

    # for filters
    quests = Quest.query.order_by(Quest.code.asc()).all()
    quest_map = {q.id: q for q in quests} 
    types = list(Task.type.type.enums)  # ["CODE","MCQ",...]

    return render_template(
        "tasks_list.html",
        items=items, total=total, page=page, per_page=per_page,
        last_page=last_page, has_prev=has_prev, has_next=has_next, q=q,
        quests=quests, quest_id=quest_id, types=types, type_filter=type_filter,
        quest_map=quest_map
    )

@app.route("/admin/tasks/new", methods=["GET", "POST"])
@require_user(("ADMIN", "MENTOR"))
def admin_task_create():
    errors = {}
    # form fields
    quest_id  = (request.form.get("quest_id") or "").strip()
    slug      = (request.form.get("slug") or "").strip()
    title     = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    type_val  = (request.form.get("type") or "").strip()
    xp        = request.form.get("xp") or "10"
    stars     = request.form.get("stars") or "10"
    difficulty= (request.form.get("difficulty") or "").strip()
    must_pass = True if request.form.get("must_pass") == "on" else False
    min_score_to_pass = request.form.get("min_score_to_pass") or "1.00"
    order_in_quest    = request.form.get("order_in_quest") or "1"
    lo_ids    = request.form.getlist("lo_ids")               # optional LO mapping
    selected_prereqs = request.form.getlist("prereq_task_ids")  # same-quest prereqs

    # for selects
    quests = Quest.query.order_by(Quest.code.asc()).all()
    types  = list(Task.type.type.enums)  # ["CODE","MCQ","TEXT","REFLECTION","VISIT","FILE_UPLOAD"]
    los    = LearningOutcome.query.order_by(LearningOutcome.code.asc()).all()
    schemas = TASK_CONFIG_SCHEMAS

    # possible prereqs depend on selected quest
    possible_prereqs = []
    if quest_id.isdigit():
        possible_prereqs = (Task.query
            .filter(Task.quest_id == int(quest_id))
            .order_by(Task.order_in_quest.asc(), Task.slug.asc())
            .all())

    # POST: validate + create
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")

        if request.form.get("preview") == "1":
        # Do NOT validate or persist; just re-render with the new type/prereqs
            return render_template(
                "tasks_new.html",
                errors={},  # no errors on preview
                quests=quests, types=types, los=los, schemas=schemas,
                possible_prereqs=possible_prereqs,
                selected_prereqs=request.form.getlist("prereq_task_ids"),
                quest_id=quest_id, slug=slug, title=title, description=description,
                type_val=type_val, xp=xp, stars=stars, difficulty=difficulty,
                must_pass=must_pass, min_score_to_pass=min_score_to_pass,
                order_in_quest=order_in_quest, lo_ids=lo_ids
            )
        # Basic validation
        if not quest_id.isdigit():
            errors["quest_id"] = "Select a quest."
        if not slug or len(slug) > 64:
            errors["slug"] = "Slug is required (≤ 64 chars)."
        if not title or len(title) > 255:
            errors["title"] = "Title is required (≤ 255 chars)."
        if type_val not in types:
            errors["type"] = "Invalid type."

        # Numeric fields
        try:
            xp_i = max(0, int(xp))
        except Exception:
            errors["xp"] = "XP must be a non-negative integer."
        try:
            stars_i = max(0, int(stars))
        except Exception:
            errors["stars"] = "Stars must be a non-negative integer."
        try:
            diff_i = int(difficulty) if difficulty else None
            if diff_i is not None and not (1 <= diff_i <= 5):
                raise ValueError
        except Exception:
            errors["difficulty"] = "Difficulty must be 1..5 or blank."
        try:
            order_i = max(1, int(order_in_quest))
        except Exception:
            errors["order_in_quest"] = "Order must be a positive integer."
        try:
            msp = float(min_score_to_pass)
            if not (0.0 <= msp <= 1.0):
                raise ValueError
        except Exception:
            errors["min_score_to_pass"] = "Threshold must be between 0.0 and 1.0."

        # Build config dict from typed schema fields (no raw JSON)
        config_obj = {}
        if type_val:
            try:
                config_obj = build_config_from_form(type_val, request.form)
            except Exception:
                errors["config"] = "Could not parse configuration inputs."

        if not errors:
            t = Task(
                quest_id=int(quest_id),
                slug=slug,
                title=title,
                description=description or None,
                type=type_val,
                xp=xp_i,
                stars=stars_i,
                difficulty=diff_i,
                must_pass=must_pass,
                min_score_to_pass=msp,
                order_in_quest=order_i,
                creator_user_id=current_user().id if current_user() else None,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                config=config_obj,
            )
            db.session.add(t)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                # unique (quest_id, slug)
                errors["slug"] = "This slug already exists in the selected quest."

            if not errors:
                # Link learning outcomes (optional)
                for lo_id in lo_ids:
                    if lo_id.isdigit():
                        db.session.add(TaskOutcome(task_id=t.id, lo_id=int(lo_id), weight=1))

                # Validate & insert same-quest prerequisites
                valid_ids = []
                if selected_prereqs:
                    rows = (Task.query.with_entities(Task.id)
                            .filter(Task.quest_id == t.quest_id,
                                    Task.id.in_([int(x) for x in selected_prereqs if x.isdigit()]))
                            .all())
                    valid_ids = [row.id for row in rows]

                for pid in valid_ids:
                    if pid != t.id:  # guard (shouldn't happen at create)
                        db.session.add(TaskPrereq(task_id=t.id, prereq_task_id=pid))

                db.session.commit()
                return redirect(url_for("admin_task_list", quest_id=t.quest_id))

    # GET or validation errors → re-render form
    return render_template(
        "tasks_new.html",
        errors=errors,
        quests=quests, types=types, los=los, schemas=schemas,
        possible_prereqs=possible_prereqs, selected_prereqs=selected_prereqs,
        quest_id=quest_id, slug=slug, title=title, description=description,
        type_val=type_val, xp=xp, stars=stars, difficulty=difficulty,
        must_pass=must_pass, min_score_to_pass=min_score_to_pass,
        order_in_quest=order_in_quest, lo_ids=lo_ids
    )

@app.route("/tasks/<int:task_id>")
def task_view(task_id: int):
    # TODO: gate by @require_student() when you hook auth
    task = Task.query.get_or_404(task_id)
    quest = Quest.query.get(task.quest_id) if task.quest_id else None

    # learning outcomes for header chips
    from models import TaskOutcome, LearningOutcome
    lo_ids = db.session.query(TaskOutcome.lo_id).filter(TaskOutcome.task_id == task.id).all()
    los = []
    if lo_ids:
        ids = [x[0] for x in lo_ids]
        los = LearningOutcome.query.filter(LearningOutcome.id.in_(ids)).all()

    return render_template("tasks/show.html", task=task, quest=quest, learning_outcomes=los)

@app.route("/tasks/<int:task_id>/submit", methods=["POST"])
def task_submit(task_id: int):
    # POC: trusts client-provided score; do not use in production
    if not verify_csrf(): abort(400, "bad csrf")
    task = Task.query.get_or_404(task_id)

    from models import Submission, StudentTaskGrade  # if using student auth, pull current student
    # For the POC, let’s store under a synthetic student (id=1) or skip if you already have require_student
    student_id = session.get("student_id") or 1

    code = (request.form.get("code") or "")
    lang = (request.form.get("language") or "python")
    try:
        score = float(request.form.get("score") or "0")
    except Exception:
        score = 0.0

    sub = Submission(
        task_id=task.id, student_id=student_id, status="PASSED" if score >= float(task.min_score_to_pass) else "FAILED",
        score=score, payload={"code": code, "language": lang}
    )
    db.session.add(sub)
    db.session.commit()
    # redirect back to task view
    return redirect(url_for("task_view", task_id=task.id))


# --------------------------------------------------------------------
# Quests
# --------------------------------------------------------------------

QUEST_COMPLETION_SCHEMA = {
    "fields": [
        {"key": "mode", "label": "Completion mode", "type": "select",
         "choices": ["ALL_REQUIRED_TASKS", "AT_LEAST_K_TASKS", "AT_LEAST_XP", "AT_LEAST_STARS"],
         "default": "ALL_REQUIRED_TASKS"},
        {"key": "k", "label": "K (tasks to pass) — used with AT_LEAST_K_TASKS", "type": "number", "min": 0, "default": 0},
        {"key": "xp", "label": "XP threshold — used with AT_LEAST_XP", "type": "number", "min": 0, "default": 0},
        {"key": "stars", "label": "Stars threshold — used with AT_LEAST_STARS", "type": "number", "min": 0, "default": 0},
        {"key": "must_pass_by_default", "label": "Tasks required by default", "type": "checkbox", "default": True},
    ]
}

def build_quest_completion_from_form(form) -> dict:
    cfg = {}
    schema = QUEST_COMPLETION_SCHEMA["fields"]
    for f in schema:
        k = f["key"]; t = f["type"]
        if t == "checkbox":
            cfg[k] = (form.get(k) == "on")
        elif t == "number":
            raw = form.get(k)
            cfg[k] = int(raw) if raw not in (None, "") else f.get("default", 0)
        elif t == "select":
            v = form.get(k, f.get("default"))
            if v not in f["choices"]:
                v = f.get("default")
            cfg[k] = v
    return cfg

@app.route("/admin/quests")
@require_user(("ADMIN", "MENTOR"))
def admin_quest_list():
    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 20) or 20), 5), 100)
    published = request.args.get("published")  # "", "1", "0"
    optional = request.args.get("optional")    # "", "1", "0"

    query = Quest.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Quest.code.like(like), Quest.title.like(like)))
    if published in ("0", "1"):
        query = query.filter(Quest.published == (published == "1"))
    if optional in ("0", "1"):
        query = query.filter(Quest.is_optional == (optional == "1"))

    total = query.count()
    items = (query.order_by(Quest.code.asc())
                  .limit(per_page).offset((page - 1) * per_page).all())

    last_page = max((total + per_page - 1) // per_page, 1)
    has_prev = page > 1
    has_next = page < last_page

    return render_template(
        "quests_list.html",
        items=items, total=total, page=page, per_page=per_page, last_page=last_page,
        has_prev=has_prev, has_next=has_next, q=q, published=published, optional=optional
    )

@app.route("/admin/quests/new", methods=["GET", "POST"])
@require_user(("ADMIN", "MENTOR"))
def admin_quest_create():
    errors = {}
    # form fields
    code = (request.form.get("code") or "").strip()
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    xp = request.form.get("xp") or "10"
    stars = request.form.get("stars") or "10"
    difficulty = (request.form.get("difficulty") or "").strip()
    is_optional = (request.form.get("is_optional") == "on")
    published = (request.form.get("published") == "on")
    starts_at = (request.form.get("starts_at") or "").strip()
    due_at = (request.form.get("due_at") or "").strip()

    # mappings
    lo_ids = request.form.getlist("lo_ids")
    prereq_ids = request.form.getlist("prereq_quest_ids")  # quest prereqs (AND)

    los = LearningOutcome.query.order_by(LearningOutcome.code.asc()).all()
    # possible prereqs = all existing quests
    possible_prereqs = Quest.query.order_by(Quest.code.asc()).all()

    # completion config
    completion_schema = QUEST_COMPLETION_SCHEMA
    completion_cfg = build_quest_completion_from_form(request.form) if request.method == "POST" else None

    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")

        if not code or len(code) > 64:
            errors["code"] = "Code is required (≤ 64 chars)."
        if not title or len(title) > 255:
            errors["title"] = "Title is required (≤ 255 chars)."

        # ints
        try:
            xp_i = max(0, int(xp))
        except Exception:
            errors["xp"] = "XP must be a non-negative integer."
        try:
            stars_i = max(0, int(stars))
        except Exception:
            errors["stars"] = "Stars must be a non-negative integer."
        try:
            diff_i = int(difficulty) if difficulty else None
            if diff_i is not None and not (1 <= diff_i <= 5):
                raise ValueError
        except Exception:
            errors["difficulty"] = "Difficulty must be 1..5 or blank."

        # dates (HTML datetime-local gives 'YYYY-MM-DDTHH:MM')
        def _parse_dt(s):
            if not s: return None
            try:
                return datetime.fromisoformat(s)
            except Exception:
                return None
        starts_dt = _parse_dt(starts_at)
        due_dt = _parse_dt(due_at)

        if not errors:
            qobj = Quest(
                code=code,
                title=title,
                description=description or None,
                xp=xp_i, stars=stars_i, difficulty=diff_i,
                is_optional=is_optional, published=published,
                starts_at=starts_dt, due_at=due_dt,
                completion=completion_cfg or {"mode": "ALL_REQUIRED_TASKS"},
                creator_user_id=current_user().id if current_user() else None,
                created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
            )
            db.session.add(qobj)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                errors["code"] = "This code already exists."

            if not errors:
                # link LOs
                for lo_id in lo_ids:
                    if lo_id.isdigit():
                        db.session.add(QuestOutcome(quest_id=qobj.id, lo_id=int(lo_id), weight=1))
                # link prerequisites (AND semantics; groups later if needed)
                valid_preq = [int(x) for x in prereq_ids if x.isdigit()]
                for pid in valid_preq:
                    if pid != qobj.id:  # guard, though it can't equal at creation time
                        db.session.add(QuestPrereq(quest_id=qobj.id, prereq_quest_id=pid))
                db.session.commit()
                return redirect(url_for("admin_quest_list"))

    return render_template(
        "quests_new.html",
        errors=errors,
        code=code, title=title, description=description,
        xp=xp, stars=stars, difficulty=difficulty,
        is_optional=is_optional, published=published,
        starts_at=starts_at, due_at=due_at,
        los=los, possible_prereqs=possible_prereqs,
        completion_schema=completion_schema
    )




# --------------------------------------------------------------------
# Exports / landing routes
# --------------------------------------------------------------------
@app.route("/export/<code>.csv")
@require_user()
def export_csv(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["poll_code","question","student_name","choice_index","choice_text","correct","timestamp"])
    for v in poll.votes:
        choice_text = poll.options[v.choice] if 0 <= v.choice < len(poll.options) else ""
        correct = (poll.correct_index is not None and v.choice == poll.correct_index)
        w.writerow([poll.code, poll.question, v.student_name or "", v.choice, choice_text, int(correct), v.created_at.isoformat()])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=f"{poll.code}.csv")

@app.route("/thanks")
def thanks():
    return render_template("thanks.html", user=current_user(), student_name=session.get("student_name"))

@app.route("/dashboard")
@require_user()
def dashboard_for_role():
    return redirect(url_for("poll_list"))

@app.route("/student")
@require_student()
def student_home():
    return redirect(url_for("index"))

# --------------------------------------------------------------------
# Dev entry
# --------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
