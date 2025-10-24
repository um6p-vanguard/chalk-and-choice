import os, io, base64, secrets, argparse, csv, functools, time, json, hmac, hashlib
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer

from models import db, Poll, Vote, Student, User, Form, FormResponse, LectureQuestion, LectureSignal
import qrcode

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
            if role and u.role != role:
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
        last = None
        while True:
            # Re-fetch on each tick to avoid detached objects
            p = Poll.query.filter_by(code=code).first()
            if not p:
                # End the stream if poll was deleted
                yield "event: end\ndata: {}\n\n"
                return

            # Compute counts without touching p.votes relationship
            counts = [0] * len(p.options)
            for v in Vote.query.filter_by(poll_id=p.id).all():
                # Guard in case an out-of-range choice slipped in
                if 0 <= v.choice < len(counts):
                    counts[v.choice] += 1

            payload = {
                "counts": counts,
                "total": sum(counts),
                "correct_index": p.correct_index,
                "options": p.options,
            }
            blob = json.dumps(payload, separators=(",", ":"))
            if blob != last:
                yield f"data: {blob}\n\n"
                last = blob
            else:
                # heartbeat so proxies don't kill the connection
                yield ": keep-alive\n\n"

            time.sleep(2.5)

    # Helpful SSE headers
    resp = Response(generate(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # if ever behind a proxy that buffers
    return resp


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


@app.route("/api/forms/<code>/responses", methods=["POST"])
def form_submit(code):
    form = Form.query.filter_by(code=code).first_or_404()

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
