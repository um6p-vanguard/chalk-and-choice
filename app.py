import os, io, base64, secrets, argparse, csv, random, functools, time, json, hmac, hashlib, traceback, builtins, sys, multiprocessing
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import NotFound
from itsdangerous import URLSafeSerializer

from models import (db, Student, User, Form, 
                    FormResponse,
                    StudentStats, Intervention, Exam, ExamSubmission, Grade,
                    Project, ProjectTask, ProjectTaskSubmission, ProjectDependency,
                    StudentGroup, StudentGroupMembership, StudentGroupReviewer, ProjectGroupAssignment)
import qrcode
from sqlalchemy import func

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
ALLOW_MULTI_ATTEMPTS = os.environ.get("ALLOW_MULTI_ATTEMPTS", "0") == "1"
ENABLE_BACKEND_CODE_RUNS = os.environ.get("ENABLE_BACKEND_CODE_RUNS", "1") == "1"
CODE_RUN_TIME_LIMIT_SEC = float(os.environ.get("CODE_RUN_TIME_LIMIT_SEC", "3.0"))

PROJECT_TASKS_SCHEMA = {
    "type": "object",
    "required": ["tasks"],
    "properties": {
        "tasks": {
            "description": "List of task definitions to create for the project.",
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["title", "questions"],
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": ["string", "null"]},
                    "instructions": {"type": ["string", "null"]},
                    "required": {"type": "boolean", "default": True},
                    "auto_grade": {"type": "boolean", "default": True},
                    "requires_review": {"type": "boolean", "default": False},
                    "questions": {
                        "type": "array",
                        "minItems": 1,
                        "description": "Question objects that follow the same structure as the task builder (multi-choice, code, text, tokens, etc.)."
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}

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
    session.pop("exam_access", None)
    session.pop("exam_drafts", None)

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
    student = current_student()
    exams = Exam.query.order_by(Exam.created_at.desc()).all() if (u or student) else []
    available_exams = [ex for ex in exams if ex.is_available] if student else []
    return render_template(
        "index.html",
        user=u,
        student_name=session.get("student_name"),
        exams=exams,
        available_exams=available_exams,
        now_utc=datetime.utcnow(),
    )

def gen_code(n=6):
    import string, random
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))
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

    db.session.commit()

    return jsonify({"ok": True})

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
    if not form.is_open or is_expired:
        return render_template("form_closed.html", form=form,
                               user=current_user(),
                               student_name=session.get("student_name")), 403

    u = current_user()
    s = current_student()
    if not (u or s):
        return redirect(url_for("login", next=url_for("form_render", code=code)))

    # latest submission (optional, to show “you have submitted N times”)
    latest_payload = {}
    attempts = 0
    if s:
        attempts = FormResponse.query.filter_by(form_id=form.id, student_id=s.id).count()
        last = FormResponse.query.filter_by(form_id=form.id, student_id=s.id)\
                                 .order_by(FormResponse.id.desc()).first()
        if last:
            latest_payload = last.payload_json if isinstance(last.payload_json, dict) else {}

    # students can ALWAYS submit while open (even if they submitted before)
    can_submit = bool(s and form.is_open)

    return render_template(
        "form_render.html",
        form=form,
        can_submit=can_submit,
        attempts=attempts,
        last_payload=latest_payload,
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

    # gate: only students & only while open
    stu = current_student()
    if not stu:
        abort(401)
    now = datetime.utcnow()
    if not form.is_open or (form.closes_at and form.closes_at <= now):
        abort(403, description="Form is closed.")

    # CSRF header
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")

    # NOTE: no “already submitted” check anymore — we keep all attempts
    data = request.get_json(silent=True) or {}

    # optional: include attempt number in the response
    prev_count = FormResponse.query.filter_by(form_id=form.id, student_id=stu.id).count()
    resp = FormResponse(
        form_id=form.id,
        student_id=stu.id,
        student_name=stu.name,
        payload_json=data,
    )
    db.session.add(resp); db.session.commit()

    return jsonify({"ok": True, "attempt": prev_count + 1})


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
# Exams & proctoring
# --------------------------------------------------------------------

def _normalize_exam_questions(payload):
    if not isinstance(payload, list) or not payload:
        raise ValueError("Add at least one question.")
    cleaned = []
    seen = set()
    for idx, raw in enumerate(payload):
        if not isinstance(raw, dict):
            raise ValueError("Question payload must be objects.")
        q_type = (raw.get("type") or "").strip().lower()
        if q_type not in ("mcq", "multi", "text", "code", "tokens", "fill"):
            raise ValueError(f"Unsupported question type '{q_type}'.")
        prompt = (raw.get("prompt") or "").strip()
        if not prompt:
            raise ValueError("Every question needs a prompt.")
        q_id = (raw.get("id") or "").strip() or f"q{idx+1}"
        if q_id in seen:
            q_id = f"{q_id}_{idx+1}"
        seen.add(q_id)
        normalized = {"id": q_id, "type": q_type, "prompt": prompt}
        title = (raw.get("title") or "").strip()
        if title:
            normalized["title"] = title
        snippet = raw.get("code_snippet")
        if isinstance(snippet, str):
            snippet = snippet.strip("\n")
            if snippet:
                normalized["code_snippet"] = snippet
        try:
            points = int(raw.get("points") or 1)
        except Exception:
            points = 1
        normalized["points"] = max(0, points)

        if q_type in ("mcq", "multi"):
            options_raw = raw.get("options") or []
            if isinstance(options_raw, str):
                options = [line.strip() for line in options_raw.splitlines() if line.strip()]
            else:
                options = [(line or "").strip() for line in options_raw if (line or "").strip()]
            if len(options) < 2:
                raise ValueError("Multiple-choice questions need at least two options.")
            normalized["options"] = options
            normalized["shuffle"] = bool(raw.get("shuffle"))
            correct_raw = raw.get("correct_indices") or []
            correct_indices = []
            if isinstance(correct_raw, str):
                tokens = [tok.strip() for tok in correct_raw.replace(";", ",").split(",") if tok.strip()]
                for tok in tokens:
                    try:
                        correct_indices.append(int(tok))
                    except Exception:
                        continue
            elif isinstance(correct_raw, list):
                for tok in correct_raw:
                    try:
                        correct_indices.append(int(tok))
                    except Exception:
                        continue
            if q_type == "mcq":
                if len(correct_indices) != 1:
                    raise ValueError("Provide exactly one correct option index for MCQ questions.")
            else:
                if not correct_indices:
                    raise ValueError("Provide at least one correct option index for multi-select questions.")
            normalized["correct_indices"] = correct_indices
        elif q_type == "text":
            normalized["placeholder"] = (raw.get("placeholder") or "").strip()
            lines_raw = raw.get("lines") or raw.get("rows")
            try:
                line_count = int(lines_raw) if lines_raw not in (None, "") else 4
            except Exception:
                line_count = 4
            normalized["lines"] = max(1, min(line_count, 12))
        elif q_type == "tokens":
            template = (raw.get("template") or "").strip()
            if "[[blank]]" not in template:
                raise ValueError("Token questions require [[blank]] markers.")
            blank_count = template.count("[[blank]]")
            correct_raw = raw.get("correct_tokens") or ""
            if isinstance(correct_raw, str):
                tokens = [t.strip() for t in correct_raw.replace("\n", ",").split(",") if t.strip()]
            elif isinstance(correct_raw, list):
                tokens = [str(t).strip() for t in correct_raw if str(t).strip()]
            else:
                tokens = []
            if len(tokens) != blank_count:
                raise ValueError("Provide one correct token for each [[blank]].")
            distractor_raw = raw.get("distractor_tokens") or ""
            if isinstance(distractor_raw, str):
                distractors = [t.strip() for t in distractor_raw.replace("\n", ",").split(",") if t.strip()]
            elif isinstance(distractor_raw, list):
                distractors = [str(t).strip() for t in distractor_raw if str(t).strip()]
            else:
                distractors = []
            normalized["template"] = template
            normalized["correct_tokens"] = tokens
            normalized["distractor_tokens"] = distractors
        elif q_type == "fill":
            template = (raw.get("template") or "").strip()
            if "[[blank]]" not in template:
                raise ValueError("Fill questions require [[blank]] markers.")
            blank_count = template.count("[[blank]]")
            answers_raw = raw.get("answers") or ""
            if isinstance(answers_raw, str):
                answers = [a.strip() for a in answers_raw.replace("\n", ",").split(",") if a.strip()]
            elif isinstance(answers_raw, list):
                answers = [str(a).strip() for a in answers_raw if str(a).strip()]
            else:
                answers = []
            if len(answers) != blank_count:
                raise ValueError("Provide one answer per [[blank]].")
            normalized["template"] = template
            normalized["answers"] = answers
            normalized["case_sensitive"] = bool(raw.get("case_sensitive"))
        else:  # code
            statement = (raw.get("statement") or "").strip()
            if not statement:
                raise ValueError("Code questions need a statement/description.")
            normalized["statement"] = statement
            normalized["starter"] = raw.get("starter") or ""
            normalized["language"] = "python"
            mode = (raw.get("mode") or "script").strip().lower()
            if mode not in ("script", "function"):
                mode = "script"
            normalized["mode"] = mode
            samples_clean = []
            samples_raw = raw.get("samples") or []
            if mode == "function":
                signature = (raw.get("function_signature") or "").strip()
                if not signature.startswith("def"):
                    raise ValueError("Function questions need a signature like 'def foo(x):'.")
                normalized["function_signature"] = signature
                if isinstance(samples_raw, list):
                    for s_idx, sample in enumerate(samples_raw):
                        if not isinstance(sample, dict):
                            continue
                        call_expr = (sample.get("call") or sample.get("input") or "").strip()
                        if not call_expr:
                            continue
                        name = (sample.get("name") or f"Sample {s_idx+1}").strip() or f"Sample {s_idx+1}"
                        expected = (sample.get("expected") or sample.get("output") or "").strip()
                        samples_clean.append({
                            "name": name,
                            "call": call_expr,
                            "expected": expected,
                            "input": call_expr,
                            "hidden": bool(sample.get("hidden")),
                        })
                if not samples_clean:
                    raise ValueError("Function code questions need at least one sample call.")
            else:
                if isinstance(samples_raw, list):
                    for s_idx, sample in enumerate(samples_raw):
                        if not isinstance(sample, dict):
                            continue
                        name = (sample.get("name") or f"Sample {s_idx+1}").strip() or f"Sample {s_idx+1}"
                        samples_clean.append({
                            "name": name,
                            "input": sample.get("input") or "",
                            "output": sample.get("output") or "",
                            "hidden": bool(sample.get("hidden")),
                        })
            normalized["samples"] = samples_clean

        cleaned.append(normalized)
    return cleaned

def _exam_share_url(exam):
    return request.url_root.rstrip("/") + url_for("exam_take", code=exam.code)

def _exam_access_table():
    data = session.get("exam_access")
    if isinstance(data, dict):
        return data
    session["exam_access"] = {}
    session.modified = True
    return session["exam_access"]

def _exam_has_access(exam_id):
    data = session.get("exam_access")
    if not isinstance(data, dict):
        return False
    return str(exam_id) in data

def _grant_exam_access(exam_id):
    data = _exam_access_table()
    data[str(exam_id)] = True
    session["exam_access"] = data
    session.modified = True

def _get_exam_draft(exam_id):
    drafts = session.get("exam_drafts")
    if isinstance(drafts, dict):
        payload = drafts.get(str(exam_id))
        if isinstance(payload, dict):
            return dict(payload)
    return {}

def _save_exam_draft(exam_id, answers):
    drafts = session.get("exam_drafts")
    if not isinstance(drafts, dict):
        drafts = {}
    drafts[str(exam_id)] = answers
    session["exam_drafts"] = drafts
    session.modified = True

def _clear_exam_draft(exam_id):
    drafts = session.get("exam_drafts")
    if isinstance(drafts, dict) and drafts.pop(str(exam_id), None) is not None:
        session["exam_drafts"] = drafts
        session.modified = True

def _get_task_draft(task_id):
    drafts = session.get("task_drafts")
    if isinstance(drafts, dict):
        payload = drafts.get(str(task_id))
        if isinstance(payload, dict):
            return dict(payload)
    return {}

def _save_task_draft(task_id, answers):
    drafts = session.get("task_drafts")
    if not isinstance(drafts, dict):
        drafts = {}
    drafts[str(task_id)] = answers
    session["task_drafts"] = drafts
    session.modified = True

def _clear_task_draft(task_id):
    drafts = session.get("task_drafts")
    if isinstance(drafts, dict) and drafts.pop(str(task_id), None) is not None:
        session["task_drafts"] = drafts
        session.modified = True

def _find_student_by_email(email: str):
    if not email:
        return None
    normalized = email.strip().lower()
    if not normalized:
        return None
    return Student.query.filter(func.lower(Student.email) == normalized).first()

def _find_student_by_name(name: str):
    if not name:
        return None
    normalized = " ".join(name.split()).lower()
    if not normalized:
        return None
    return Student.query.filter(func.lower(Student.name) == normalized).first()

def _create_grade_entry(student, assignment, score, max_score, remarks=None):
    if not student or not assignment:
        return None
    entry = Grade(
        student_id=student.id,
        student_name=student.name,
        assignment=assignment,
        score=score,
        max_score=max_score,
        remarks=(remarks or "").strip() or None,
    )
    db.session.add(entry)
    return entry

def _project_task_submission(task, student):
    if not student:
        return None
    return ProjectTaskSubmission.query.filter_by(task_id=task.id, student_id=student.id).first()

def _project_required_count(project):
    required_tasks = [t for t in project.tasks if t.required]
    if project.required_task_count and project.required_task_count > 0:
        return min(project.required_task_count, len(required_tasks) or len(project.tasks))
    return len(required_tasks) if required_tasks else len(project.tasks)

def _project_completed(project, student):
    required_count = _project_required_count(project)
    if required_count <= 0:
        return True
    required_tasks = [t for t in project.tasks if t.required]
    tasks_to_check = required_tasks if required_tasks else list(project.tasks)
    completed = 0
    for task in tasks_to_check:
        sub = _project_task_submission(task, student)
        if not sub:
            continue
        if sub.status == "accepted":
            completed += 1
        if completed >= required_count:
            return True
    return False

def _project_dependencies_met(project, student):
    deps = project.dependencies or []
    for dep in deps:
        if not _project_completed(dep.prerequisite, student):
            return False
    return True

def _award_project_points_if_needed(project, student):
    """
    Award project points once per student/project when completed.
    Caller must commit.
    """
    if not project or not student:
        return
    if not project.points or project.points <= 0:
        return
    assignment_name = f"Project: {project.title}"
    existing = Grade.query.filter_by(student_id=student.id, assignment=assignment_name).first()
    if existing:
        return
    _create_grade_entry(
        student,
        assignment_name,
        float(project.points),
        float(project.points),
        remarks=f"Auto-awarded for completing project '{project.title}'.",
    )

def _student_group_ids(student):
    if not student:
        return set()
    memberships = getattr(student, "group_memberships", [])
    return {m.group_id for m in memberships if m.group_id}

def _project_visible_to_student(project, student):
    assignments = project.group_assignments or []
    if not assignments:
        return True
    group_ids = _student_group_ids(student)
    for assignment in assignments:
        if assignment.applies_to_all:
            return True
        if assignment.group_id in group_ids:
            return True
    return False

def _project_required_for_student(project, student):
    assignments = project.group_assignments or []
    if not assignments:
        return True
    group_ids = _student_group_ids(student)
    matched = False
    required = False
    for assignment in assignments:
        applies = assignment.applies_to_all or assignment.group_id in group_ids
        if not applies:
            continue
        matched = True
        if assignment.is_required:
            required = True
    return required if matched else False

def _import_project_tasks_from_config(project, config):
    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object.")
    tasks_data = config.get("tasks")
    if not isinstance(tasks_data, list) or not tasks_data:
        raise ValueError("Config must include a non-empty 'tasks' array.")
    existing = ProjectTask.query.filter_by(project_id=project.id).count() or 0
    new_tasks = []
    for offset, entry in enumerate(tasks_data, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Task #{offset} must be an object.")
        title = (entry.get("title") or "").strip()
        if not title:
            raise ValueError(f"Task #{offset} is missing a title.")
        questions_payload = entry.get("questions")
        if not isinstance(questions_payload, list) or not questions_payload:
            raise ValueError(f"Task '{title}' must include a non-empty 'questions' array.")
        try:
            questions = _normalize_exam_questions(questions_payload)
        except ValueError as exc:
            raise ValueError(f"Task '{title}': {exc}")
        except Exception:
            raise ValueError(f"Task '{title}': unable to parse questions.")
        description = (entry.get("description") or "").strip()
        instructions = (entry.get("instructions") or "").strip()
        task = ProjectTask(
            project_id=project.id,
            title=title,
            description=description or None,
            instructions=instructions or None,
            questions_json=questions,
            required=bool(entry.get("required", True)),
            auto_grade=bool(entry.get("auto_grade", True)),
            requires_review=bool(entry.get("requires_review", False)),
            order_index=existing + offset,
        )
        new_tasks.append(task)
    for task in new_tasks:
        db.session.add(task)
    return len(new_tasks)

def _grade_exam_submission(exam, answers):
    questions = exam.questions_json if isinstance(exam.questions_json, list) else []
    answer_map = answers if isinstance(answers, dict) else {}
    earned = 0.0
    total = 0.0
    details = []
    for q in questions:
        qid = q.get("id")
        qtype = q.get("type")
        points = max(0, int(q.get("points") or 1))
        total += points
        res = {"question_id": qid, "type": qtype, "points": points, "earned": 0.0}
        raw_answer = answer_map.get(qid, "") or ""
        if qtype == "mcq":
            correct = q.get("correct_indices") or []
            if correct:
                try:
                    idx = int(raw_answer)
                except Exception:
                    idx = None
                if idx is not None and idx == correct[0]:
                    res["earned"] = points
        elif qtype == "multi":
            correct = sorted(set(int(val) for val in (q.get("correct_indices") or [])))
            submitted = []
            for token in raw_answer.split("||"):
                token = token.strip()
                if not token:
                    continue
                try:
                    submitted.append(int(token))
                except Exception:
                    continue
            submitted = sorted(set(submitted))
            if correct and submitted == correct:
                res["earned"] = points
        elif qtype == "tokens":
            expected_tokens = q.get("correct_tokens") or []
            submitted = [tok.strip() for tok in (raw_answer.split("||") if raw_answer else []) if tok.strip()]
            if submitted == expected_tokens and expected_tokens:
                res["earned"] = points
        elif qtype == "fill":
            answers_expected = q.get("answers") or []
            submitted = [tok for tok in (raw_answer.split("||") if raw_answer else []) if tok]
            case_sensitive = bool(q.get("case_sensitive"))
            matches = len(submitted) >= len(answers_expected) and bool(answers_expected)
            if matches:
                for exp, got in zip(answers_expected, submitted):
                    left = exp or ""
                    right = got or ""
                    if not case_sensitive:
                        left = left.strip().lower()
                        right = right.strip().lower()
                    if left != right:
                        matches = False
                        break
            if matches and answers_expected:
                res["earned"] = points
        elif qtype == "code":
            samples = q.get("samples") or []
            mode = q.get("mode") or "script"
            res["cases"] = []
            res["timed_out"] = False
            if samples:
                run_results, timed_out = _run_code_tests_backend(raw_answer, samples, mode)
                res["cases"] = run_results
                res["timed_out"] = timed_out
                if not timed_out and all((r.get("status") == "passed") for r in run_results):
                    res["earned"] = points
                res["manual_review"] = False
            else:
                res["manual_review"] = True
        details.append(res)
        earned += res["earned"]
    return earned, total, details

def _run_logs_by_question(logs):
    mapping = {}
    if not isinstance(logs, list):
        return mapping
    for log in logs:
        try:
            qid = log.get("question_id")
        except Exception:
            continue
        if qid is None:
            continue
        mapping.setdefault(str(qid), []).append(log)
    return mapping

# --------------------------------------------------------------------
# Safe builtins for student code
# --------------------------------------------------------------------
UNSAFE_BUILTINS = {
    "__import__",      # arbitrary imports
    "eval", "exec", "compile",
    "open",           # file I/O
    "help", "quit", "exit",
    "globals", "locals", "vars",
    "dir",             # not fatal, but lets them inspect too much
    "input",           # we will override with our own stub/fake
    "breakpoint",
}

def build_safe_builtins():
    safe = {}
    for name in dir(builtins):
        if name.startswith("_"):
            continue
        if name in UNSAFE_BUILTINS:
            continue
        safe[name] = getattr(builtins, name)
    return safe

SAFE_CODE_BUILTINS = build_safe_builtins()

def _disallow_input(*args, **kwargs):
    """
    Default stub for input(): used in function-mode problems, where
    students must not use input().
    """
    raise RuntimeError("input() is not allowed in this problem; use function arguments instead.")

SAFE_CODE_BUILTINS["input"] = _disallow_input

def safe_env():
    """
    Return a fresh environment dict with safe builtins.
    """
    return {"__builtins__": dict(SAFE_CODE_BUILTINS)}

def _run_code_tests_worker(code_text, tests, mode):
    results = []
    if not tests:
        return results
    if not code_text:
        for idx, test in enumerate(tests):
            hidden = bool(test.get("hidden"))
            name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
            results.append({
                "name": name,
                "status": "error",
                "input": test.get("call") or test.get("input") or "",
                "output": "",
                "expected": test.get("expected") or test.get("output") or "",
                "error": "No code submitted.",
                "hidden": hidden,
            })
        return results
    mode = (mode or "script").strip().lower()
    if mode not in ("script", "function"):
        mode = "script"
    env_base = None
    if mode == "function":
        try:
            env_base = safe_env()
            exec(code_text, env_base, env_base)
        except Exception:
            tb = traceback.format_exc()
            for idx, test in enumerate(tests):
                hidden = bool(test.get("hidden"))
                name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
                results.append({
                    "name": name,
                    "status": "error",
                    "input": test.get("call") or test.get("input") or "",
                    "output": "",
                    "expected": test.get("expected") or test.get("output") or "",
                    "error": tb,
                    "hidden": hidden,
                })
            return results
    for idx, test in enumerate(tests):
        hidden = bool(test.get("hidden"))
        name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
        if mode == "function":
            call_expr = (test.get("call") or test.get("input") or "").strip()
            expected_output = (test.get("expected") or test.get("output") or "")
            status = "passed"
            error_text = ""
            output_value = ""
            if not call_expr:
                status = "error"
                error_text = "Missing call expression."
            else:
                env = dict(env_base or safe_env())
                stdout = io.StringIO()
                original_stdout = sys.stdout
                sys.stdout = stdout
                try:
                    result = eval(call_expr, env, env)
                    output_value = repr(result)
                except Exception:
                    status = "error"
                    error_text = traceback.format_exc()
                finally:
                    sys.stdout = original_stdout
            if status == "passed" and expected_output.strip() and output_value.strip() != expected_output.strip():
                status = "mismatch"
            results.append({
                "name": name,
                "status": status,
                "input": call_expr,
                "output": output_value,
                "expected": expected_output,
                "error": error_text,
                "hidden": hidden,
            })
        else:
            sample_input = test.get("input") or ""
            expected_output = (test.get("expected") or test.get("output") or "")
            stdin_buffer = io.StringIO(sample_input)
            stdout_buffer = io.StringIO()
            status = "passed"
            error_text = ""
            try:
                env = safe_env()
                def fake_input(prompt: str = ""):
                    line = stdin_buffer.readline()
                    if line == "":
                        raise EOFError("EOF when reading a line")
                    return line.rstrip("\n")
                env["input"] = fake_input
                env["__name__"] = "__main__"
                original_stdout = sys.stdout
                sys.stdout = stdout_buffer
                try:
                    exec(code_text, env, env)
                finally:
                    sys.stdout = original_stdout
            except Exception:
                status = "error"
                error_text = traceback.format_exc()
            output_value = stdout_buffer.getvalue()
            if status == "passed" and expected_output.strip():
                if output_value.rstrip() != expected_output.rstrip():
                    status = "mismatch"
                    error_text = ""
            results.append({
                "name": name,
                "status": status,
                "input": sample_input,
                "output": output_value,
                "expected": expected_output,
                "error": error_text,
                "hidden": hidden,
            })
    return results

def _run_code_tests_backend(code_text, tests, mode):
    """
    Run code in a child process with a hard time limit.
    Returns (results, timed_out).
    """
    if not tests:
        return [], False

    try:
        ctx = multiprocessing.get_context("fork")
    except ValueError:
        ctx = multiprocessing.get_context()
    result_queue = ctx.Queue()

    def _child():
        try:
            res = _run_code_tests_worker(code_text, tests, mode)
        except Exception as e:
            res = []
            for idx, t in enumerate(tests):
                hidden = bool(t.get("hidden"))
                name = t.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
                res.append({
                    "name": name,
                    "status": "error",
                    "input": t.get("call") or t.get("input") or "",
                    "output": "",
                    "expected": t.get("expected") or t.get("output") or "",
                    "error": repr(e),
                    "hidden": hidden,
                })
        result_queue.put(res)

    proc = ctx.Process(target=_child)
    proc.start()
    proc.join(CODE_RUN_TIME_LIMIT_SEC)

    timed_out = False
    results = []

    if proc.is_alive():
        timed_out = True
        try:
            proc.terminate()
        finally:
            proc.join()
        for idx, t in enumerate(tests):
            hidden = bool(t.get("hidden"))
            name = t.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
            results.append({
                "name": name,
                "status": "timeout",
                "input": "",
                "output": "",
                "expected": "",
                "error": "Time limit exceeded",
                "hidden": hidden,
            })
    else:
        try:
            results = result_queue.get_nowait()
        except Exception:
            timed_out = True
            for idx, t in enumerate(tests):
                hidden = bool(t.get("hidden"))
                name = t.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
                results.append({
                    "name": name,
                    "status": "error",
                    "input": "",
                    "output": "",
                    "expected": "",
                    "error": "No results from worker process",
                    "hidden": hidden,
                })

    return results, timed_out

def _split_visible_hidden_results(results):
    visible = []
    hidden = []
    for res in results or []:
        is_hidden = bool(res.get("hidden"))
        base = {
            "name": res.get("name") or ("Hidden test" if is_hidden else "Test"),
            "status": res.get("status") or "error",
            "hidden": is_hidden,
        }
        if is_hidden:
            hidden.append(base)
        else:
            base.update({
                "input": res.get("input") or "",
                "output": res.get("output") or "",
                "expected": res.get("expected") or "",
                "error": res.get("error") or "",
            })
            visible.append(base)
    return visible, hidden

def _summarize_test_results(visible, hidden, timed_out):
    visible_passed = sum(1 for r in visible if r.get("status") == "passed")
    hidden_passed = sum(1 for r in hidden if r.get("status") == "passed")
    visible_total = len(visible)
    hidden_total = len(hidden)
    all_passed = (
        (visible_total + hidden_total) > 0
        and visible_passed == visible_total
        and hidden_passed == hidden_total
        and not timed_out
    )
    return {
        "visible_passed": visible_passed,
        "visible_total": visible_total,
        "hidden_passed": hidden_passed,
        "hidden_total": hidden_total,
        "all_passed": all_passed,
        "timed_out": bool(timed_out),
    }

@app.route("/exams")
@require_user()
def exams_list():
    exams = Exam.query.order_by(Exam.created_at.desc()).all()
    stats = {}
    for ex in exams:
        total = len(ex.submissions)
        submitted = sum(1 for sub in ex.submissions if sub.status == "submitted")
        stats[ex.id] = {"total": total, "submitted": submitted}
    return render_template(
        "exams_list.html",
        exams=exams,
        stats=stats,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/exams/new", methods=["GET", "POST"])
@require_user()
def exams_new():
    error = None
    form_data = {
        "title": request.form.get("title") or "",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "duration_minutes": request.form.get("duration_minutes") or "",
        "starts_at": request.form.get("starts_at") or "",
        "ends_at": request.form.get("ends_at") or "",
        "questions_payload": request.form.get("questions_payload") or "[]",
        "question_type": request.form.get("question_type") or "mcq",
    }

    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        title = form_data["title"].strip()
        description = form_data["description"].strip() or None
        instructions = form_data["instructions"].strip() or None
        access_password = (request.form.get("access_password") or "").strip()
        duration = None
        if form_data["duration_minutes"]:
            try:
                duration = max(5, int(form_data["duration_minutes"]))
            except Exception:
                error = "Duration must be a number (minutes)."
        starts_at = parse_dt_local(form_data["starts_at"])
        ends_at = parse_dt_local(form_data["ends_at"])
        raw_questions = form_data["questions_payload"]
        questions = []
        if not error:
            try:
                payload = json.loads(raw_questions or "[]")
                questions = _normalize_exam_questions(payload)
            except ValueError as e:
                error = str(e)
            except Exception:
                error = "Unable to parse the questions payload."
        if not title and not error:
            error = "Title is required."
        if not error:
            code = gen_code(8)
            while Exam.query.filter_by(code=code).first() is not None:
                code = gen_code(8)
            exam = Exam(
                code=code,
                title=title,
                description=description,
                instructions=instructions,
                duration_minutes=duration,
                starts_at=starts_at,
                ends_at=ends_at,
                questions_json=questions,
                creator_user_id=current_user().id if current_user() else None,
            )
            exam.set_access_password(access_password)
            db.session.add(exam)
            db.session.commit()
            return redirect(url_for("exams_show", code=exam.code))

    return render_template(
        "exams_new.html",
        error=error,
        form_data=form_data,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/exams/<code>")
@require_user()
def exams_show(code):
    exam = Exam.query.filter_by(code=code).first_or_404()
    submissions = ExamSubmission.query.filter_by(exam_id=exam.id).order_by(ExamSubmission.started_at.asc()).all()
    questions = exam.questions_json if isinstance(exam.questions_json, list) else []
    return render_template(
        "exams_show.html",
        exam=exam,
        submissions=submissions,
        share_url=_exam_share_url(exam),
        questions=questions,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/exams/<code>/submissions/<int:submission_id>/download")
@require_user()
def exams_download_submission(code, submission_id):
    exam = Exam.query.filter_by(code=code).first_or_404()
    submission = ExamSubmission.query.filter_by(id=submission_id, exam_id=exam.id).first_or_404()
    payload = {
        "exam": {
            "code": exam.code,
            "title": exam.title,
            "description": exam.description,
        },
        "student": {
            "id": submission.student_id,
            "name": submission.student_name,
        },
        "status": submission.status,
        "score": submission.score,
        "max_score": submission.max_score,
        "started_at": submission.started_at.isoformat() if submission.started_at else None,
        "submitted_at": submission.submitted_at.isoformat() if submission.submitted_at else None,
        "last_activity_at": submission.last_activity_at.isoformat() if submission.last_activity_at else None,
        "answers": submission.answers_json,
        "grading": submission.grading_json,
        "run_logs": submission.run_logs,
    }
    filename = f"{exam.code}_submission_{submission.id}.json"
    body = json.dumps(payload, indent=2, sort_keys=True)
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return Response(body, mimetype="application/json", headers=headers)

@app.post("/exams/<code>/open")
@require_user()
def exams_open(code):
    if not verify_csrf(): abort(400, "bad csrf")
    exam = Exam.query.filter_by(code=code).first_or_404()
    exam.is_open = True
    db.session.commit()
    return redirect(url_for("exams_show", code=exam.code))

@app.post("/exams/<code>/close")
@require_user()
def exams_close(code):
    if not verify_csrf(): abort(400, "bad csrf")
    exam = Exam.query.filter_by(code=code).first_or_404()
    exam.is_open = False
    db.session.commit()
    return redirect(url_for("exams_show", code=exam.code))

@app.post("/exams/<code>/password")
@require_user()
def exams_update_password(code):
    if not verify_csrf(): abort(400, "bad csrf")
    exam = Exam.query.filter_by(code=code).first_or_404()
    password = (request.form.get("access_password") or "").strip()
    exam.set_access_password(password)
    db.session.commit()
    return redirect(url_for("exams_show", code=exam.code))

@app.route("/exam/<code>", methods=["GET", "POST"])
def exam_take(code):
    exam = Exam.query.filter_by(code=code).first_or_404()
    user = current_user()
    student = current_student()
    preview = bool(user and not student)

    if not (student or preview):
        return redirect(url_for("login", next=url_for("exam_take", code=code)))

    # ------------------------------------------------------------------
    # Access password gate
    # ------------------------------------------------------------------
    locked = bool(exam.access_password_hash) and student and not _exam_has_access(exam.id)
    if locked:
        error = None
        if request.method == "POST":
            if not verify_csrf():
                abort(400, "bad csrf")
            attempt = request.form.get("unlock_password") or ""
            if exam.check_access_password(attempt):
                _grant_exam_access(exam.id)
                return redirect(url_for("exam_take", code=code))
            else:
                error = "Incorrect password."
        return render_template(
            "exams_unlock.html",
            exam=exam,
            error=error,
            user=user,
            student_name=session.get("student_name"),
        )

    # ------------------------------------------------------------------
    # Questions + index handling
    # ------------------------------------------------------------------
    questions = exam.questions_json if isinstance(exam.questions_json, list) else []
    total_questions = len(questions)

    def clamp_q(idx):
        if total_questions <= 0:
            return 0
        try:
            val = int(idx)
        except Exception:
            val = 0
        return max(0, min(val, total_questions - 1))

    requested_q = request.args.get("q", "0")
    q_index = clamp_q(requested_q)

    # ------------------------------------------------------------------
    # Submission: single row per (exam, student) + optional multi attempts
    # ------------------------------------------------------------------
    submission = None
    base_answers = {}

    if student:
        submission = ExamSubmission.query.filter_by(exam_id=exam.id, student_id=student.id).first()

        if submission and ALLOW_MULTI_ATTEMPTS and submission.status == "submitted":
            # Start a fresh attempt by resetting the existing row.
            _clear_exam_draft(exam.id)
            submission.status = "in_progress"
            submission.started_at = datetime.utcnow()
            submission.submitted_at = None
            submission.last_activity_at = submission.started_at
            submission.answers_json = {}
            submission.run_logs = []
            submission.score = 0.0
            submission.max_score = 0.0
            submission.grading_json = None
            # NOTE: no commit here; we only care about in-memory values
            # for timer and grading. Commit happens on submit/timeout.

        if not submission:
            submission = ExamSubmission(
                exam_id=exam.id,
                student_id=student.id,
                student_name=student.name,
                answers_json={},
                run_logs=[],
                ip_address=(request.remote_addr or "")[:64],
            )
            db.session.add(submission)
            db.session.commit()  # one-time insert to get started_at, id, etc.

        base_answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}

    # ------------------------------------------------------------------
    # If already submitted and multi-attempts disabled: lock them out
    # ------------------------------------------------------------------
    already_submitted = bool(submission and submission.status == "submitted")
    if already_submitted and not preview and not ALLOW_MULTI_ATTEMPTS:
        _clear_exam_draft(exam.id)
        return render_template(
            "exams_submitted.html",
            exam=exam,
            submission=submission,
            user=user,
            student_name=session.get("student_name"),
        )

    # ------------------------------------------------------------------
    # Draft answers (session-based autosave)
    # ------------------------------------------------------------------
    draft_answers = _get_exam_draft(exam.id) if student else {}
    previous_answers = dict(base_answers)
    previous_answers.update(draft_answers)

    # ------------------------------------------------------------------
    # Timer + automatic submission on timeout
    # ------------------------------------------------------------------
    duration_seconds = exam.duration_minutes * 60 if exam.duration_minutes else None
    time_remaining = None

    if duration_seconds and submission:
        # started_at is assumed to be set by DB default or earlier commit
        deadline = submission.started_at + timedelta(seconds=duration_seconds)
        time_remaining = int((deadline - datetime.utcnow()).total_seconds())
        if time_remaining <= 0 and submission.status != "submitted":
            answers = dict(base_answers)
            answers.update(draft_answers)
            submission.answers_json = answers
            submission.status = "submitted"
            submission.submitted_at = datetime.utcnow()
            submission.last_activity_at = submission.submitted_at
            grade_score, grade_total, grade_details = _grade_exam_submission(exam, answers)
            submission.score = grade_score
            submission.max_score = grade_total
            submission.grading_json = grade_details
            db.session.commit()
            _clear_exam_draft(exam.id)
            return render_template(
                "exams_submitted.html",
                exam=exam,
                submission=submission,
                user=user,
                student_name=session.get("student_name"),
            )

    # ------------------------------------------------------------------
    # Can submit?
    # ------------------------------------------------------------------
    can_submit = bool(student and exam.is_available)

    if not ALLOW_MULTI_ATTEMPTS:
        # In single-attempt mode, block further submissions after one is submitted.
        can_submit = can_submit and (not submission or submission.status != "submitted")

    if can_submit and time_remaining is not None:
        can_submit = can_submit and (time_remaining > 0)

    # ------------------------------------------------------------------
    # POST: save to draft (session) + optional final submit
    # ------------------------------------------------------------------
    if request.method == "POST" and not locked:
        if preview:
            return redirect(url_for("exam_take", code=code, q=q_index))
        if not verify_csrf():
            abort(400, "bad csrf")

        post_q_index = clamp_q(request.form.get("q_index", q_index))
        q_index = post_q_index
        current_question = questions[q_index] if total_questions else None

        # Save current question answer into session draft only
        if student and current_question:
            qid = current_question.get("id")
            if qid:
                field = f"answer_{qid}"
                if current_question.get("type") == "multi":
                    vals = request.form.getlist(field)
                    val = "||".join(vals)
                else:
                    val = request.form.get(field, "")
                draft_answers[qid] = val
                previous_answers[qid] = val
                _save_exam_draft(exam.id, draft_answers)

        action = request.form.get("nav_action") or request.form.get("nav_action_auto")
        if not action:
            if total_questions and q_index >= total_questions - 1:
                action = "submit"
            else:
                action = "next"

        if action == "submit":
            if not can_submit:
                return render_template(
                    "exams_take.html",
                    exam=exam,
                    question=current_question,
                    total_questions=total_questions,
                    current_index=q_index,
                    has_prev=(q_index > 0),
                    has_next=(q_index + 1 < total_questions),
                    can_submit=False,
                    preview=preview,
                    already_submitted=True,
                    previous_answers=previous_answers,
                    user=user,
                    student_name=session.get("student_name"),
                ), 403

            answers = dict(base_answers)
            answers.update(draft_answers)
            grade_score, grade_total, grade_details = _grade_exam_submission(exam, answers)
            submission.answers_json = answers
            submission.status = "submitted"
            submission.submitted_at = datetime.utcnow()
            submission.last_activity_at = submission.submitted_at
            submission.score = grade_score
            submission.max_score = grade_total
            submission.grading_json = grade_details
            db.session.commit()
            _clear_exam_draft(exam.id)
            return render_template(
                "exams_submitted.html",
                exam=exam,
                submission=submission,
                user=user,
                student_name=session.get("student_name"),
            )
        else:
            if submission and student:
                answers = dict(base_answers)
                answers.update(draft_answers)
                submission.answers_json = answers
                submission.last_activity_at = datetime.utcnow()
                db.session.commit()
            target = q_index
            if action == "prev":
                target = max(0, q_index - 1)
            elif action == "next":
                target = min(total_questions - 1, q_index + 1) if total_questions else 0
            return redirect(url_for("exam_take", code=code, q=target))

    # ------------------------------------------------------------------
    # GET (or POST fall-through): render current question
    # ------------------------------------------------------------------
    current_question = dict(questions[q_index]) if total_questions else None
    if current_question and current_question.get("type") == "tokens":
        options = list(current_question.get("correct_tokens") or [])
        distractors = current_question.get("distractor_tokens") or []
        if isinstance(distractors, list):
            options.extend([t for t in distractors if t])
        random.shuffle(options)
        current_question["token_options"] = options
        template = current_question.get("template") or ""
        current_question["blank_count"] = template.count("[[blank]]")

    return render_template(
        "exams_take.html",
        exam=exam,
        question=current_question,
        total_questions=total_questions,
        current_index=q_index,
        has_prev=(q_index > 0),
        has_next=(q_index + 1 < total_questions),
        can_submit=can_submit,
        preview=preview,
        already_submitted=(submission and submission.status == "submitted"),
        previous_answers=previous_answers,
        time_remaining_seconds=time_remaining if time_remaining is not None else None,
        user=user,
        student_name=session.get("student_name"),
    )



@app.route("/api/exams/<code>/log-run", methods=["POST"])
def exams_log_run(code):
    exam = Exam.query.filter_by(code=code).first_or_404()
    student = current_student()
    if not student:
        abort(401)
    if exam.access_password_hash and not _exam_has_access(exam.id):
        abort(403)
    submission = ExamSubmission.query.filter_by(exam_id=exam.id, student_id=student.id).first()
    if not submission:
        submission = ExamSubmission(
            exam_id=exam.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
            ip_address=(request.remote_addr or "")[:64],
        )
        db.session.add(submission)
        db.session.commit()
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    question_id = data.get("question_id")
    samples = data.get("samples") or []
    summary = {
        "question_id": question_id,
        "samples": samples,
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append(summary)
    submission.run_logs = logs
    submission.last_activity_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "log_count": len(logs)})

@app.route("/api/exams/<code>/run-code", methods=["POST"])
def exams_run_code(code):
    if not ENABLE_BACKEND_CODE_RUNS:
        return jsonify({"ok": False, "error": "Backend code runs are disabled."}), 503
    exam = Exam.query.filter_by(code=code).first_or_404()
    student = current_student()
    if not student:
        abort(401)
    if exam.access_password_hash and not _exam_has_access(exam.id):
        abort(403)
    if not exam.is_available:
        abort(403)
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    qid = data.get("question_id")
    code_text = data.get("code") or ""
    if not qid or code_text is None:
        return jsonify({"ok": False, "error": "Missing question_id or code"}), 400
    questions = exam.questions_json if isinstance(exam.questions_json, list) else []
    q = next((qq for qq in questions if str(qq.get("id")) == str(qid)), None)
    if not q or q.get("type") != "code":
        return jsonify({"ok": False, "error": "Unknown or non-code question"}), 400
    tests = q.get("samples") or []
    mode = q.get("mode") or "script"
    results, timed_out = _run_code_tests_backend(code_text, tests, mode)
    visible, hidden = _split_visible_hidden_results(results)
    summary = _summarize_test_results(visible, hidden, timed_out)

    submission = ExamSubmission.query.filter_by(exam_id=exam.id, student_id=student.id).first()
    if not submission:
        submission = ExamSubmission(
            exam_id=exam.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
            ip_address=(request.remote_addr or "")[:64],
        )
        db.session.add(submission)

    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append({
        "question_id": qid,
        "tests": visible + hidden,
        "summary": summary,
        "ts": datetime.utcnow().isoformat() + "Z",
    })
    submission.run_logs = logs
    submission.last_activity_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "tests": visible + hidden, "summary": summary})

@app.route("/api/projects/<code>/tasks/<int:task_id>/run-code", methods=["POST"])
def projects_run_code(code, task_id):
    if not ENABLE_BACKEND_CODE_RUNS:
        return jsonify({"ok": False, "error": "Backend code runs are disabled."}), 503
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    student = current_student()
    if not student:
        abort(401)
    if not _project_visible_to_student(project, student):
        abort(403)
    if not _project_dependencies_met(project, student):
        abort(403)
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    qid = data.get("question_id")
    code_text = data.get("code") or ""
    if not qid or code_text is None:
        return jsonify({"ok": False, "error": "Missing question_id or code"}), 400
    questions = task.questions_json if isinstance(task.questions_json, list) else []
    q = next((qq for qq in questions if str(qq.get("id")) == str(qid)), None)
    if not q or q.get("type") != "code":
        return jsonify({"ok": False, "error": "Unknown or non-code question"}), 400
    tests = q.get("samples") or []
    mode = q.get("mode") or "script"
    results, timed_out = _run_code_tests_backend(code_text, tests, mode)
    visible, hidden = _split_visible_hidden_results(results)
    summary = _summarize_test_results(visible, hidden, timed_out)

    submission = _project_task_submission(task, student)
    if not submission:
        submission = ProjectTaskSubmission(
            task_id=task.id,
            project_id=project.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
        )
        db.session.add(submission)

    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append({
        "question_id": qid,
        "tests": visible + hidden,
        "summary": summary,
        "ts": datetime.utcnow().isoformat() + "Z",
    })
    submission.run_logs = logs
    submission.last_activity_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "tests": visible + hidden, "summary": summary})

# --------------------------------------------------------------------
# Student Groups (admin)
# --------------------------------------------------------------------

@app.route("/groups", methods=["GET", "POST"])
@require_user()
def groups_list():
    form_data = {
        "name": (request.form.get("name") or "").strip(),
        "description": request.form.get("description") or "",
    }
    error = None
    action = request.form.get("action") or ""
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        if action == "create_group":
            name = form_data["name"]
            if not name:
                error = "Group name is required."
            else:
                exists = StudentGroup.query.filter(func.lower(StudentGroup.name) == name.lower()).first()
                if exists:
                    error = "Group name already exists."
            if not error:
                group = StudentGroup(name=name, description=form_data["description"].strip() or None)
                db.session.add(group)
                db.session.commit()
                return redirect(url_for("groups_list"))
        elif action == "add_member":
            try:
                group_id = int(request.form.get("group_id") or 0)
                student_id = int(request.form.get("student_id") or 0)
            except ValueError:
                group_id = 0
                student_id = 0
            if group_id and student_id:
                group = StudentGroup.query.get(group_id)
                student = Student.query.get(student_id)
                if group and student:
                    exists = StudentGroupMembership.query.filter_by(group_id=group.id, student_id=student.id).first()
                    if not exists:
                        membership = StudentGroupMembership(group_id=group.id, student_id=student.id)
                        db.session.add(membership)
                        db.session.commit()
            return redirect(url_for("groups_list"))
        elif action == "remove_member":
            try:
                membership_id = int(request.form.get("membership_id") or 0)
            except ValueError:
                membership_id = 0
            if membership_id:
                membership = StudentGroupMembership.query.get(membership_id)
                if membership:
                    db.session.delete(membership)
                    db.session.commit()
            return redirect(url_for("groups_list"))
        elif action == "delete_group":
            try:
                group_id = int(request.form.get("group_id") or 0)
            except ValueError:
                group_id = 0
            if group_id:
                group = StudentGroup.query.get(group_id)
                if group:
                    db.session.delete(group)
                    db.session.commit()
            return redirect(url_for("groups_list"))
        elif action == "add_reviewer":
            try:
                group_id = int(request.form.get("group_id") or 0)
                user_id = int(request.form.get("user_id") or 0)
            except ValueError:
                group_id = 0
                user_id = 0
            if group_id and user_id:
                group = StudentGroup.query.get(group_id)
                mentor = User.query.get(user_id)
                if group and mentor:
                    exists = StudentGroupReviewer.query.filter_by(group_id=group.id, user_id=mentor.id).first()
                    if not exists:
                        reviewer = StudentGroupReviewer(group_id=group.id, user_id=mentor.id)
                        db.session.add(reviewer)
                        db.session.commit()
            return redirect(url_for("groups_list"))
        elif action == "remove_reviewer":
            try:
                reviewer_id = int(request.form.get("reviewer_id") or 0)
            except ValueError:
                reviewer_id = 0
            if reviewer_id:
                reviewer = StudentGroupReviewer.query.get(reviewer_id)
                if reviewer:
                    db.session.delete(reviewer)
                    db.session.commit()
            return redirect(url_for("groups_list"))
    groups = StudentGroup.query.order_by(StudentGroup.name.asc(), StudentGroup.id.asc()).all()
    group_rows = []
    for group in groups:
        memberships = sorted(
            group.memberships,
            key=lambda m: (m.student.name.lower() if m.student and m.student.name else ""),
        )
        reviewers = sorted(
            group.reviewers,
            key=lambda r: (r.user.name.lower() if r.user and r.user.name else ""),
        )
        group_rows.append({
            "group": group,
            "memberships": memberships,
            "reviewers": reviewers,
        })
    students = Student.query.order_by(Student.name.asc()).all()
    mentors = User.query.order_by(User.name.asc()).all()
    return render_template(
        "groups_list.html",
        groups=group_rows,
        students=students,
        mentors=mentors,
        form_data=form_data,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects")
@require_user()
def projects_list():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template(
        "projects_list.html",
        projects=projects,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/projects/<code>/delete")
@require_user()
def projects_delete(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    db.session.delete(project)
    db.session.commit()
    return redirect(url_for("projects_list"))

@app.route("/projects/new", methods=["GET", "POST"])
@require_user()
def projects_new():
    form_data = {
        "title": request.form.get("title") or "",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "required_task_count": request.form.get("required_task_count") or "",
        "points": request.form.get("points") or "",
        "retry_cooldown_hours": request.form.get("retry_cooldown_hours") or "",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        if not title:
            error = "Project title is required."
        required_count = None
        rtc_raw = form_data["required_task_count"].strip()
        if rtc_raw:
            try:
                required_count = max(0, int(rtc_raw))
            except Exception:
                error = "Required task count must be a number."
        points_value = 0
        points_raw = form_data["points"].strip()
        if points_raw and not error:
            try:
                points_value = max(0, int(points_raw))
            except Exception:
                error = "Points must be a number."
        retry_hours_value = 0
        retry_raw = form_data["retry_cooldown_hours"].strip()
        if retry_raw and not error:
            try:
                retry_hours_value = max(0, int(retry_raw))
            except Exception:
                error = "Retry cooldown must be a number (hours)."
        if not error:
            code = gen_code(8)
            while Project.query.filter_by(code=code).first() is not None:
                code = gen_code(8)
            project = Project(
                code=code,
                title=title,
                description=form_data["description"].strip() or None,
                instructions=form_data["instructions"].strip() or None,
                required_task_count=required_count,
                is_active=False,
                points=points_value,
                retry_cooldown_hours=retry_hours_value,
            )
            db.session.add(project)
            db.session.commit()
            return redirect(url_for("projects_show", code=project.code))
    return render_template(
        "projects_new.html",
        form_data=form_data,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>")
@require_user()
def projects_show(code):
    project = Project.query.filter_by(code=code).first_or_404()
    tasks = ProjectTask.query.filter_by(project_id=project.id).order_by(ProjectTask.order_index.asc(), ProjectTask.id.asc()).all()
    deps = ProjectDependency.query.filter_by(project_id=project.id).all()
    other_projects = Project.query.filter(Project.id != project.id).order_by(Project.title.asc()).all()
    assignments = ProjectGroupAssignment.query.filter_by(project_id=project.id).order_by(ProjectGroupAssignment.applies_to_all.desc(), ProjectGroupAssignment.created_at.asc()).all()
    student_groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    return render_template(
        "projects_show.html",
        project=project,
        tasks=tasks,
        dependencies=deps,
        other_projects=other_projects,
        group_assignments=assignments,
        student_groups=student_groups,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/projects/<code>/update-meta")
@require_user()
def projects_update_meta(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    points_raw = (request.form.get("points") or "").strip()
    retry_raw = (request.form.get("retry_cooldown_hours") or "").strip()
    try:
        points_val = int(points_raw) if points_raw else project.points or 0
        retry_val = int(retry_raw) if retry_raw else project.retry_cooldown_hours or 0
    except Exception:
        abort(400, "Points and retry cooldown must be numbers.")
    project.points = max(0, points_val)
    project.retry_cooldown_hours = max(0, retry_val)
    db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.post("/projects/<code>/publish")
@require_user()
def projects_publish(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    state = request.form.get("state") or "publish"
    project.is_active = (state == "publish")
    db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.post("/projects/<code>/dependencies")
@require_user()
def projects_add_dependency(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    dep_code = (request.form.get("dependency_code") or "").strip()
    prerequisite = Project.query.filter_by(code=dep_code).first()
    if prerequisite and prerequisite.id != project.id:
        exists = ProjectDependency.query.filter_by(project_id=project.id, prerequisite_id=prerequisite.id).first()
        if not exists:
            dep = ProjectDependency(project_id=project.id, prerequisite_id=prerequisite.id)
            db.session.add(dep)
            db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.post("/projects/<code>/groups")
@require_user()
def projects_assign_group(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    scope = (request.form.get("group_scope") or "").strip()
    required_flag = request.form.get("is_required") == "1"
    assignment = None
    if scope == "all":
        assignment = ProjectGroupAssignment.query.filter_by(project_id=project.id, applies_to_all=True).first()
        if assignment:
            assignment.is_required = required_flag
        else:
            assignment = ProjectGroupAssignment(
                project_id=project.id,
                applies_to_all=True,
                is_required=required_flag,
            )
            db.session.add(assignment)
    else:
        try:
            group_id = int(scope)
        except ValueError:
            group_id = None
        if group_id:
            group = StudentGroup.query.get(group_id)
            if group:
                assignment = ProjectGroupAssignment.query.filter_by(project_id=project.id, group_id=group.id).first()
                if assignment:
                    assignment.is_required = required_flag
                else:
                    assignment = ProjectGroupAssignment(
                        project_id=project.id,
                        group_id=group.id,
                        is_required=required_flag,
                    )
                    db.session.add(assignment)
    if assignment:
        db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.post("/projects/<code>/groups/<int:assignment_id>/remove")
@require_user()
def projects_remove_group_assignment(code, assignment_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    assignment = ProjectGroupAssignment.query.filter_by(id=assignment_id, project_id=project.id).first()
    if assignment:
        db.session.delete(assignment)
        db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.route("/projects/tasks/schema")
@require_user()
def projects_tasks_schema():
    return jsonify(PROJECT_TASKS_SCHEMA)

@app.route("/projects/<code>/tasks/new", methods=["GET", "POST"])
@require_user()
def projects_task_new(code):
    project = Project.query.filter_by(code=code).first_or_404()
    req_flag = request.form.get("required")
    auto_flag = request.form.get("auto_grade")
    review_flag = request.form.get("requires_review")
    form_data = {
        "title": request.form.get("title") or "",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "questions_payload": request.form.get("questions_payload") or "[]",
        "required": True if request.method != "POST" and req_flag is None else bool(req_flag),
        "auto_grade": True if request.method != "POST" and auto_flag is None else (auto_flag == "1"),
        "requires_review": bool(review_flag),
        "question_type": request.form.get("question_type") or "mcq",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        if not title:
            error = "Task title is required."
        questions = []
        if not error:
            try:
                payload = json.loads(form_data["questions_payload"] or "[]")
                questions = _normalize_exam_questions(payload)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Unable to parse task questions."
        if not questions and not error:
            error = "Add at least one question for the task."
        if not error:
            order_index = (ProjectTask.query.filter_by(project_id=project.id).count() or 0) + 1
            task = ProjectTask(
                project_id=project.id,
                title=title,
                description=form_data["description"].strip() or None,
                instructions=form_data["instructions"].strip() or None,
                questions_json=questions,
                required=form_data["required"],
                auto_grade=form_data["auto_grade"],
                requires_review=form_data["requires_review"],
                order_index=order_index,
            )
            db.session.add(task)
            db.session.commit()
            return redirect(url_for("projects_show", code=project.code))
    return render_template(
        "projects_task_new.html",
        project=project,
        task=None,
        form_data=form_data,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/tasks/import", methods=["GET", "POST"])
@require_user()
def projects_task_import(code):
    project = Project.query.filter_by(code=code).first_or_404()
    error = None
    default_json = json.dumps({"tasks": []}, indent=2)
    payload = request.form.get("payload") or default_json
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        try:
            config = json.loads(payload or "{}")
        except ValueError as exc:
            error = f"Invalid JSON: {exc}"
        else:
            try:
                created = _import_project_tasks_from_config(project, config)
                db.session.commit()
                return redirect(url_for("projects_show", code=project.code))
            except ValueError as exc:
                db.session.rollback()
                error = str(exc)
            except Exception:
                db.session.rollback()
                error = "Unable to import tasks. Please review your JSON."
    schema_json = json.dumps(PROJECT_TASKS_SCHEMA, indent=2)
    return render_template(
        "projects_task_import.html",
        project=project,
        payload=payload,
        schema_json=schema_json,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@require_user()
def projects_task_edit(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    req_flag = request.form.get("required")
    auto_flag = request.form.get("auto_grade")
    review_flag = request.form.get("requires_review")
    if request.method == "POST":
        form_data = {
            "title": request.form.get("title") or "",
            "description": request.form.get("description") or "",
            "instructions": request.form.get("instructions") or "",
            "questions_payload": request.form.get("questions_payload") or "[]",
            "required": bool(req_flag),
            "auto_grade": (auto_flag == "1"),
            "requires_review": bool(review_flag),
            "question_type": request.form.get("question_type") or "mcq",
        }
    else:
        payload = json.dumps(task.questions_json or [], ensure_ascii=False)
        first_type = None
        if isinstance(task.questions_json, list) and task.questions_json:
            first_type = task.questions_json[0].get("type")
        form_data = {
            "title": task.title or "",
            "description": task.description or "",
            "instructions": task.instructions or "",
            "questions_payload": payload,
            "required": bool(task.required),
            "auto_grade": bool(task.auto_grade),
            "requires_review": bool(task.requires_review),
            "question_type": first_type or "mcq",
        }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        if not title:
            error = "Task title is required."
        questions = []
        if not error:
            try:
                payload = json.loads(form_data["questions_payload"] or "[]")
                questions = _normalize_exam_questions(payload)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Unable to parse task questions."
        if not questions and not error:
            error = "Add at least one question for the task."
        if not error:
            task.title = title
            task.description = form_data["description"].strip() or None
            task.instructions = form_data["instructions"].strip() or None
            task.questions_json = questions
            task.required = form_data["required"]
            task.auto_grade = form_data["auto_grade"]
            task.requires_review = form_data["requires_review"]
            db.session.commit()
            return redirect(url_for("projects_show", code=project.code))
    return render_template(
        "projects_task_new.html",
        project=project,
        task=task,
        form_data=form_data,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/projects/<code>/tasks/<int:task_id>/delete")
@require_user()
def projects_task_delete(code, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.route("/student/projects")
@require_student()
def student_projects():
    student = current_student()
    projects = Project.query.filter_by(is_active=True).order_by(Project.created_at.asc()).all()
    available_rows = []
    locked_rows = []
    completed_rows = []
    for project in projects:
        if not _project_visible_to_student(project, student):
            continue
        unlocked = _project_dependencies_met(project, student)
        completed = _project_completed(project, student) if unlocked else False
        tasks = []
        completed_count = 0
        for task in project.tasks:
            submission = _project_task_submission(task, student)
            status = submission.status if submission and submission.status else "not_started"
            if status in ("submitted", "accepted", "pending_review"):
                completed_count += 1
            cooldown_seconds = 0
            can_retry_now = True
            if submission:
                if status in ("pending_review", "submitted", "accepted"):
                    can_retry_now = False
                elif status == "rejected":
                    retry_hours = project.retry_cooldown_hours or 0
                    if retry_hours > 0 and submission.last_activity_at:
                        elapsed = (datetime.utcnow() - submission.last_activity_at).total_seconds()
                        wait_seconds = int(retry_hours * 3600 - elapsed)
                        if wait_seconds > 0:
                            can_retry_now = False
                            cooldown_seconds = wait_seconds
            tasks.append({
                "task": task,
                "status": status,
                "submission": submission,
                "can_retry_now": can_retry_now,
                "cooldown_seconds_remaining": cooldown_seconds,
            })
        row = {
            "project": project,
            "unlocked": unlocked,
            "completed": completed,
            "tasks": tasks,
            "completed_count": completed_count,
            "total_tasks": len(tasks),
            "required": _project_required_for_student(project, student),
            "dependencies": [dep.prerequisite.title for dep in (project.dependencies or []) if dep.prerequisite],
        }
        if completed:
            completed_rows.append(row)
        elif unlocked:
            available_rows.append(row)
        else:
            locked_rows.append(row)
    tab = request.args.get("tab", "active").lower()
    if tab not in ("active", "completed"):
        tab = "active"
    return render_template(
        "projects_student.html",
        available_projects=available_rows,
        locked_projects=locked_rows,
        completed_projects=completed_rows,
        selected_tab=tab,
        user=current_user(),
        student_name=student.name,
    )

def _task_exam_view(project, task):
    data = {
        "title": f"{project.title} — {task.title}",
        "description": task.description,
        "instructions": task.instructions,
        "starts_at": None,
        "ends_at": None,
        "duration_minutes": None,
        "code": f"{project.code}-{task.id}",
        "kind": "project_task",
        "project_code": project.code,
    }
    return type("TaskExamView", (), data)()

@app.route("/projects/<code>/task/<int:task_id>", methods=["GET", "POST"])
@require_student()
def project_task_take(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    student = current_student()
    if not _project_visible_to_student(project, student):
        abort(403)
    if not _project_dependencies_met(project, student):
        abort(403)
    submission = _project_task_submission(task, student)
    if not submission:
        submission = ProjectTaskSubmission(
            task_id=task.id,
            project_id=project.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
        )
        db.session.add(submission)
        db.session.commit()
    questions = task.questions_json if isinstance(task.questions_json, list) else []
    total_questions = len(questions)
    now = datetime.utcnow()
    cooldown_hours = project.retry_cooldown_hours or 0
    cooldown_seconds_remaining = 0
    status = submission.status if submission and submission.status else "in_progress"
    can_submit = status not in ("submitted", "pending_review", "accepted")
    if can_submit and cooldown_hours > 0 and status == "rejected":
        if submission.last_activity_at:
            elapsed = (now - submission.last_activity_at).total_seconds()
            wait_seconds = int(cooldown_hours * 3600 - elapsed)
            if wait_seconds > 0:
                can_submit = False
                cooldown_seconds_remaining = wait_seconds

    def clamp_q(idx):
        if total_questions <= 0:
            return 0
        try:
            val = int(idx)
        except Exception:
            val = 0
        return max(0, min(val, total_questions - 1))

    requested_q = request.args.get("q", "0")
    q_index = clamp_q(requested_q)
    draft_answers = _get_task_draft(task.id)
    base_answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    previous_answers = dict(base_answers)
    previous_answers.update(draft_answers)

    preview = False

    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        post_q_index = clamp_q(request.form.get("q_index", q_index))
        q_index = post_q_index
        current_question = questions[q_index] if total_questions else None
        if current_question:
            qid = current_question.get("id")
            if qid:
                field = f"answer_{qid}"
                if current_question.get("type") == "multi":
                    vals = request.form.getlist(field)
                    val = "||".join(vals)
                else:
                    val = request.form.get(field, "")
                draft_answers[qid] = val
                previous_answers[qid] = val
                _save_task_draft(task.id, draft_answers)
        action = request.form.get("nav_action") or request.form.get("nav_action_auto")
        if not action:
            if total_questions and q_index >= total_questions - 1:
                action = "submit"
            else:
                action = "next"
        if action == "submit":
            if not can_submit:
                return render_template(
                    "exams_take.html",
                    exam=_task_exam_view(project, task),
                    question=current_question,
                    total_questions=total_questions,
                    current_index=q_index,
                    has_prev=(q_index > 0),
                    has_next=(q_index + 1 < total_questions),
                    can_submit=False,
                    preview=preview,
                    already_submitted=True,
                    previous_answers=previous_answers,
                    time_remaining_seconds=None,
                    user=current_user(),
                    student_name=student.name,
                    run_log_url=url_for("projects_task_log_run", code=project.code, task_id=task.id),
                    cooldown_seconds_remaining=cooldown_seconds_remaining,
                ), 403
            answers = dict(base_answers)
            answers.update(draft_answers)
            grade_score = 0
            grade_total = 0
            grade_details = []
            if task.auto_grade:
                grade_score, grade_total, grade_details = _grade_exam_submission(task, answers)
            submission.answers_json = answers
            submission.score = grade_score
            submission.max_score = grade_total
            submission.last_activity_at = now
            submission.submitted_at = now
            if task.requires_review:
                submission.status = "pending_review"
            else:
                has_manual_review = any(d.get("manual_review") for d in (grade_details or []))
                if task.auto_grade and not has_manual_review and grade_total > 0:
                    if grade_score >= grade_total:
                        submission.status = "accepted"
                    else:
                        submission.status = "rejected"
                else:
                    submission.status = "submitted"
            if submission.status == "accepted":
                if _project_completed(project, student):
                    _award_project_points_if_needed(project, student)
            db.session.commit()
            _clear_task_draft(task.id)
            return render_template(
                "exams_submitted.html",
                exam=_task_exam_view(project, task),
                submission=submission,
                user=current_user(),
                student_name=student.name,
            )
        else:
            answers = dict(base_answers)
            answers.update(draft_answers)
            submission.answers_json = answers
            submission.last_activity_at = datetime.utcnow()
            db.session.commit()
            target = q_index
            if action == "prev":
                target = max(0, q_index - 1)
            elif action == "next":
                target = min(total_questions - 1, q_index + 1) if total_questions else 0
            return redirect(url_for("project_task_take", code=project.code, task_id=task.id, q=target))

    current_question = dict(questions[q_index]) if total_questions else None
    exam_view = _task_exam_view(project, task)
    return render_template(
        "exams_take.html",
        exam=exam_view,
        question=current_question,
        total_questions=total_questions,
        current_index=q_index,
        has_prev=(q_index > 0),
        has_next=(q_index + 1 < total_questions),
        can_submit=can_submit,
        preview=preview,
        already_submitted=(submission.status in ("submitted", "pending_review", "accepted", "rejected")),
        previous_answers=previous_answers,
        time_remaining_seconds=None,
        user=current_user(),
        student_name=student.name,
        run_log_url=url_for("projects_task_log_run", code=project.code, task_id=task.id),
        cooldown_seconds_remaining=cooldown_seconds_remaining,
    )

@app.route("/student/projects/<code>/tasks/<int:task_id>/submission")
@require_student()
def project_task_submission_self_view(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    student = current_student()
    if not _project_visible_to_student(project, student):
        abort(403)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(
        project_id=project.id,
        task_id=task.id,
        student_id=student.id,
    ).first_or_404()
    questions = task.questions_json if isinstance(task.questions_json, list) else []
    answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_by_question = _run_logs_by_question(submission.run_logs if hasattr(submission, "run_logs") else None)
    return render_template(
        "projects_submission_task_detail.html",
        project=project,
        student=student,
        task=task,
        submission=submission,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        user=current_user(),
        student_name=student.name,
    )

@app.post("/projects/<code>/students/<int:student_id>/reset")
@require_user()
def project_reset_student_progress(code, student_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    # delete all task submissions for this student/project
    subs = ProjectTaskSubmission.query.filter_by(project_id=project.id, student_id=student.id).all()
    for sub in subs:
        db.session.delete(sub)
    # remove awarded grade entry if present
    assignment_name = f"Project: {project.title}"
    Grade.query.filter_by(student_id=student.id, assignment=assignment_name).delete()
    db.session.commit()
    return redirect(url_for("projects_student_submissions", code=project.code, student_id=student.id))

@app.route("/api/projects/<code>/tasks/<int:task_id>/log-run", methods=["POST"])
def projects_task_log_run(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    student = current_student()
    if not student:
        abort(401)
    submission = _project_task_submission(task, student)
    if not submission:
        submission = ProjectTaskSubmission(
            task_id=task.id,
            project_id=project.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
        )
        db.session.add(submission)
        db.session.commit()
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    data = request.get_json(silent=True) or {}
    summary = {
        "question_id": data.get("question_id"),
        "samples": data.get("samples") or [],
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append(summary)
    submission.run_logs = logs
    submission.last_activity_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "log_count": len(logs)})

@app.route("/projects/<code>/submissions")
@require_user()
def projects_submissions_overview(code):
    project = Project.query.filter_by(code=code).first_or_404()
    tasks = project.tasks or []
    submissions = ProjectTaskSubmission.query.filter_by(project_id=project.id).order_by(ProjectTaskSubmission.last_activity_at.desc()).all()
    grouped = {}
    for sub in submissions:
        sid = sub.student_id
        key = sid if sid is not None else f"anon-{sub.id}"
        student = sub.student
        entry = grouped.setdefault(key, {
            "student": student,
            "student_id": sub.student_id,
            "student_name": (student.name if student else None) or (sub.student_name or "Unknown student"),
            "student_email": student.email if student else None,
            "subs": [],
        })
        entry["subs"].append(sub)
    student_rows = []
    total_tasks = len(tasks)
    for data in grouped.values():
        subs = data["subs"]
        attempted = len(subs)
        completed = sum(1 for s in subs if s.status in ("submitted", "pending_review", "accepted", "rejected"))
        accepted = sum(1 for s in subs if s.status == "accepted")
        pending = sum(1 for s in subs if s.status == "pending_review")
        in_progress = sum(1 for s in subs if s.status not in ("submitted", "pending_review", "accepted", "rejected"))
        last_activity = max((s.last_activity_at for s in subs if s.last_activity_at), default=None)
        student_rows.append({
            "student": data["student"],
            "student_id": data["student_id"],
            "student_name": data["student_name"],
            "student_email": data["student_email"],
            "attempted_count": attempted,
            "completed_count": completed,
            "accepted_count": accepted,
            "pending_count": pending,
            "in_progress_count": in_progress,
            "total_tasks": total_tasks,
            "last_activity": last_activity,
        })
    student_rows.sort(key=lambda row: row["last_activity"] or datetime.min, reverse=True)
    return render_template(
        "projects_submissions_overview.html",
        project=project,
        student_rows=student_rows,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/submissions/<int:student_id>")
@require_user()
def projects_student_submissions(code, student_id):
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    tasks = project.tasks or []
    submissions = ProjectTaskSubmission.query.filter_by(project_id=project.id, student_id=student_id).all()
    submissions_map = {sub.task_id: sub for sub in submissions}
    return render_template(
        "projects_student_submissions.html",
        project=project,
        student=student,
        tasks=tasks,
        submissions_map=submissions_map,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>")
@require_user()
def projects_submission_task_detail(code, student_id, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student_id).first_or_404()
    questions = task.questions_json if isinstance(task.questions_json, list) else []
    answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_by_question = _run_logs_by_question(submission.run_logs if hasattr(submission, "run_logs") else None)
    return render_template(
        "projects_submission_task_detail.html",
        project=project,
        student=student,
        task=task,
        submission=submission,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews")
@require_user()
def projects_reviews():
    user = current_user()
    sort_mode = request.args.get("sort", "newest")
    project_filter = request.args.get("project_id")
    try:
        project_filter_id = int(project_filter) if project_filter else None
    except ValueError:
        project_filter_id = None
    reviewer_groups = [rev.group_id for rev in getattr(user, "group_reviews", []) if rev.group_id]
    query = ProjectTaskSubmission.query.filter_by(status="pending_review")
    if project_filter_id:
        query = query.filter_by(project_id=project_filter_id)
    if sort_mode == "oldest":
        query = query.order_by(ProjectTaskSubmission.submitted_at.asc())
    else:
        sort_mode = "newest"
        query = query.order_by(ProjectTaskSubmission.submitted_at.desc())
    submissions = query.all()
    if reviewer_groups:
        allowed = set(reviewer_groups)
        pruned = []
        for sub in submissions:
            student = sub.student
            groups = {m.group_id for m in getattr(student, "group_memberships", []) if m.group_id} if student else set()
            if groups & allowed:
                pruned.append(sub)
        submissions = pruned
    projects = Project.query.order_by(Project.title.asc()).all()
    return render_template(
        "projects_reviews.html",
        submissions=submissions,
        filter_sort=sort_mode,
        filter_project_id=project_filter_id,
        reviewer_groups=reviewer_groups,
        projects=projects,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews/<int:submission_id>")
@require_user()
def projects_review_detail(submission_id):
    submission = ProjectTaskSubmission.query.get_or_404(submission_id)
    task = submission.task
    project = submission.project
    questions = task.questions_json if task and isinstance(task.questions_json, list) else []
    answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_by_question = _run_logs_by_question(submission.run_logs if hasattr(submission, "run_logs") else None)
    return render_template(
        "projects_review_detail.html",
        submission=submission,
        project=project,
        task=task,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/projects/reviews/<int:submission_id>")
@require_user()
def projects_review_decision(submission_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    submission = ProjectTaskSubmission.query.get_or_404(submission_id)
    action = request.form.get("action")
    notes = (request.form.get("review_notes") or "").strip()
    if action == "accept":
        submission.status = "accepted"
    elif action == "reject":
        submission.status = "rejected"
    if notes:
        submission.review_notes = notes
    submission.last_activity_at = datetime.utcnow()
    if submission.status == "accepted" and submission.student:
        if _project_completed(submission.project, submission.student):
            _award_project_points_if_needed(submission.project, submission.student)
    db.session.commit()
    return redirect(url_for("projects_reviews"))

# --------------------------------------------------------------------
# Gradebook
# --------------------------------------------------------------------

@app.route("/grades", methods=["GET", "POST"])
@require_user()
def grades_admin():
    message = session.pop("grades_status", None)
    error = session.pop("grades_error", None)
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        student_email = (request.form.get("student_email") or "").strip()
        assignment = (request.form.get("assignment") or "").strip()
        score_raw = request.form.get("score") or "0"
        max_raw = request.form.get("max_score") or "0"
        remarks = request.form.get("remarks") or ""
        student = _find_student_by_email(student_email)
        if not student:
            session["grades_error"] = "Student not found for email provided."
            return redirect(url_for("grades_admin"))
        if not assignment:
            session["grades_error"] = "Assignment/test name is required."
            return redirect(url_for("grades_admin"))
        try:
            score = float(score_raw)
            max_score = float(max_raw)
        except Exception:
            session["grades_error"] = "Score and maximum score must be numbers."
            return redirect(url_for("grades_admin"))
        _create_grade_entry(student, assignment, score, max_score, remarks)
        db.session.commit()
        session["grades_status"] = f"Recorded grade for {student.name}."
        return redirect(url_for("grades_admin"))

    grades = Grade.query.order_by(Grade.created_at.desc()).limit(200).all()
    return render_template(
        "grades_admin.html",
        grades=grades,
        message=message,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/grades/import")
@require_user()
def grades_import():
    if not verify_csrf():
        abort(400, "bad csrf")
    payload = request.form.get("payload") or ""
    fmt = (request.form.get("payload_format") or "json").lower()
    records = []
    errors = []
    created = 0
    if fmt == "csv":
        try:
            reader = csv.DictReader(io.StringIO(payload))
            for row in reader:
                records.append(row)
        except Exception as exc:
            session["grades_error"] = f"Unable to parse CSV: {exc}"
            return redirect(url_for("grades_admin"))
    else:
        try:
            data = json.loads(payload or "[]")
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError("JSON payload must be a list of objects.")
            for row in data:
                if isinstance(row, dict):
                    records.append(row)
        except Exception as exc:
            session["grades_error"] = f"Invalid JSON payload: {exc}"
            return redirect(url_for("grades_admin"))

    for idx, row in enumerate(records, start=1):
        email = str(row.get("student_email") or row.get("email") or "").strip()
        student_name = str(row.get("student_name") or row.get("student") or row.get("learner") or "").strip()
        assignment = str(row.get("assignment") or row.get("assignment_name") or row.get("title") or row.get("name") or "").strip()
        remarks = str(row.get("remarks") or row.get("comment") or "").strip()
        score_raw = row.get("score")
        max_raw = row.get("max_score") or row.get("max") or row.get("total")
        student = _find_student_by_email(email)
        if not student and student_name:
            student = _find_student_by_name(student_name)
        if not student:
            identifier = email or student_name or "unknown"
            errors.append(f"Row {idx}: unknown student '{identifier}'.")
            continue
        if not assignment:
            errors.append(f"Row {idx}: missing assignment/test name.")
            continue
        try:
            score = float(score_raw)
            max_score = float(max_raw)
        except Exception:
            errors.append(f"Row {idx}: invalid score/max values.")
            continue
        _create_grade_entry(student, assignment, score, max_score, remarks)
        created += 1

    if created:
        db.session.commit()
        msg = f"Imported {created} grade(s)."
        if errors:
            msg += f" Skipped {len(errors)} row(s)."
        session["grades_status"] = msg
    else:
        db.session.rollback()
        session["grades_error"] = errors[0] if errors else "No grades imported."
    return redirect(url_for("grades_admin"))

@app.route("/my-grades")
@require_student()
def student_grades():
    student = current_student()
    grades = Grade.query.filter_by(student_id=student.id).order_by(Grade.created_at.desc()).all()
    return render_template(
        "grades_student.html",
        grades=grades,
        user=current_user(),
        student_name=student.name,
    )

@app.route("/thanks")
def thanks():
    return render_template("thanks.html", user=current_user(), student_name=session.get("student_name"))

@app.route("/dashboard")
@require_user()
def dashboard_for_role():
    return redirect(url_for("index"))

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
