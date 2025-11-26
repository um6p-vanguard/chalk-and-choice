import os, io, base64, secrets, argparse, csv, random, functools, time, json, hmac, hashlib, re, sys, subprocess, tempfile, resource, signal
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import NotFound
from itsdangerous import URLSafeSerializer
from sqlalchemy import or_
from models import (db, Poll, Vote, Student, User, Form, 
                    FormResponse, LectureQuestion, LectureSignal,
                    StudentStats, Intervention, Notebook, StudentHomework,
                    Homework, HomeworkMessage, Mentor, CodeExercise,
                    CodeSubmission, StudentProgress, ExerciseSet, MentorSlot,
                    SlotBooking, Exam, ExamQuestion, ExamSubmission, ExamAnswer)
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

def compare_outputs(actual, expected):
    """
    Smart comparison of code outputs that handles Python data structures.
    Normalizes whitespace and evaluates Python literals when possible.
    
    Examples:
    - "['h', 'a', 'm']" == "['h','a','m']"  -> True
    - "[1, 2, 3]" == "[1,2,3]"  -> True
    - "{'a': 1, 'b': 2}" == "{'a':1,'b':2}"  -> True
    - "42" == "42.0"  -> False (different types)
    """
    if not actual and not expected:
        return True
    if not actual or not expected:
        return False
    
    # Trim both
    actual_trimmed = actual.strip()
    expected_trimmed = expected.strip()
    
    # Exact match (fastest path)
    if actual_trimmed == expected_trimmed:
        return True
    
    # Normalize whitespace in Python data structures
    def normalize_whitespace(s):
        # Remove spaces around brackets, braces, parentheses, commas, colons
        s = re.sub(r'\[\s+', '[', s)      # [ x -> [x
        s = re.sub(r'\s+\]', ']', s)      # x ] -> x]
        s = re.sub(r'\{\s+', '{', s)      # { x -> {x
        s = re.sub(r'\s+\}', '}', s)      # x } -> x}
        s = re.sub(r'\(\s+', '(', s)      # ( x -> (x
        s = re.sub(r'\s+\)', ')', s)      # x ) -> x)
        s = re.sub(r'\s*,\s*', ',', s)    # x , y -> x,y
        s = re.sub(r'\s*:\s*', ':', s)    # x : y -> x:y
        s = re.sub(r'\s+', ' ', s)        # multiple spaces -> single
        return s.strip()
    
    actual_normalized = normalize_whitespace(actual_trimmed)
    expected_normalized = normalize_whitespace(expected_trimmed)
    
    if actual_normalized == expected_normalized:
        return True
    
    # Try to evaluate as Python literals if they look like data structures
    def is_python_literal(s):
        s = s.strip()
        return (
            (s.startswith('[') and s.endswith(']')) or   # List
            (s.startswith('(') and s.endswith(')')) or   # Tuple
            (s.startswith('{') and s.endswith('}')) or   # Dict/Set
            s in ('True', 'False', 'None') or             # Boolean/None
            re.match(r'^-?\d+$', s) or                    # Integer
            re.match(r'^-?\d+\.\d+$', s)                  # Float
        )
    
    if is_python_literal(actual_trimmed) and is_python_literal(expected_trimmed):
        try:
            # Safely evaluate Python literals
            import ast
            actual_val = ast.literal_eval(actual_trimmed)
            expected_val = ast.literal_eval(expected_trimmed)
            return actual_val == expected_val
        except (ValueError, SyntaxError):
            # If evaluation fails, fall through to string comparison
            pass
    
    # Case-insensitive comparison as last resort (for text outputs)
    return actual_normalized.lower() == expected_normalized.lower()

# --------------------------------------------------------------------
# Server-side code execution helper (minimal sandbox)
# --------------------------------------------------------------------
def _run_python_code_isolated(code: str, input_text: str, timeout_sec: float = 3.0):
    """Run arbitrary Python code with limited resources and capture stdout.
    This is used for grading code exam questions on the server without
    exposing hidden tests to clients.
    """
    start = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "main.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(code or "")

            def _limit_resources():
                try:
                    # CPU seconds
                    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
                    # Address space (approx memory) ~256MB
                    mem = 256 * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
                    # File size limits ~1MB
                    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
                    # Prevent core dumps
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass

            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env["PYTHONIOENCODING"] = "utf-8"

            proc = subprocess.run(
                [sys.executable, "-S", path],
                input=(input_text or "").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tmpdir,
                timeout=timeout_sec,
                env=env,
                preexec_fn=_limit_resources,
            )
            elapsed = int((time.perf_counter() - start) * 1000)
            out = proc.stdout.decode("utf-8", errors="replace")
            err = proc.stderr.decode("utf-8", errors="replace")
            return {
                "success": proc.returncode == 0,
                "output": out,
                "error": err,
                "time_ms": elapsed,
            }
    except subprocess.TimeoutExpired as te:
        elapsed = int((time.perf_counter() - start) * 1000)
        out = te.stdout.decode("utf-8", errors="replace") if te.stdout else ""
        return {"success": False, "output": out, "error": "Timeout", "time_ms": elapsed}
    except Exception as e:
        elapsed = int((time.perf_counter() - start) * 1000)
        return {"success": False, "output": "", "error": str(e), "time_ms": elapsed}

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

def current_mentor():
    """Get the Mentor object if current user is a mentor"""
    u = current_user()
    if u and u.role == "mentor" and u.mentor_id:
        return Mentor.query.get(u.mentor_id)
    return None

def logout_everyone():
    session.pop("user_id", None)
    session.pop("user_role", None)
    session.pop("student_id", None)
    session.pop("student_name", None)
    session.pop("must_change_pw", None)

# --------------------------------------------------------------------
# Mentor assignment helper (round-robin per homework)
# --------------------------------------------------------------------
def assign_mentor_to_homework(homework_id, student_homework_id):
    """
    Assign a mentor to a student homework using round-robin strategy.
    Each homework has its own independent assignment sequence.
    Returns the assigned Mentor object or None if no active mentors.
    """
    # Get all active mentors ordered by ID for consistent round-robin
    active_mentors = Mentor.query.filter_by(is_active=True).order_by(Mentor.id).all()
    
    if not active_mentors:
        return None
    
    # Count how many submissions for THIS homework already have mentors assigned
    # This gives us the position in the round-robin sequence
    assigned_count = (StudentHomework.query
                      .filter_by(homework_id=homework_id)
                      .filter(StudentHomework.assigned_mentor_id.isnot(None))
                      .count())
    
    # Round-robin: use modulo to cycle through mentors
    mentor_index = assigned_count % len(active_mentors)
    assigned_mentor = active_mentors[mentor_index]
    
    # Update the student homework record
    sh = StudentHomework.query.get(student_homework_id)
    if sh:
        sh.assigned_mentor_id = assigned_mentor.id
        sh.assigned_at = datetime.now()
        db.session.commit()
    
    return assigned_mentor

def require_user(role=None):
    """
    Decorator to require user authentication.
    If role is specified, checks if user has that role.
    Role can be: 'admin', 'instructor', 'mentor', or a list like ['admin', 'instructor']
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if role:
                if isinstance(role, list):
                    if u.role not in role:
                        abort(403)
                elif u.role != role:
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

#---------------------------------------------------------------------
# Homework helpers
#---------------------------------------------------------------------

def _active_homeworks_for_student(student):
    """Return homeworks open for this student and not yet submitted by them."""
    now = datetime.now()  # naive local time
    # Open window: (open_at is null or <= now) AND (due_at is null or >= now)
    open_q = (Homework.query
              .filter(or_(Homework.open_at == None, Homework.open_at <= now))
              .filter(or_(Homework.due_at == None, Homework.due_at >= now))
              .order_by(Homework.created_at.desc()))

    items = []
    for hw in open_q.all():
        sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=student.id).first()
        # Hide if already submitted
        if sh and sh.submitted_at:
            continue
        items.append({
            "code": hw.code,
            "title": hw.title,
            "description": hw.description,
            "open_at": hw.open_at,
            "due_at": hw.due_at,
            "has_copy": bool(sh),
        })
    return items



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
                acct_user.last_login = datetime.now()
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
                acct_student.last_login = datetime.now()
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
    if session.get("student_id"):
        s = current_student()
        
        # Get available exercise sets for student home
        now = datetime.now()
        available_sets_query = (
            ExerciseSet.query
            .filter(ExerciseSet.is_published == True)
            .filter(or_(
                ExerciseSet.available_from == None,
                ExerciseSet.available_from <= now
            ))
            .filter(or_(
                ExerciseSet.available_until == None,
                ExerciseSet.available_until >= now
            ))
            .order_by(ExerciseSet.created_at.desc())
            .limit(6)  # Show 6 most recent on home
        )
        
        available_exercises = []
        for ex_set in available_sets_query.all():
            # Count exercises in set
            exercise_count = len(ex_set.exercises)
            
            # Check progress - count completed exercises in this set
            completed_count = 0
            total_points = 0
            for ex in ex_set.exercises:
                total_points += ex.points
                progress = StudentProgress.query.filter_by(
                    student_id=s.id,
                    exercise_id=ex.id,
                    completed=True
                ).first()
                if progress:
                    completed_count += 1
            
            available_exercises.append({
                "code": ex_set.code,
                "title": ex_set.title,
                "description": ex_set.description,
                "exercise_count": exercise_count,
                "completed_count": completed_count,
                "total_points": total_points,
                "is_completed": completed_count == exercise_count if exercise_count > 0 else False
            })
        
        exams_data = []
        now = datetime.now()
        for exm in Exam.query.filter_by(is_published=True).order_by(Exam.start_at.asc()).all():
            # Hide exams that have already ended
            if exm.end_at and now > exm.end_at:
                continue
            is_open = bool(exm.start_at and exm.start_at <= now and (exm.end_at is None or now <= exm.end_at))
            sub = ExamSubmission.query.filter_by(exam_id=exm.id, student_id=s.id).first()
            submitted = bool(sub and sub.submitted_at)
            exams_data.append({
                "code": exm.code,
                "title": exm.title,
                "description": exm.description,
                "start_at": exm.start_at,
                "end_at": exm.end_at,
                "is_open": is_open,
                "submitted": submitted
            })

        return render_template(
            "index.html",
            student_name=s.name,
            polls=polls,
            user=None,
            active_homeworks=_active_homeworks_for_student(s),
            available_exercises=available_exercises,
            available_exams=exams_data
        )
    return render_template("index.html", user=u, polls=polls, student_name=session.get("student_name"))

@app.get("/api/me")
@require_student()
def api_me():
    s = current_student()
    return jsonify({"id": s.id, "name": s.name})

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
        iv.started_at = datetime.now()
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

    iv.ended_at = datetime.now()
    iv.status = "completed"

    # Update StudentStats
    ss = StudentStats.query.filter_by(student_id=iv.student_id).first()
    if not ss:
        ss = StudentStats(student_id=iv.student_id, times_spoken=0, current_round_done=False)
        db.session.add(ss)
    ss.times_spoken += 1
    ss.last_spoken_at = datetime.now()
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
    now = datetime.now()
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
    
    now = datetime.now()
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

#---------------------------------------------------------------------
# Notebook management apis
#---------------------------------------------------------------------

def _filename_from_nb(nb_json, fallback: str) -> str:
    """Return the saved file name from notebook metadata (chalk_name) or fallback."""
    try:
        meta = (nb_json.get("metadata") or {})
        name = (meta.get("chalk_name") or "").strip()
        return name if name else fallback
    except Exception:
        return fallback

def _parse_dt_local(s: str | None):
    if not s:
        return None
    try:
        # Accept HTML <input type="datetime-local"> format (naive)
        return datetime.fromisoformat(s)
    except Exception:
        return None

@app.route("/notebooks")
@require_student()
def notebooks_page():
    # Embeds JupyterLite (iframe). The plugin handles load/save.
    s = current_student()
    return render_template("notebooks.html", student_name=s.name if s else session.get("student_name"))

@app.route("/my-notebooks")
@require_student()
def my_notebooks_page():
    s = current_student()
    rows = (Notebook.query
            .filter_by(student_id=s.id)
            .order_by(Notebook.updated_at.desc())
            .all())
    items = []
    now = datetime.now()
    for nb in rows:
        meta = (nb.content_json.get("metadata") or {})
        code = (meta.get("homework_code") or "").strip()
        fname = _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb")
        submitted = False
        due_at = None
        can_submit = False
        feedback = None
        reopened = False
        mentor_name = None
        
        if code:
            hw = Homework.query.filter_by(code=code).first()
            sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first() if hw else None
            if sh:
                # Check if actually locked (submitted and not reopened)
                is_locked = bool(sh.submitted_at and not sh.reopened_at)
                submitted = is_locked
                feedback = sh.feedback
                reopened = bool(sh.reopened_at)
                due_at = hw.due_at if hw else None
                can_submit = (not is_locked) and (not due_at or now <= due_at)
                # Get mentor info
                if sh.assigned_mentor_id:
                    mentor = Mentor.query.get(sh.assigned_mentor_id)
                    mentor_name = mentor.name if mentor else None
            else:
                due_at = hw.due_at if hw else None
                can_submit = (not due_at or now <= due_at)
                
        items.append({
            "id": nb.id,
            "name": fname,
            "updated_at": nb.updated_at,
            "is_homework": bool(code),
            "homework_code": code if code else None,
            "submitted": submitted,
            "due_at": due_at,
            "can_submit": can_submit,
            "feedback": feedback,
            "reopened": reopened,
            "mentor_name": mentor_name
        })
    return render_template("my_notebooks.html", notebooks=items, student_name=s.name if s else session.get("student_name"))


# -------------------------
# CSRF for JS clients
# -------------------------

@app.get("/api/csrf")
def api_csrf():
    """CSRF token endpoint - accessible to both students and instructors"""
    # Require authentication but allow both user types
    if not (current_user() or current_student()):
        abort(401)
    return jsonify({"csrf": csrf_token()})

# -------------------------
# Notebook APIs (student-scoped)
# -------------------------

@app.get("/api/notebooks")
@require_student()
def notebooks_list():
    s = current_student()
    rows = (Notebook.query
            .filter_by(student_id=s.id)
            .order_by(Notebook.updated_at.desc())
            .all())
    res = []
    for nb in rows:
        fname = _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb")
        res.append({
            "id": nb.id,
            "name": fname,
            "updated_at": nb.updated_at.isoformat()
        })
    return jsonify({"items": res})

@app.get("/api/notebooks/<int:nb_id>")
@require_student()
def notebooks_get(nb_id: int):
    s = current_student()
    nb = Notebook.query.filter_by(id=nb_id, student_id=s.id).first()
    if not nb:
        raise NotFound()
    name = _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb")
    return jsonify({"id": nb.id, "name": name, "content": nb.content_json})

@app.get("/api/notebooks/<int:nb_id>/student-homework-id")
@require_student()
def notebooks_get_student_homework_id(nb_id: int):
    """Get the student_homework_id for a notebook if it's associated with a homework"""
    s = current_student()
    nb = Notebook.query.filter_by(id=nb_id, student_id=s.id).first()
    if not nb:
        raise NotFound()
    
    # Check if this notebook is associated with a homework
    sh = StudentHomework.query.filter_by(notebook_id=nb.id, student_id=s.id).first()
    
    if sh:
        return jsonify({"student_homework_id": sh.id})
    else:
        return jsonify({"student_homework_id": None})

@app.post("/api/notebooks")
@require_student()
def notebooks_create():
    data = request.get_json(silent=True) or {}
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    content = data.get("content")
    if not isinstance(content, dict):
        abort(400, description="Missing/invalid content")
    s = current_student()
    nb = Notebook(student_id=s.id, content_json=content)
    db.session.add(nb)
    db.session.commit()
    return jsonify({"id": nb.id})

@app.put("/api/notebooks/<int:nb_id>")
@require_student()
def notebooks_update(nb_id: int):
    data = request.get_json(silent=True) or {}
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    content = data.get("content")
    if not isinstance(content, dict):
        abort(400, description="Missing/invalid content")

    s = current_student()
    nb = Notebook.query.filter_by(id=nb_id, student_id=s.id).first()
    if not nb:
        raise NotFound()

    # If this notebook is a homework copy and already submitted, block edits
    sh = StudentHomework.query.filter_by(notebook_id=nb.id, student_id=s.id).first()
    if sh and sh.submitted_at:
        abort(403, description="Homework already submitted (read-only)")

    nb.content_json = content
    db.session.commit()
    return jsonify({"ok": True})


@app.delete("/api/notebooks/<int:nb_id>")
@require_student()
def notebooks_delete(nb_id: int):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    s = current_student()
    nb = Notebook.query.filter_by(id=nb_id, student_id=s.id).first()
    if not nb:
        raise NotFound()
    db.session.delete(nb)
    db.session.commit()
    return jsonify({"ok": True})

#---------------------------------------------------------------------
# Homework management
#---------------------------------------------------------------------

@app.get("/homework/new")
@require_user()  # instructors/admins
def homework_new():
    return render_template("homework_new.html", user=current_user(), student_name=session.get("student_name"))

@app.post("/homework/new")
@require_user()
def homework_create():
    verify_csrf()
    title = (request.form.get("title") or "").strip() or "Homework"
    description = (request.form.get("description") or "").strip()
    open_at = _parse_dt_local(request.form.get("open_at"))
    due_at  = _parse_dt_local(request.form.get("due_at"))

    file = request.files.get("ipynb")
    raw_json = request.form.get("template_json")

    if not file and not raw_json:
        abort(400, description="Upload a .ipynb or paste JSON")

    try:
        template_json = json.load(file.stream) if file else json.loads(raw_json)
    except Exception:
        abort(400, description="Invalid notebook JSON")

    md = (template_json.get("metadata") or {})
    if not md.get("chalk_name"):
        md["chalk_name"] = f"{title}.ipynb" if not title.lower().endswith(".ipynb") else title
        template_json["metadata"] = md

    code = gen_code()
    hw = Homework(
        code=code,
        title=title,
        description=description,
        template_json=template_json,
        open_at=open_at,
        due_at=due_at,
        creator_user_id=current_user().id
    )
    db.session.add(hw)
    db.session.commit()
    return redirect(url_for("homework_share", code=code))

@app.get("/homework")
@require_user()
def homework_list():
    hws = Homework.query.order_by(Homework.created_at.desc()).all()
    items = []
    for hw in hws:
        created = (StudentHomework.query
                   .filter_by(homework_id=hw.id)
                   .count())
        submitted = (StudentHomework.query
                     .filter(StudentHomework.homework_id == hw.id,
                             StudentHomework.submitted_at.isnot(None))
                     .count())

        items.append({
            "title": hw.title,
            "code": hw.code,
            "open_at": hw.open_at,
            "due_at": hw.due_at,
            "is_open": hw.is_open,
            "created_count": created,
            "submitted_count": submitted
        })
    return render_template("homework_list.html", items=items, user=current_user(), student_name=session.get("student_name"))

@app.get("/homework/<code>/submissions")
@require_user()
def homework_submissions(code):
    hw = Homework.query.filter_by(code=code).first_or_404()
    u = current_user()
    
    # join StudentHomework -> Notebook -> Student -> Mentor for display
    q = (db.session.query(StudentHomework, Notebook, Student, Mentor)
         .join(Notebook, Notebook.id == StudentHomework.notebook_id)
         .join(Student, Student.id == StudentHomework.student_id)
         .outerjoin(Mentor, Mentor.id == StudentHomework.assigned_mentor_id)
         .filter(StudentHomework.homework_id == hw.id))
    
    # If user is a mentor, only show homework assigned to them
    if u.role == "mentor":
        m = current_mentor()
        if m:
            q = q.filter(StudentHomework.assigned_mentor_id == m.id)
    
    q = q.order_by(StudentHomework.created_at.asc())
    items = []
    for sh, nb, st, mentor in q.all():
        items.append({
            "student_homework_id": sh.id,
            "student_id": st.id,
            "student_name": st.name,
            "notebook_id": nb.id,
            "filename": _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb"),
            "updated_at": nb.updated_at,
            "submitted_at": sh.submitted_at,
            "feedback": sh.feedback,
            "feedback_at": sh.feedback_at,
            "reopened_at": sh.reopened_at,
            "assigned_mentor": mentor.name if mentor else None,
            "assigned_mentor_email": mentor.email if mentor else None,
            "assigned_at": sh.assigned_at,
            "acceptance_status": sh.acceptance_status,
            "acceptance_comment": sh.acceptance_comment,
            "reviewed_at": sh.reviewed_at
        })
    return render_template("homework_submissions.html", hw=hw, items=items, user=current_user(), student_name=session.get("student_name"))

@app.get("/homework/<code>/share")
@require_user()
def homework_share(code):
    hw = Homework.query.filter_by(code=code).first_or_404()
    share_url = url_for("homework_open", code=hw.code, _external=True)
    return render_template("homework_share.html", hw=hw, share_url=share_url, user=current_user(), student_name=session.get("student_name"))

# optional QR (similar to polls/forms)
@app.get("/homework/<code>/qr.png")
@require_user()
def homework_qr(code):
    from io import BytesIO
    hw = Homework.query.filter_by(code=code).first_or_404()
    url = url_for("homework_open", code=code, _external=True)
    img = qrcode.make(url, box_size=8, border=2)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.get("/hw/<code>")
@require_student()
def homework_open(code):
    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first()
    
    # Show locked page only if submitted AND not reopened
    if sh and sh.submitted_at and not sh.reopened_at:
        nb = Notebook.query.get(sh.notebook_id) if sh else None
        mentor = Mentor.query.get(sh.assigned_mentor_id) if sh and sh.assigned_mentor_id else None
        return render_template("homework_locked.html", hw=hw, sh=sh, nb=nb, mentor=mentor, student_name=s.name if s else session.get("student_name"))
    
    # If reopened or not yet submitted, allow access (pass sh for chat functionality)
    return render_template("homework_play.html", hw=hw, sh=sh, student_name=s.name if s else session.get("student_name"))

@app.get("/api/hw/<code>/my")
@require_student()
def api_hw_my(code):
    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first()

    if sh and sh.submitted_at:
        return jsonify({"submitted": True}), 403

    # Lazy-create student's personal copy on first open
    if not sh:
        nb_json = json.loads(json.dumps(hw.template_json))  # deep copy
        md = nb_json.get("metadata") or {}
        # ensure filename metadata is present
        if not md.get("chalk_name"):
            md["chalk_name"] = f"{hw.title}-{s.name or s.id}.ipynb"
            nb_json["metadata"] = md
        # mark homework linkage (optional, helps filtering)
        md["homework_code"] = hw.code
        nb = Notebook(student_id=s.id, content_json=nb_json)
        db.session.add(nb)
        db.session.flush()
        sh = StudentHomework(homework_id=hw.id, student_id=s.id, notebook_id=nb.id)
        db.session.add(sh)
        db.session.commit()

    nb = Notebook.query.filter_by(id=sh.notebook_id, student_id=s.id).first()
    if not nb:
        raise NotFound()

    name = _filename_from_nb(nb.content_json, f"{hw.title}-{s.id}.ipynb")
    return jsonify({
        "submitted": False,
        "notebook_id": nb.id,
        "student_homework_id": sh.id,
        "name": name,
        "content": nb.content_json
    })

@app.get("/api/hw/<code>/student-homework-id")
@require_student()
def api_hw_student_homework_id(code):
    """Get the student_homework.id for chat functionality"""
    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first()
    
    if not sh:
        # Create it if it doesn't exist (same as api_hw_my)
        nb_json = json.loads(json.dumps(hw.template_json))
        md = nb_json.get("metadata") or {}
        if not md.get("chalk_name"):
            md["chalk_name"] = f"{hw.title}-{s.name or s.id}.ipynb"
            nb_json["metadata"] = md
        md["homework_code"] = hw.code
        nb = Notebook(student_id=s.id, content_json=nb_json)
        db.session.add(nb)
        db.session.flush()
        sh = StudentHomework(homework_id=hw.id, student_id=s.id, notebook_id=nb.id)
        db.session.add(sh)
        db.session.commit()
    
    return jsonify({"student_homework_id": sh.id})

@app.get("/api/hw/<code>/status")
@require_student()
def api_hw_status(code):
    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first()
    if not sh:
        return jsonify({
            "exists": False, 
            "submitted": False, 
            "reopened": False,
            "due_at": hw.due_at.isoformat() if hw.due_at else None
        })
    
    # If reopened, treat as not submitted for editing purposes
    is_locked = bool(sh.submitted_at and not sh.reopened_at)
    
    return jsonify({
        "exists": True, 
        "submitted": is_locked,
        "reopened": bool(sh.reopened_at),
        "due_at": hw.due_at.isoformat() if hw.due_at else None
    })


@app.put("/api/hw/<code>/save")
@require_student()
def api_hw_save(code):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")

    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first_or_404()
    
    # Block saves only if submitted AND not reopened
    if sh.submitted_at and not sh.reopened_at:
        abort(403, description="Already submitted")

    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if not isinstance(content, dict):
        abort(400, description="Missing/invalid content")

    nb = Notebook.query.filter_by(id=sh.notebook_id, student_id=s.id).first_or_404()
    nb.content_json = content
    db.session.commit()
    return jsonify({"ok": True, "id": nb.id})

@app.post("/api/hw/<code>/submit")
@require_student()
def api_hw_submit(code):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")

    hw = Homework.query.filter_by(code=code).first_or_404()
    s = current_student()
    sh = StudentHomework.query.filter_by(homework_id=hw.id, student_id=s.id).first_or_404()

    # lock if past due
    if hw.due_at and datetime.now() > hw.due_at:
        abort(403, description="Past due")

    # Allow resubmission if reopened (clear reopened timestamp on resubmit)
    if sh.submitted_at and not sh.reopened_at:
        return jsonify({"ok": True, "already": True})

    # Assign mentor on FIRST submission only (mentor persists through reopens/resubmissions)
    if not sh.assigned_mentor_id:
        assigned_mentor = assign_mentor_to_homework(hw.id, sh.id)
        mentor_info = {
            "mentor_assigned": assigned_mentor is not None,
            "mentor_name": assigned_mentor.name if assigned_mentor else None,
            "mentor_email": assigned_mentor.email if assigned_mentor else None
        }
    else:
        # Mentor already assigned (resubmission after reopen)
        mentor = Mentor.query.get(sh.assigned_mentor_id)
        mentor_info = {
            "mentor_assigned": True,
            "mentor_name": mentor.name if mentor else None,
            "mentor_email": mentor.email if mentor else None,
            "note": "Keeping existing mentor assignment"
        }

    sh.submitted_at = datetime.now()
    sh.reopened_at = None  # Clear reopened flag on resubmission
    db.session.commit()
    
    return jsonify({"ok": True, **mentor_info})


# Admin: Add feedback to student homework
@app.post("/api/homework/submission/<int:sh_id>/feedback")
@require_user()
def api_homework_add_feedback(sh_id: int):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    data = request.get_json(silent=True) or {}
    feedback_text = (data.get("feedback") or "").strip()
    
    if not feedback_text:
        abort(400, description="Feedback text required")
    
    sh = StudentHomework.query.get_or_404(sh_id)
    u = current_user()
    
    sh.feedback = feedback_text
    sh.feedback_by_user_id = u.id
    sh.feedback_at = datetime.now()
    db.session.commit()
    
    return jsonify({"ok": True, "feedback_at": sh.feedback_at.isoformat()})


# Admin: Reopen homework for a student
@app.post("/api/homework/submission/<int:sh_id>/reopen")
@require_user()
def api_homework_reopen(sh_id: int):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    sh = StudentHomework.query.get_or_404(sh_id)
    u = current_user()
    
    # Clear submission timestamp to allow re-editing
    sh.submitted_at = None
    sh.reopened_at = datetime.now()
    sh.reopened_by_user_id = u.id
    db.session.commit()
    
    return jsonify({"ok": True, "reopened_at": sh.reopened_at.isoformat()})


# Get chat messages for homework submission (only student and assigned mentor can access)
@app.get("/api/homework/submission/<int:sh_id>/messages")
def api_homework_messages(sh_id: int):
    u = current_user()
    s = current_student()
    
    if not (u or s):
        abort(401)
    
    sh = StudentHomework.query.get_or_404(sh_id)
    
    # Students can only see their own homework messages
    if s and sh.student_id != s.id:
        abort(403)
    
    # Mentors can only see messages for homework assigned to them
    if u and u.role == "mentor":
        mentor = current_mentor()
        if not mentor or sh.assigned_mentor_id != mentor.id:
            abort(403, description="You can only view messages for homework assigned to you")
    
    # Admins and regular instructors cannot access chat (privacy between student and mentor)
    if u and u.role in ["admin", "instructor"]:
        abort(403, description="Chat is private between student and assigned mentor")
    
    messages = HomeworkMessage.query.filter_by(student_homework_id=sh_id)\
                                    .order_by(HomeworkMessage.created_at.asc())\
                                    .all()
    
    # Count unread messages for the current user
    unread_count = 0
    if s:
        # For student: count mentor messages that are newer than last read
        unread_count = sum(1 for msg in messages 
                          if msg.sender_type == 'mentor' 
                          and (not msg.student_read_at or msg.created_at > msg.student_read_at))
    elif u and u.role == "mentor":
        # For mentor: count student messages that are newer than last read
        unread_count = sum(1 for msg in messages 
                          if msg.sender_type == 'student' 
                          and (not msg.instructor_read_at or msg.created_at > msg.instructor_read_at))
    
    return jsonify({
        "messages": [{
            "id": msg.id,
            "sender_type": msg.sender_type,
            "sender_name": msg.sender_name,
            "message": msg.message,
            "created_at": msg.created_at.isoformat()
        } for msg in messages],
        "unread_count": unread_count
    })



# Mark messages as read
@app.post("/api/homework/submission/<int:sh_id>/messages/mark-read")
def api_homework_mark_messages_read(sh_id: int):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    u = current_user()
    s = current_student()
    
    if not (u or s):
        abort(401)
    
    sh = StudentHomework.query.get_or_404(sh_id)
    
    # Students can only mark their own homework
    if s and sh.student_id != s.id:
        abort(403)
    
    # Mentors can only mark messages for homework assigned to them
    if u and u.role == "mentor":
        mentor = current_mentor()
        if not mentor or sh.assigned_mentor_id != mentor.id:
            abort(403, description="You can only access homework assigned to you")
    
    # Admins and instructors cannot access chat
    if u and u.role in ["admin", "instructor"]:
        abort(403, description="Chat is private between student and assigned mentor")
    
    now = datetime.now()
    
    # Update all messages for this homework
    messages = HomeworkMessage.query.filter_by(student_homework_id=sh_id).all()
    
    for msg in messages:
        if s:
            # Student marking as read
            msg.student_read_at = now
        elif u and u.role == "mentor":
            # Mentor marking as read
            msg.instructor_read_at = now
    
    db.session.commit()
    
    return jsonify({"ok": True, "marked_at": now.isoformat()})


# Send a message (only student or assigned mentor)
@app.post("/api/homework/submission/<int:sh_id>/messages")
def api_homework_send_message(sh_id: int):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    u = current_user()
    s = current_student()
    
    if not (u or s):
        abort(401)
    
    sh = StudentHomework.query.get_or_404(sh_id)
    
    # Students can only message on their own homework
    if s and sh.student_id != s.id:
        abort(403)
    
    # Mentors can only message for homework assigned to them
    if u and u.role == "mentor":
        mentor = current_mentor()
        if not mentor or sh.assigned_mentor_id != mentor.id:
            abort(403, description="You can only message on homework assigned to you")
    
    # Admins and instructors cannot send messages
    if u and u.role in ["admin", "instructor"]:
        abort(403, description="Only the assigned mentor can message students about their homework")
    
    data = request.get_json(silent=True) or {}
    message_text = (data.get("message") or "").strip()
    
    if not message_text:
        abort(400, description="Message text required")
    
    # Create message
    if u and u.role == "mentor":
        # Mentor sending message
        msg = HomeworkMessage(
            student_homework_id=sh_id,
            sender_type="mentor",
            sender_user_id=u.id,
            sender_name=u.name,
            message=message_text
        )
    else:
        # Student sending message
        msg = HomeworkMessage(
            student_homework_id=sh_id,
            sender_type="student",
            sender_student_id=s.id,
            sender_name=s.name,
            message=message_text
        )
    
    db.session.add(msg)
    db.session.commit()
    
    return jsonify({
        "ok": True,
        "message": {
            "id": msg.id,
            "sender_type": msg.sender_type,
            "sender_name": msg.sender_name,
            "message": msg.message,
            "created_at": msg.created_at.isoformat()
        }
    })


# Admin: open notebook JSON (for JupyterLite import)
@app.get("/api/admin/notebooks/<int:nb_id>")
@require_user()
def api_admin_notebook(nb_id: int):
    nb = Notebook.query.get_or_404(nb_id)
    name = _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb")
    return jsonify({"id": nb.id, "name": name, "content": nb.content_json})

# Admin: download notebook
@app.get("/admin/notebooks/<int:nb_id>/download")
@require_user()
def admin_download_notebook(nb_id: int):
    nb = Notebook.query.get_or_404(nb_id)
    name = _filename_from_nb(nb.content_json, f"Notebook-{nb.id}.ipynb")
    buf = io.BytesIO(json.dumps(nb.content_json, ensure_ascii=False).encode("utf-8"))
    return send_file(buf, mimetype="application/x-ipynb+json", as_attachment=True, download_name=name)

# Admin JupyterLite viewer page
@app.get("/admin/jlite")
@require_user()
def admin_jlite():
    return render_template("admin_jlite.html", user=current_user(), student_name=session.get("student_name"))


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
                now = datetime.now()
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
    cutoff = datetime.now() - timedelta(minutes=5)
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
        LectureQuestion.created_at >= datetime.now() - timedelta(seconds=60)
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

# --------------------------------------------------------------------
# Mentor Management
# --------------------------------------------------------------------
@app.route("/mentors")
@require_user()
def mentors_list():
    u = current_user()
    
    # If user is a mentor, redirect to their profile page
    if u.role == "mentor":
        return redirect(url_for("mentor_profile"))
    
    # Admin can see full details
    if u.role == "admin":
        mentors = Mentor.query.order_by(Mentor.name).all()
        
        # Get stats for each mentor
        mentor_stats = []
        for m in mentors:
            total_assigned = StudentHomework.query.filter_by(assigned_mentor_id=m.id).count()
            submitted = StudentHomework.query.filter(
                StudentHomework.assigned_mentor_id == m.id,
                StudentHomework.submitted_at.isnot(None)
            ).count()
            
            # Count accepted homework
            accepted = StudentHomework.query.filter(
                StudentHomework.assigned_mentor_id == m.id,
                StudentHomework.acceptance_status == 'accepted'
            ).count()
            
            # Count rejected homework
            rejected = StudentHomework.query.filter(
                StudentHomework.assigned_mentor_id == m.id,
                StudentHomework.acceptance_status == 'rejected'
            ).count()
            
            # Count reopened homework (homework that has been reopened at least once)
            reopened = StudentHomework.query.filter(
                StudentHomework.assigned_mentor_id == m.id,
                StudentHomework.reopened_at.isnot(None)
            ).count()
            
            # Check if mentor has user account
            user_account = User.query.filter_by(mentor_id=m.id, role="mentor").first()
            
            mentor_stats.append({
                "mentor": m,
                "total_assigned": total_assigned,
                "submitted": submitted,
                "accepted": accepted,
                "rejected": rejected,
                "reopened": reopened,
                "has_account": bool(user_account),
                "user_email": user_account.email if user_account else None
            })
        
        return render_template("mentors_list.html", 
                             mentor_stats=mentor_stats, 
                             user=u, 
                             student_name=session.get("student_name"))
    
    # Instructors see basic list
    mentors = Mentor.query.order_by(Mentor.name).all()
    return render_template("mentors_list.html", 
                         mentors=mentors, 
                         user=u, 
                         student_name=session.get("student_name"))

@app.route("/mentor/profile")
@require_user(role="mentor")
def mentor_profile():
    u = current_user()
    m = current_mentor()
    
    if not m:
        abort(404, description="Mentor profile not found")
    
    # Get mentor's assignments
    assignments = (db.session.query(StudentHomework, Notebook, Student, Homework)
                   .join(Notebook, Notebook.id == StudentHomework.notebook_id)
                   .join(Student, Student.id == StudentHomework.student_id)
                   .join(Homework, Homework.id == StudentHomework.homework_id)
                   .filter(StudentHomework.assigned_mentor_id == m.id)
                   .order_by(StudentHomework.submitted_at.desc())
                   .all())
    
    items = []
    for sh, nb, st, hw in assignments:
        items.append({
            "student_homework_id": sh.id,
            "student_name": st.name,
            "homework_title": hw.title,
            "homework_code": hw.code,
            "notebook_id": nb.id,
            "submitted_at": sh.submitted_at,
            "feedback": sh.feedback,
            "feedback_at": sh.feedback_at,
            "acceptance_status": sh.acceptance_status,
            "acceptance_comment": sh.acceptance_comment,
            "reviewed_at": sh.reviewed_at,
        })
    
    return render_template("mentor_profile.html", 
                         mentor=m, 
                         assignments=items,
                         user=u, 
                         student_name=session.get("student_name"))

@app.post("/mentor/toggle-active")
@require_user(role="mentor")
def mentor_toggle_active():
    if not verify_csrf():
        abort(400, "bad csrf")
    
    m = current_mentor()
    if not m:
        abort(404)
    
    m.is_active = not m.is_active
    db.session.commit()
    
    return redirect(url_for("mentor_profile"))

@app.post("/api/mentor/homework/<int:sh_id>/review")
@require_user(role="mentor")
def mentor_review_homework(sh_id: int):
    """Mentor accepts or rejects a homework submission"""
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    u = current_user()
    m = current_mentor()
    
    if not m:
        abort(404, description="Mentor profile not found")
    
    sh = StudentHomework.query.get_or_404(sh_id)
    
    # Verify this homework is assigned to this mentor
    if sh.assigned_mentor_id != m.id:
        abort(403, description="You can only review homework assigned to you")
    
    # Verify homework is submitted
    if not sh.submitted_at:
        abort(400, description="Homework must be submitted before review")
    
    data = request.get_json(silent=True) or {}
    status = data.get("status")  # "accepted" or "rejected"
    comment = (data.get("comment") or "").strip()
    
    if status not in ["accepted", "rejected"]:
        abort(400, description="Status must be 'accepted' or 'rejected'")
    
    sh.acceptance_status = status
    sh.acceptance_comment = comment if comment else None
    sh.reviewed_at = datetime.now()
    sh.reviewed_by_user_id = u.id
    db.session.commit()
    
    return jsonify({
        "ok": True,
        "status": status,
        "reviewed_at": sh.reviewed_at.isoformat()
    })

@app.post("/mentors/add")
@require_user(role="admin")
def mentors_add():
    if not verify_csrf():
        abort(400, "bad csrf")
    
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    
    if not name or not email:
        session["error"] = "Name and email required"
        return redirect(url_for("mentors_list"))
    
    # Check if email already exists in mentors or users
    existing_mentor = Mentor.query.filter_by(email=email).first()
    existing_user = User.query.filter_by(email=email).first()
    
    if existing_mentor or existing_user:
        session["error"] = "Email already exists"
        return redirect(url_for("mentors_list"))
    
    # Generate random password
    import secrets, string
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(12))
    
    # Create mentor entry
    mentor = Mentor(name=name, email=email, is_active=True, first_login=True)
    mentor.set_password(password)
    db.session.add(mentor)
    db.session.flush()
    
    # Create user account with mentor role
    user = User(
        name=name,
        email=email,
        role="mentor",
        first_login=True,
        mentor_id=mentor.id
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Store password in session to show once
    session["new_mentor_password"] = {
        "email": email,
        "password": password,
        "name": name
    }
    
    return redirect(url_for("mentors_list"))

@app.post("/mentors/<int:mentor_id>/toggle")
@require_user(role="admin")
def mentors_toggle(mentor_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    
    mentor = Mentor.query.get_or_404(mentor_id)
    mentor.is_active = not mentor.is_active
    db.session.commit()
    
    return redirect(url_for("mentors_list"))

@app.post("/mentors/<int:mentor_id>/delete")
@require_user(role="admin")
def mentors_delete(mentor_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    
    mentor = Mentor.query.get_or_404(mentor_id)
    
    # Check if mentor has assignments
    assignment_count = StudentHomework.query.filter_by(assigned_mentor_id=mentor_id).count()
    if assignment_count > 0:
        session["error"] = f"Cannot delete mentor with {assignment_count} homework assignments. Deactivate instead."
        return redirect(url_for("mentors_list"))
    
    # Delete associated user account if exists
    user_account = User.query.filter_by(mentor_id=mentor_id, role="mentor").first()
    if user_account:
        db.session.delete(user_account)
    
    db.session.delete(mentor)
    db.session.commit()
    
    return redirect(url_for("mentors_list"))

@app.route("/dashboard")
@require_user()
def dashboard_for_role():
    u = current_user()
    if u.role == "mentor":
        return redirect(url_for("mentor_profile"))
    return redirect(url_for("poll_list"))

@app.route("/student")
@require_student()
def student_home():
    return redirect(url_for("index"))

# --------------------------------------------------------------------
# Code Exercises
# --------------------------------------------------------------------

# Admin: List all exercises
@app.route("/exercises/manage")
@require_user()
def exercises_manage():
    exercise_sets = ExerciseSet.query.order_by(ExerciseSet.created_at.desc()).all()
    
    # Get stats for each set
    sets_data = []
    for ex_set in exercise_sets:
        exercise_count = len(ex_set.exercises)
        
        # Count total submissions and unique students across all exercises in the set
        total_submissions = 0
        unique_students_set = set()
        for ex in ex_set.exercises:
            total_submissions += CodeSubmission.query.filter_by(exercise_id=ex.id).count()
            students = db.session.query(CodeSubmission.student_id).filter_by(exercise_id=ex.id).distinct().all()
            unique_students_set.update([s[0] for s in students])
        
        sets_data.append({
            'set': ex_set,
            'exercise_count': exercise_count,
            'total_submissions': total_submissions,
            'unique_students': len(unique_students_set)
        })
    
    return render_template("exercises_manage.html", exercise_sets=sets_data, 
                         user=current_user(), student_name=session.get("student_name"))

# Admin: Create new exercise set
@app.route("/exercises/new", methods=["GET", "POST"])
@require_user()
def exercise_new():
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        # Exercise Set details
        set_code = (request.form.get("set_code") or "").strip()
        set_title = (request.form.get("set_title") or "").strip()
        set_description = (request.form.get("set_description") or "").strip()
        is_published = bool(request.form.get("published"))
        
        # Parse datetime fields
        available_from = parse_dt_local(request.form.get("available_from"))
        available_until = parse_dt_local(request.form.get("available_until"))
        
        if not set_code or not set_title:
            return render_template("exercise_set_new.html", 
                                 error="Set code and title are required",
                                 user=current_user(), 
                                 student_name=session.get("student_name"))
        
        # Check if code already exists
        existing = ExerciseSet.query.filter_by(code=set_code).first()
        if existing:
            return render_template("exercise_set_new.html", 
                                 error=f"A set with code '{set_code}' already exists",
                                 user=current_user(), 
                                 student_name=session.get("student_name"))
        
        # Create the exercise set
        exercise_set = ExerciseSet(
            code=set_code,
            title=set_title,
            description=set_description,
            is_published=is_published,
            available_from=available_from,
            available_until=available_until,
            creator_user_id=current_user().id,
            created_at=datetime.now()
        )
        db.session.add(exercise_set)
        db.session.flush()  # Get the ID
        
        # Parse exercises from form
        exercise_count = int(request.form.get("exercise_count", 0))
        for i in range(exercise_count):
            title = (request.form.get(f"ex_title_{i}") or "").strip()
            description = (request.form.get(f"ex_description_{i}") or "").strip()
            starter_code = request.form.get(f"ex_starter_code_{i}", "")
            default_input = request.form.get(f"ex_default_input_{i}", "")
            points = int(request.form.get(f"ex_points_{i}", 10))
            
            if not title:  # Skip if no title
                continue
            
            # Parse test cases for this exercise
            test_cases = []
            test_count = int(request.form.get(f"ex_test_count_{i}", 0))
            for j in range(test_count):
                input_data = request.form.get(f"ex_{i}_test_input_{j}", "")
                expected = request.form.get(f"ex_{i}_test_expected_{j}", "")
                hidden = bool(request.form.get(f"ex_{i}_test_hidden_{j}"))
                desc = request.form.get(f"ex_{i}_test_desc_{j}", "")
                
                if input_data or expected:  # Only add if has data
                    test_cases.append({
                        "input": input_data,
                        "expected_output": expected,
                        "hidden": hidden,
                        "description": desc
                    })
            
            # Create exercise
            exercise = CodeExercise(
                exercise_set_id=exercise_set.id,
                order=i + 1,
                title=title,
                description=description,
                starter_code=starter_code,
                language="python",
                default_input=default_input,
                test_cases_json=test_cases,
                points=points,
                created_at=datetime.now()
            )
            db.session.add(exercise)
        
        db.session.commit()
        
        return redirect(url_for("exercises_manage"))
    
    return render_template("exercise_set_new.html", user=current_user(), 
                         student_name=session.get("student_name"))

# Admin: Edit exercise SET
@app.route("/exercises/<code>/edit", methods=["GET", "POST"])
@require_user()
def exercise_edit(code):
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        exercise_set.title = (request.form.get("title") or "").strip()
        exercise_set.description = (request.form.get("description") or "").strip()
        exercise_set.is_published = bool(request.form.get("published"))
        
        exercise_set.available_from = parse_dt_local(request.form.get("available_from"))
        exercise_set.available_until = parse_dt_local(request.form.get("available_until"))
        
        db.session.commit()
        
        return redirect(url_for("exercises_manage"))
    
    # Use new exercise set edit template
    return render_template("exercise_set_edit.html", exercise_set=exercise_set, 
                         user=current_user(), student_name=session.get("student_name"))


# Admin: Edit individual exercise
@app.route("/exercises/<code>/<int:exercise_num>/edit-exercise", methods=["GET", "POST"])
@require_user()
def exercise_edit_individual(code, exercise_num):
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    exercise = CodeExercise.query.filter_by(
        exercise_set_id=exercise_set.id, 
        order=exercise_num
    ).first_or_404()
    
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        exercise.title = (request.form.get("title") or "").strip()
        exercise.description = (request.form.get("description") or "").strip()
        exercise.difficulty = request.form.get("difficulty") or "medium"
        exercise.category = (request.form.get("category") or "").strip()
        exercise.points = int(request.form.get("points") or 10)
        exercise.starter_code = request.form.get("starter_code") or ""
        exercise.default_input = request.form.get("default_input") or ""
        
        # Handle test cases
        test_cases = []
        test_inputs = request.form.getlist("test_input[]")
        test_outputs = request.form.getlist("test_output[]")
        test_hidden = request.form.getlist("test_hidden[]")
        test_descriptions = request.form.getlist("test_description[]")
        
        for i in range(len(test_inputs)):
            test_cases.append({
                "input": test_inputs[i],
                "expected_output": test_outputs[i],
                "hidden": str(i) in test_hidden,  # Checkboxes only send checked values
                "description": test_descriptions[i] if i < len(test_descriptions) else ""
            })
        
        exercise.test_cases_json = test_cases  # JSONText handles serialization automatically
        
        db.session.commit()
        
        return redirect(url_for("exercise_edit", code=code))
    
    # Get test cases (already deserialized by JSONText)
    test_cases = exercise.test_cases_json if exercise.test_cases_json else []
    
    return render_template("exercise_edit_clean.html", 
                         exercise=exercise, 
                         exercise_set=exercise_set,
                         test_cases=test_cases,
                         user=current_user(), 
                         student_name=session.get("student_name"))


# Admin: Delete individual exercise
@app.route("/exercises/<code>/<int:exercise_num>/delete-exercise", methods=["POST"])
@require_user()
def exercise_delete_individual(code, exercise_num):
    if not verify_csrf():
        abort(400, "bad csrf")
    
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    exercise = CodeExercise.query.filter_by(
        exercise_set_id=exercise_set.id, 
        order=exercise_num
    ).first_or_404()
    
    db.session.delete(exercise)
    
    # Reorder remaining exercises
    remaining = CodeExercise.query.filter_by(exercise_set_id=exercise_set.id).filter(
        CodeExercise.order > exercise_num
    ).all()
    for ex in remaining:
        ex.order -= 1
    
    db.session.commit()
    
    return redirect(url_for("exercise_edit", code=code))


# Admin: Add new exercise to a set
@app.route("/exercises/<code>/new-exercise", methods=["GET", "POST"])
@require_user()
def exercise_new_individual(code):
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        # Get next order number
        max_order = db.session.query(db.func.max(CodeExercise.order)).filter_by(
            exercise_set_id=exercise_set.id
        ).scalar() or 0
        
        exercise = CodeExercise()
        exercise.exercise_set_id = exercise_set.id
        exercise.order = max_order + 1
        exercise.title = (request.form.get("title") or "").strip()
        exercise.description = (request.form.get("description") or "").strip()
        exercise.difficulty = request.form.get("difficulty") or "medium"
        exercise.category = (request.form.get("category") or "").strip()
        exercise.points = int(request.form.get("points") or 10)
        exercise.starter_code = request.form.get("starter_code") or ""
        exercise.default_input = request.form.get("default_input") or ""
        
        # Handle test cases
        test_cases = []
        test_inputs = request.form.getlist("test_input[]")
        test_outputs = request.form.getlist("test_output[]")
        test_hidden = request.form.getlist("test_hidden[]")
        test_descriptions = request.form.getlist("test_description[]")
        
        for i in range(len(test_inputs)):
            test_cases.append({
                "input": test_inputs[i],
                "expected_output": test_outputs[i],
                "hidden": str(i) in test_hidden,
                "description": test_descriptions[i] if i < len(test_descriptions) else ""
            })
        
        exercise.test_cases_json = test_cases  # JSONText handles serialization automatically
        
        db.session.add(exercise)
        db.session.commit()
        
        return redirect(url_for("exercise_edit", code=code))
    
    # Show empty form for new exercise
    return render_template("exercise_new_individual.html", 
                         exercise_set=exercise_set,
                         user=current_user(), 
                         student_name=session.get("student_name"))


# Admin: Delete exercise SET
@app.route("/exercises/<code>/delete", methods=["POST"])
@require_user()
def exercise_delete(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    db.session.delete(exercise_set)
    db.session.commit()
    
    return redirect(url_for("exercises_manage"))

# Admin: Share exercise SET (QR code)
@app.route("/exercises/<code>/share")
@require_user()
def exercise_share(code):
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    
    scheme = "https" if request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https" else "http"
    host = SHARE_HOST or request.host
    link = f"{scheme}://{host}{url_for('exercise_play', code=exercise_set.code)}"
    
    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    
    # Pass as 'exercise' for template compatibility
    return render_template("exercise_share.html", exercise=exercise_set, link=link, 
                         data_url=data_url, user=current_user(), 
                         student_name=session.get("student_name"))

# Admin: View submissions for an exercise SET
@app.route("/exercises/<code>/submissions")
@require_user()
def exercise_submissions(code):
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    
    # Get all exercises in this set
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    # Get all students who submitted to any exercise in this set
    students_data = []
    student_ids = set()
    
    for exercise in exercises:
        for submission in CodeSubmission.query.filter_by(exercise_id=exercise.id).all():
            student_ids.add(submission.student_id)
    
    for student_id in student_ids:
        student = db.session.get(Student, student_id)
        if not student:
            continue
            
        # Get progress for each exercise
        exercise_progress = []
        total_score = 0
        max_score = 0
        
        for exercise in exercises:
            progress = StudentProgress.query.filter_by(
                student_id=student_id,
                exercise_id=exercise.id
            ).first()
            
            max_score += exercise.points
            
            if progress:
                total_score += progress.best_score
                exercise_progress.append({
                    'exercise': exercise,
                    'completed': progress.completed,
                    'best_score': progress.best_score,
                    'attempts': progress.attempts
                })
            else:
                exercise_progress.append({
                    'exercise': exercise,
                    'completed': False,
                    'best_score': 0,
                    'attempts': 0
                })
        
        students_data.append({
            'student': student,
            'total_score': total_score,
            'max_score': max_score,
            'percentage': round(total_score / max_score * 100) if max_score > 0 else 0,
            'exercise_progress': exercise_progress
        })
    
    # Sort by total score descending
    students_data.sort(key=lambda x: x['total_score'], reverse=True)
    
    return render_template("exercise_submissions.html", 
                         exercise_set=exercise_set,
                         exercises=exercises,
                         students_data=students_data,
                         user=current_user(), 
                         student_name=session.get("student_name"))
    
    items = []
    for sub, student in submissions:
        progress = StudentProgress.query.filter_by(
            student_id=student.id,
            exercise_id=exercise.id
        ).first()
        
        items.append({
            'student': student,
            'submission': sub,
            'progress': progress
        })
    
    return render_template("exercise_submissions.html", exercise=exercise, 
                         items=items, user=current_user(), 
                         student_name=session.get("student_name"))

# Student: Browse exercises
@app.route("/exercises")
@require_student()
def exercises_list():
    student = current_student()
    now = datetime.now()
    
    # Get all available exercise sets
    sets_query = (ExerciseSet.query
                  .filter(ExerciseSet.is_published == True)
                  .filter(or_(
                      ExerciseSet.available_from == None,
                      ExerciseSet.available_from <= now
                  ))
                  .filter(or_(
                      ExerciseSet.available_until == None,
                      ExerciseSet.available_until >= now
                  ))
                  .order_by(ExerciseSet.created_at.desc()))
    
    sets_data = []
    for ex_set in sets_query.all():
        # Count completed exercises in this set
        completed_count = 0
        total_points = 0
        for ex in ex_set.exercises:
            total_points += ex.points
            progress = StudentProgress.query.filter_by(
                student_id=student.id,
                exercise_id=ex.id,
                completed=True
            ).first()
            if progress:
                completed_count += 1
        
        sets_data.append({
            'set': ex_set,
            'exercise_count': len(ex_set.exercises),
            'completed_count': completed_count,
            'total_points': total_points
        })
    
    return render_template("exercises_list.html", exercise_sets=sets_data,
                         user=None, student_name=student.name)

# Student: Work on exercise set
@app.route("/ex/<code>")
@app.route("/ex/<code>/<int:exercise_num>")
@require_student()
def exercise_play(code, exercise_num=1):
    # Find the exercise set
    exercise_set = ExerciseSet.query.filter_by(code=code).first_or_404()
    student = current_student()
    
    # Check if set is available
    now = datetime.now()
    if not exercise_set.is_published:
        abort(403)
    if exercise_set.available_from and exercise_set.available_from > now:
        return render_template("exercise_locked.html", 
                             exercise_set=exercise_set,
                             reason="not_yet_available",
                             available_from=exercise_set.available_from,
                             user=None, student_name=student.name), 403
    if exercise_set.available_until and exercise_set.available_until < now:
        return render_template("exercise_locked.html", 
                             exercise_set=exercise_set,
                             reason="expired",
                             available_until=exercise_set.available_until,
                             user=None, student_name=student.name), 403
    
    # Get exercises in order
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    if not exercises:
        abort(404, "No exercises in this set")
    
    # Validate exercise number
    if exercise_num < 1 or exercise_num > len(exercises):
        exercise_num = 1
    
    current_exercise = exercises[exercise_num - 1]
    
    # Get or create progress for this exercise
    progress = StudentProgress.query.filter_by(
        student_id=student.id,
        exercise_id=current_exercise.id
    ).first()
    
    if not progress:
        progress = StudentProgress(
            student_id=student.id,
            exercise_id=current_exercise.id,
            status='in_progress'
        )
        db.session.add(progress)
        db.session.commit()
    elif progress.status == 'not_started':
        progress.status = 'in_progress'
        db.session.commit()
    
    # Calculate set progress
    completed_exercises = 0
    for ex in exercises:
        prog = StudentProgress.query.filter_by(
            student_id=student.id,
            exercise_id=ex.id,
            completed=True
        ).first()
        if prog:
            completed_exercises += 1
    
    return render_template("exercise_play.html", 
                         exercise_set=exercise_set,
                         exercise=current_exercise, 
                         exercise_num=exercise_num,
                         total_exercises=len(exercises),
                         set_progress=f"{completed_exercises}/{len(exercises)}",
                         progress=progress,
                         user=None, student_name=student.name)

# API: Get exercise data from set
@app.get("/api/ex/<set_code>/<int:exercise_num>/data")
@require_student()
def api_exercise_data(set_code, exercise_num):
    # Get the exercise set
    exercise_set = ExerciseSet.query.filter_by(code=set_code).first_or_404()
    student = current_student()
    
    # Check availability
    now = datetime.now()
    if not exercise_set.is_published:
        abort(403, description="Exercise set not available")
    if exercise_set.available_from and exercise_set.available_from > now:
        abort(403, description="Exercise set not yet available")
    if exercise_set.available_until and exercise_set.available_until < now:
        abort(403, description="Exercise set has expired")
    
    # Get exercises in order
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    if exercise_num < 1 or exercise_num > len(exercises):
        abort(404, description="Exercise not found")
    
    exercise = exercises[exercise_num - 1]
    
    # Get student progress
    progress = StudentProgress.query.filter_by(
        student_id=student.id,
        exercise_id=exercise.id
    ).first()
    
    # Get only visible test cases for initial display
    visible_tests = [t for t in exercise.test_cases_json if not t.get('hidden', False)]
    
    return jsonify({
        'id': exercise.id,
        'title': exercise.title,
        'description': exercise.description,
        'starter_code': exercise.starter_code,
        'default_input': exercise.default_input or '',
        'points': exercise.points,
        'visible_test_cases': visible_tests,
        'progress': {
            'status': progress.status if progress else 'not_started',
            'attempts': progress.attempts if progress else 0,
            'best_score': progress.best_score if progress else 0,
            'completed': progress.completed if progress else False
        } if progress else None
    })

# API: Get all test cases (for submission)
@app.get("/api/ex/<set_code>/<int:exercise_num>/all-tests")
@require_student()
def api_exercise_all_tests(set_code, exercise_num):
    exercise_set = ExerciseSet.query.filter_by(code=set_code).first_or_404()
    
    # Check availability
    now = datetime.now()
    if not exercise_set.is_published:
        abort(403, description="Exercise set not available")
    if exercise_set.available_from and exercise_set.available_from > now:
        abort(403, description="Exercise set not yet available")
    if exercise_set.available_until and exercise_set.available_until < now:
        abort(403, description="Exercise set has expired")
    
    # Get exercises in order
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    if exercise_num < 1 or exercise_num > len(exercises):
        abort(404, description="Exercise not found")
    
    exercise = exercises[exercise_num - 1]
    
    return jsonify({
        'test_cases': exercise.test_cases_json,
        'points': exercise.points
    })

# API: Submit solution
@app.post("/api/ex/<set_code>/<int:exercise_num>/submit")
@require_student()
def api_exercise_submit(set_code, exercise_num):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    
    exercise_set = ExerciseSet.query.filter_by(code=set_code).first_or_404()
    student = current_student()
    
    # Check availability
    now = datetime.now()
    if not exercise_set.is_published:
        abort(403, description="Exercise set not available")
    if exercise_set.available_from and exercise_set.available_from > now:
        abort(403, description="Exercise set not yet available")
    if exercise_set.available_until and exercise_set.available_until < now:
        abort(403, description="Exercise set has expired")
    
    # Get exercises in order
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    if exercise_num < 1 or exercise_num > len(exercises):
        abort(404, description="Exercise not found")
    
    exercise = exercises[exercise_num - 1]
    
    data = request.get_json(silent=True) or {}
    code_text = data.get("code", "").strip()
    test_results = data.get("test_results", [])
    
    if not code_text:
        abort(400, description="Code required")
    
    # Validate test results
    expected_tests = exercise.test_cases_json
    if len(test_results) != len(expected_tests):
        abort(400, description="Invalid test results")
    
    # Verify and categorize results
    visible_passed = 0
    visible_total = 0
    hidden_passed = 0
    hidden_total = 0
    
    validated_results = []
    
    for i, (result, expected) in enumerate(zip(test_results, expected_tests)):
        # Server validates the result using smart comparison
        actual_output = (result.get("actual", "") or "")
        expected_output = expected["expected_output"]
        is_correct = compare_outputs(actual_output, expected_output)
        
        result["passed"] = is_correct
        result["test_num"] = i + 1
        
        if expected.get("hidden"):
            hidden_total += 1
            if is_correct:
                hidden_passed += 1
        else:
            visible_total += 1
            if is_correct:
                visible_passed += 1
        
        validated_results.append(result)
    
    total_passed = visible_passed + hidden_passed
    total_tests = visible_total + hidden_total
    all_passed = (total_passed == total_tests)
    score = (total_passed / total_tests) * exercise.points if total_tests > 0 else 0
    
    # Get or create progress
    progress = StudentProgress.query.filter_by(
        student_id=student.id,
        exercise_id=exercise.id
    ).first()
    
    if not progress:
        progress = StudentProgress(
            student_id=student.id,
            exercise_id=exercise.id,
            status='in_progress'
        )
        db.session.add(progress)
        db.session.flush()
    
    # Update progress
    attempt_number = progress.attempts + 1
    progress.attempts = attempt_number
    progress.last_attempted_at = datetime.now()
    
    if score > progress.best_score:
        progress.best_score = score
    
    if all_passed and not progress.completed:
        progress.completed = True
        progress.completed_at = datetime.now()
        progress.status = 'completed'
    
    # Create submission
    submission = CodeSubmission(
        exercise_id=exercise.id,
        student_id=student.id,
        code=code_text,
        test_results_json=validated_results,
        visible_passed=visible_passed,
        visible_total=visible_total,
        hidden_passed=hidden_passed,
        hidden_total=hidden_total,
        total_passed=total_passed,
        total_tests=total_tests,
        all_passed=all_passed,
        score=score,
        attempt_number=attempt_number
    )
    db.session.add(submission)
    db.session.commit()
    
    # Prepare filtered response
    response_results = []
    for result, expected in zip(validated_results, expected_tests):
        if expected.get("hidden"):
            # Hide details for hidden tests
            response_results.append({
                "test_num": result["test_num"],
                "hidden": True,
                "passed": result["passed"],
                "time_ms": result.get("time_ms", 0)
            })
        else:
            # Show full details for visible tests
            response_results.append({
                "test_num": result["test_num"],
                "hidden": False,
                "passed": result["passed"],
                "input": result.get("input", ""),
                "expected": expected["expected_output"],
                "actual": result.get("actual", ""),
                "time_ms": result.get("time_ms", 0),
                "description": expected.get("description", "")
            })
    
    return jsonify({
        "ok": True,
        "submission_id": submission.id,
        "attempt_number": attempt_number,
        "score": round(score, 1),
        "max_score": exercise.points,
        "all_passed": all_passed,
        "visible": {
            "passed": visible_passed,
            "total": visible_total,
            "percentage": round((visible_passed / visible_total * 100) if visible_total > 0 else 0, 1)
        },
        "hidden": {
            "passed": hidden_passed,
            "total": hidden_total,
            "percentage": round((hidden_passed / hidden_total * 100) if hidden_total > 0 else 0, 1)
        },
        "test_results": response_results,
        "is_best_score": (score == progress.best_score),
        "completed": all_passed
    })

# API: Get student's submission history for a specific exercise
@app.get("/api/ex/<set_code>/<int:exercise_num>/my-submissions")
@require_student()
def api_exercise_my_submissions(set_code, exercise_num):
    exercise_set = ExerciseSet.query.filter_by(code=set_code).first_or_404()
    student = current_student()
    
    # Get exercises in order
    exercises = sorted(exercise_set.exercises, key=lambda e: e.order)
    
    if exercise_num < 1 or exercise_num > len(exercises):
        abort(404, description="Exercise not found")
    
    exercise = exercises[exercise_num - 1]
    
    submissions = (CodeSubmission.query
                   .filter_by(exercise_id=exercise.id, student_id=student.id)
                   .order_by(CodeSubmission.submitted_at.desc())
                   .all())
    
    progress = StudentProgress.query.filter_by(
        student_id=student.id,
        exercise_id=exercise.id
    ).first()
    
    best_score = progress.best_score if progress else 0
    
    return jsonify({
        "submissions": [{
            "id": sub.id,
            "attempt_number": sub.attempt_number,
            "score": sub.score,
            "max_score": exercise.points,
            "all_passed": sub.all_passed,
            "visible_passed": sub.visible_passed,
            "visible_total": sub.visible_total,
            "hidden_passed": sub.hidden_passed,
            "hidden_total": sub.hidden_total,
            "submitted_at": sub.submitted_at.isoformat(),
            "is_best": (sub.score == best_score)
        } for sub in submissions]
    })

# API: View specific submission
@app.get("/api/submissions/<int:submission_id>")
@require_student()
def api_submission_detail(submission_id):
    submission = CodeSubmission.query.get_or_404(submission_id)
    student = current_student()
    
    # Students can only view their own submissions
    if submission.student_id != student.id:
        abort(403)
    
    exercise = submission.exercise
    expected_tests = exercise.test_cases_json
    
    # Filter hidden test details
    filtered_results = []
    for result, expected in zip(submission.test_results_json, expected_tests):
        if expected.get("hidden"):
            filtered_results.append({
                "test_num": result.get("test_num"),
                "hidden": True,
                "passed": result.get("passed"),
                "time_ms": result.get("time_ms", 0)
            })
        else:
            filtered_results.append({
                "test_num": result.get("test_num"),
                "hidden": False,
                "passed": result.get("passed"),
                "input": result.get("input", ""),
                "expected": expected["expected_output"],
                "actual": result.get("actual", ""),
                "time_ms": result.get("time_ms", 0),
                "description": expected.get("description", "")
            })
    
    return jsonify({
        "id": submission.id,
        "code": submission.code,
        "attempt_number": submission.attempt_number,
        "score": submission.score,
        "max_score": exercise.points,
        "all_passed": submission.all_passed,
        "submitted_at": submission.submitted_at.isoformat(),
        "test_results": filtered_results
    })

# --------------------------------------------------------------------
# Mentor Slot Management
# --------------------------------------------------------------------

# Admin: View all mentor slots and bookings
@app.route("/admin/mentor-slots")
@require_user(role=['admin', 'instructor'])
def admin_mentor_slots():
    user = current_user()
    
    # Get all mentors
    mentors = Mentor.query.filter_by(is_active=True).order_by(Mentor.name).all()
    
    mentor_data = []
    for mentor in mentors:
        # Get all slots for this mentor
        slots = MentorSlot.query.filter_by(mentor_id=mentor.id).order_by(MentorSlot.start_time).all()
        
        # Get stats
        total_slots = len(slots)
        active_slots = len([s for s in slots if s.is_active])
        upcoming_slots = len([s for s in slots if s.start_time > datetime.now()])
        
        # Get all bookings
        all_bookings = []
        for slot in slots:
            bookings = SlotBooking.query.filter_by(
                slot_id=slot.id,
                status='confirmed'
            ).all()
            for booking in bookings:
                all_bookings.append({
                    'slot': slot,
                    'booking': booking,
                    'student': booking.student
                })
        
        mentor_data.append({
            'mentor': mentor,
            'total_slots': total_slots,
            'active_slots': active_slots,
            'upcoming_slots': upcoming_slots,
            'total_bookings': len(all_bookings),
            'bookings': sorted(all_bookings, key=lambda x: x['slot'].start_time)
        })
    
    return render_template("admin_mentor_slots.html", 
                         user=user,
                         mentor_data=mentor_data,
                         now=datetime.now())

# Mentor: View/manage their slots
@app.route("/mentor/slots")
@require_user(role='mentor')
def mentor_slots():
    mentor = current_mentor()
    if not mentor:
        abort(403, description="Not linked to a mentor profile")
    
    # Get all slots for this mentor, ordered by start time
    slots = MentorSlot.query.filter_by(mentor_id=mentor.id).order_by(MentorSlot.start_time).all()
    
    # Get booking info for each slot
    slots_with_bookings = []
    for slot in slots:
        bookings = SlotBooking.query.filter_by(slot_id=slot.id, status='confirmed').all()
        slots_with_bookings.append({
            'slot': slot,
            'bookings': bookings,
            'bookings_count': len(bookings)
        })
    
    user = current_user()
    return render_template("mentor_slots.html", 
                         user=user, 
                         mentor=mentor,
                         slots=slots_with_bookings)

# Mentor: Create new slot
@app.route("/mentor/slots/new", methods=["GET", "POST"])
@require_user(role='mentor')
def mentor_slot_new():
    mentor = current_mentor()
    if not mentor:
        abort(403, description="Not linked to a mentor profile")
    
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        start_time_str = request.form.get("start_time", "").strip()
        end_time_str = request.form.get("end_time", "").strip()
        max_bookings = request.form.get("max_bookings", "1").strip()
        
        # Validate
        if not start_time_str or not end_time_str:
            return render_template("mentor_slot_new.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 error="Start time and end time are required"), 400
        
        start_time = parse_dt_local(start_time_str)
        end_time = parse_dt_local(end_time_str)
        
        if not start_time or not end_time:
            return render_template("mentor_slot_new.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 error="Invalid date/time format"), 400
        
        if end_time <= start_time:
            return render_template("mentor_slot_new.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 error="End time must be after start time"), 400
        
        if start_time < datetime.now():
            return render_template("mentor_slot_new.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 error="Cannot create slots in the past"), 400
        
        try:
            max_bookings_int = int(max_bookings)
            if max_bookings_int < 1:
                raise ValueError()
        except ValueError:
            return render_template("mentor_slot_new.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 error="Max bookings must be a positive number"), 400
        
        # Create slot
        slot = MentorSlot(
            mentor_id=mentor.id,
            title=title or None,
            description=description or None,
            location=location or None,
            start_time=start_time,
            end_time=end_time,
            max_bookings=max_bookings_int
        )
        db.session.add(slot)
        db.session.commit()
        
        return redirect(url_for("mentor_slots"))
    
    user = current_user()
    return render_template("mentor_slot_new.html", user=user, mentor=mentor)

# Mentor: Edit slot
@app.route("/mentor/slots/<int:slot_id>/edit", methods=["GET", "POST"])
@require_user(role='mentor')
def mentor_slot_edit(slot_id):
    mentor = current_mentor()
    if not mentor:
        abort(403, description="Not linked to a mentor profile")
    
    slot = MentorSlot.query.get_or_404(slot_id)
    
    # Verify ownership
    if slot.mentor_id != mentor.id:
        abort(403)
    
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        start_time_str = request.form.get("start_time", "").strip()
        end_time_str = request.form.get("end_time", "").strip()
        max_bookings = request.form.get("max_bookings", "1").strip()
        is_active = request.form.get("is_active") == "on"
        
        # Validate
        if not start_time_str or not end_time_str:
            return render_template("mentor_slot_edit.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 slot=slot,
                                 error="Start time and end time are required"), 400
        
        start_time = parse_dt_local(start_time_str)
        end_time = parse_dt_local(end_time_str)
        
        if not start_time or not end_time:
            return render_template("mentor_slot_edit.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 slot=slot,
                                 error="Invalid date/time format"), 400
        
        if end_time <= start_time:
            return render_template("mentor_slot_edit.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 slot=slot,
                                 error="End time must be after start time"), 400
        
        try:
            max_bookings_int = int(max_bookings)
            if max_bookings_int < 1:
                raise ValueError()
        except ValueError:
            return render_template("mentor_slot_edit.html", 
                                 user=current_user(), 
                                 mentor=mentor,
                                 slot=slot,
                                 error="Max bookings must be a positive number"), 400
        
        # Update slot
        slot.title = title or None
        slot.description = description or None
        slot.location = location or None
        slot.start_time = start_time
        slot.end_time = end_time
        slot.max_bookings = max_bookings_int
        slot.is_active = is_active
        db.session.commit()
        
        return redirect(url_for("mentor_slots"))
    
    user = current_user()
    return render_template("mentor_slot_edit.html", user=user, mentor=mentor, slot=slot)

# Mentor: Delete slot
@app.route("/mentor/slots/<int:slot_id>/delete", methods=["POST"])
@require_user(role='mentor')
def mentor_slot_delete(slot_id):
    mentor = current_mentor()
    if not mentor:
        abort(403, description="Not linked to a mentor profile")
    
    slot = MentorSlot.query.get_or_404(slot_id)
    
    # Verify ownership
    if slot.mentor_id != mentor.id:
        abort(403)
    
    db.session.delete(slot)
    db.session.commit()
    
    return redirect(url_for("mentor_slots"))

# Student: Browse available slots
@app.route("/slots")
@require_student()
def student_slots():
    student = current_student()
    
    # Get all active slots that haven't started yet
    now = datetime.now()
    available_slots = MentorSlot.query.filter(
        MentorSlot.is_active == True,
        MentorSlot.start_time > now
    ).order_by(MentorSlot.start_time).all()
    
    # Group by mentor and filter by availability
    slots_by_mentor = {}
    for slot in available_slots:
        if slot.is_available:
            mentor_name = slot.mentor.name
            if mentor_name not in slots_by_mentor:
                slots_by_mentor[mentor_name] = []
            slots_by_mentor[mentor_name].append(slot)
    
    # Get student's bookings
    my_bookings = SlotBooking.query.filter_by(
        student_id=student.id,
        status='confirmed'
    ).order_by(SlotBooking.booked_at.desc()).all()
    
    return render_template("student_slots.html", 
                         student_name=student.name,
                         slots_by_mentor=slots_by_mentor,
                         my_bookings=my_bookings,
                         now=now)

# Student: Book a slot
@app.route("/slots/<int:slot_id>/book", methods=["POST"])
@require_student()
def student_slot_book(slot_id):
    student = current_student()
    slot = MentorSlot.query.get_or_404(slot_id)
    
    # Verify slot is available
    if not slot.is_available:
        return jsonify({"error": "Slot is no longer available"}), 400
    
    # Check if student already booked this slot
    existing = SlotBooking.query.filter_by(
        slot_id=slot_id,
        student_id=student.id,
        status='confirmed'
    ).first()
    
    if existing:
        return jsonify({"error": "You have already booked this slot"}), 400
    
    # Get notes from request
    data = request.get_json(silent=True) or {}
    notes = data.get("notes", "").strip()
    
    # Create booking
    booking = SlotBooking(
        slot_id=slot_id,
        student_id=student.id,
        notes=notes or None
    )
    db.session.add(booking)
    db.session.commit()
    
    return jsonify({"success": True, "booking_id": booking.id})

# Student: Cancel booking
@app.route("/slots/bookings/<int:booking_id>/cancel", methods=["POST"])
@require_student()
def student_booking_cancel(booking_id):
    student = current_student()
    booking = SlotBooking.query.get_or_404(booking_id)
    
    # Verify ownership
    if booking.student_id != student.id:
        abort(403)
    
    # Only allow canceling confirmed bookings
    if booking.status != 'confirmed':
        return jsonify({"error": "Cannot cancel this booking"}), 400
    
    # Update status
    booking.status = 'cancelled_by_student'
    booking.cancelled_at = datetime.now()
    db.session.commit()
    
    return jsonify({"success": True})

# Mentor: Cancel a booking
@app.route("/mentor/bookings/<int:booking_id>/cancel", methods=["POST"])
@require_user(role='mentor')
def mentor_booking_cancel(booking_id):
    mentor = current_mentor()
    if not mentor:
        abort(403, description="Not linked to a mentor profile")
    
    booking = SlotBooking.query.get_or_404(booking_id)
    
    # Verify the booking is for this mentor's slot
    if booking.slot.mentor_id != mentor.id:
        abort(403)
    
    # Only allow canceling confirmed bookings
    if booking.status != 'confirmed':
        return jsonify({"error": "Cannot cancel this booking"}), 400
    
    # Update status
    booking.status = 'cancelled_by_mentor'
    booking.cancelled_at = datetime.now()
    db.session.commit()
    
    return jsonify({"success": True})

@app.route("/exams")
@require_user(role=["admin", "instructor"])
def exams_list():
    exams = Exam.query.order_by(Exam.start_at.desc()).all()
    return render_template("exams_list.html", exams=exams, user=current_user(), student_name=session.get("student_name"))

@app.route("/exams/new", methods=["GET","POST"])
@require_user(role=["admin", "instructor"])
def exams_new():
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        start_at = parse_dt_local(request.form.get("start_at"))
        end_at = parse_dt_local(request.form.get("end_at"))
        is_published = bool(request.form.get("published"))
        if not title or not start_at:
            sets = ExerciseSet.query.order_by(ExerciseSet.created_at.desc()).all()
            sets_payload = []
            for st in sets:
                exs = CodeExercise.query.filter_by(exercise_set_id=st.id).order_by(CodeExercise.order.asc()).all()
                sets_payload.append({
                    "set": {"id": st.id, "code": st.code, "title": st.title},
                    "exercises": [{"id": e.id, "order": e.order, "title": e.title} for e in exs]
                })
            return render_template("exam_new.html", error="Title and start time required", user=current_user(), sets_data=sets_payload, student_name=session.get("student_name"))
        code = gen_code()
        while Exam.query.filter_by(code=code).first() is not None:
            code = gen_code()
        exm = Exam(code=code, title=title, description=description, start_at=start_at, end_at=end_at, is_published=is_published, creator_user_id=current_user().id)
        db.session.add(exm)
        db.session.flush()
        spec_raw = request.form.get("spec_json") or "{}"
        try:
            spec = json.loads(spec_raw)
        except Exception:
            spec = {}
        qlist = spec.get("questions") or []
        order = 1
        for q in qlist:
            qtype = (q.get("type") or "").lower()
            qtitle = (q.get("title") or "").strip()
            qprompt = q.get("prompt")
            qpoints = int(q.get("points") or (10 if qtype == "code" else 1))
            if qtype == "mcq":
                # Simplified MCQ: question text in 'question'
                prompt_text = (q.get("question") or qprompt or "").strip()
                options = q.get("options") or []
                correct = q.get("correct") or []
                multiple = bool(q.get("multiple"))
                eq = ExamQuestion(exam_id=exm.id, order=order, q_type="mcq", title=None, prompt=prompt_text, points=qpoints, options_json=options, correct_indices_json=correct, multiple_select=multiple)
                db.session.add(eq)
                order += 1
            elif qtype == "code":
                # Accept either legacy linking to an exercise or inline fields
                cxid = q.get("code_exercise_id")
                if cxid:
                    eq = ExamQuestion(exam_id=exm.id, order=order, q_type="code", title=qtitle or None, prompt=qprompt, points=qpoints, code_exercise_id=int(cxid))
                else:
                    title = (q.get("title") or "").strip() or None
                    desc = (q.get("description") or qprompt or "").strip() or None
                    starter = q.get("starter_code") or None
                    tests = q.get("test_cases") or []
                    eq = ExamQuestion(exam_id=exm.id, order=order, q_type="code", title=title, prompt=desc, points=qpoints, code_exercise_id=None, code_starter_code=starter, code_test_cases_json=tests)
                db.session.add(eq)
                order += 1
        db.session.commit()
        return redirect(url_for("exams_list"))
    sets = ExerciseSet.query.order_by(ExerciseSet.created_at.desc()).all()
    sets_payload = []
    for st in sets:
        exs = CodeExercise.query.filter_by(exercise_set_id=st.id).order_by(CodeExercise.order.asc()).all()
        sets_payload.append({
            "set": {"id": st.id, "code": st.code, "title": st.title},
            "exercises": [{"id": e.id, "order": e.order, "title": e.title} for e in exs]
        })
    return render_template("exam_new.html", user=current_user(), sets_data=sets_payload, student_name=session.get("student_name"))

@app.route("/exams/<code>/edit", methods=["GET","POST"])
@require_user(role=["admin", "instructor"])
def exams_edit(code):
    exm = Exam.query.filter_by(code=code).first_or_404()
    if request.method == "POST":
        if not verify_csrf(): abort(400, "bad csrf")
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        start_at = parse_dt_local(request.form.get("start_at"))
        end_at = parse_dt_local(request.form.get("end_at"))
        is_published = bool(request.form.get("published"))
        if not title or not start_at:
            # Re-render with error and existing spec
            spec = {"questions": []}
            for q in exm.questions:
                if q.q_type == "mcq":
                    spec["questions"].append({
                        "type": "mcq",
                        "question": q.prompt or "",
                        "options": q.options_json or [],
                        "correct": q.correct_indices_json or [],
                        "multiple": bool(q.multiple_select),
                        "points": q.points,
                    })
                elif q.q_type == "code":
                    if q.code_exercise_id:
                        spec["questions"].append({
                            "type": "code",
                            "title": q.title or "",
                            "prompt": q.prompt or "",
                            "points": q.points,
                            "code_exercise_id": q.code_exercise_id,
                        })
                    else:
                        spec["questions"].append({
                            "type": "code",
                            "title": q.title or "",
                            "description": q.prompt or "",
                            "starter_code": q.code_starter_code or "",
                            "points": q.points,
                        })
            return render_template("exam_new.html", error="Title and start time required", exam=exm, spec=spec, user=current_user(), student_name=session.get("student_name"))
        # Update exam meta
        exm.title = title
        exm.description = description
        exm.start_at = start_at
        exm.end_at = end_at
        exm.is_published = is_published
        # Replace questions
        spec_raw = request.form.get("spec_json") or "{}"
        try:
            spec = json.loads(spec_raw)
        except Exception:
            spec = {}
        # delete existing questions
        ExamQuestion.query.filter_by(exam_id=exm.id).delete()
        db.session.flush()
        order = 1
        for q in (spec.get("questions") or []):
            qtype = (q.get("type") or "").lower()
            qtitle = (q.get("title") or "").strip()
            qprompt = q.get("prompt")
            qpoints = int(q.get("points") or (10 if qtype == "code" else 1))
            if qtype == "mcq":
                prompt_text = (q.get("question") or qprompt or "").strip()
                options = q.get("options") or []
                correct = q.get("correct") or []
                multiple = bool(q.get("multiple"))
                eq = ExamQuestion(exam_id=exm.id, order=order, q_type="mcq", title=None, prompt=prompt_text, points=qpoints, options_json=options, correct_indices_json=correct, multiple_select=multiple)
                db.session.add(eq)
                order += 1
            elif qtype == "code":
                cxid = q.get("code_exercise_id")
                if cxid:
                    eq = ExamQuestion(exam_id=exm.id, order=order, q_type="code", title=qtitle or None, prompt=qprompt, points=qpoints, code_exercise_id=int(cxid))
                else:
                    title2 = (q.get("title") or "").strip() or None
                    desc = (q.get("description") or qprompt or "").strip() or None
                    starter = q.get("starter_code") or None
                    tests = q.get("test_cases") or []
                    eq = ExamQuestion(exam_id=exm.id, order=order, q_type="code", title=title2, prompt=desc, points=qpoints, code_exercise_id=None, code_starter_code=starter, code_test_cases_json=tests)
                db.session.add(eq)
                order += 1
        db.session.commit()
        return redirect(url_for("exams_list"))
    # GET: render edit form with existing spec prefilled
    spec = {"questions": []}
    for q in exm.questions:
        if q.q_type == "mcq":
            spec["questions"].append({
                "type": "mcq",
                "question": q.prompt or "",
                "options": q.options_json or [],
                "correct": q.correct_indices_json or [],
                "multiple": bool(q.multiple_select),
                "points": q.points,
            })
        elif q.q_type == "code":
            if q.code_exercise_id:
                spec["questions"].append({
                    "type": "code",
                    "title": q.title or "",
                    "prompt": q.prompt or "",
                    "points": q.points,
                    "code_exercise_id": q.code_exercise_id,
                })
            else:
                spec["questions"].append({
                    "type": "code",
                    "title": q.title or "",
                    "description": q.prompt or "",
                    "starter_code": q.code_starter_code or "",
                    "test_cases": q.code_test_cases_json or [],
                    "points": q.points,
                })
    return render_template("exam_new.html", exam=exm, spec=spec, user=current_user(), student_name=session.get("student_name"))

@app.route("/exams/<code>/submissions")
@require_user(role=["admin", "instructor"])
def exams_submissions(code):
    exm = Exam.query.filter_by(code=code).first_or_404()
    subs = ExamSubmission.query.filter_by(exam_id=exm.id).order_by(ExamSubmission.started_at.desc()).all()
    return render_template("exam_submissions.html", exam=exm, subs=subs, user=current_user(), student_name=session.get("student_name"))

@app.route("/exams/<code>/submission/<int:sub_id>")
@require_user(role=["admin", "instructor"])
def exams_submission_detail(code, sub_id):
    exm = Exam.query.filter_by(code=code).first_or_404()
    sub = ExamSubmission.query.filter_by(id=sub_id, exam_id=exm.id).first_or_404()
    # Build mapping from question id to answer for convenience
    ans_by_qid = {a.question_id: a for a in sub.answers}
    # Keep questions ordered
    qitems = []
    for q in exm.questions:
        a = ans_by_qid.get(q.id)
        # Extract shallow fields for template convenience
        meta = {"type": q.q_type, "points": q.points}
        if q.q_type == "mcq":
            meta.update({
                "prompt": q.prompt or "",
                "options": q.options_json or [],
                "correct": q.correct_indices_json or [],
                "multiple": bool(q.multiple_select),
            })
        else:
            meta.update({
                "title": q.title or "",
                "prompt": q.prompt or "",
            })
        qitems.append({"q": q, "a": a, "meta": meta})
    return render_template("exam_submission_detail.html", exam=exm, sub=sub, qitems=qitems, user=current_user(), student_name=session.get("student_name"))

def _exam_accessible(exm):
    now = datetime.now()
    if not exm.is_published:
        return False
    if not exm.start_at or now < exm.start_at:
        return False
    if exm.end_at and now > exm.end_at:
        return False
    return True

def _find_exam_submission(exm, stu):
    return ExamSubmission.query.filter_by(exam_id=exm.id, student_id=stu.id).first()

def _exam_submission(exm, stu):
    sub = ExamSubmission.query.filter_by(exam_id=exm.id, student_id=stu.id).first()
    if not sub:
        sub = ExamSubmission(exam_id=exm.id, student_id=stu.id)
        db.session.add(sub)
        db.session.commit()
    return sub

@app.route("/exam/<code>")
@require_student()
def exam_play(code):
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        return render_template("exam_locked.html", exam=exm, user=None, student_name=s.name if s else session.get("student_name")), 403
    # Block reopened exams after submission
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        return render_template("exam_locked.html", exam=exm, user=None, already_submitted=True, student_name=s.name if s else session.get("student_name")), 403
    _exam_submission(exm, s)
    return render_template("exam_play.html", exam=exm, user=None, student_name=s.name if s else session.get("student_name"))

@app.get("/api/exam/<code>/meta")
@require_student()
def api_exam_meta(code):
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        abort(403)
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        abort(403)
    _exam_submission(exm, s)
    return jsonify({
        "code": exm.code,
        "title": exm.title,
        "description": exm.description,
        "start_at": exm.start_at.isoformat() if exm.start_at else None,
        "end_at": exm.end_at.isoformat() if exm.end_at else None,
        "questions": [{"order": q.order, "type": q.q_type, "title": q.title or f"Question {q.order}", "points": q.points} for q in exm.questions]
    })

@app.get("/api/exam/<code>/question/<int:order>")
@require_student()
def api_exam_question(code, order):
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        abort(403)
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        abort(403)
    sub = sub or _exam_submission(exm, s)
    q = ExamQuestion.query.filter_by(exam_id=exm.id, order=order).first_or_404()
    ans = ExamAnswer.query.filter_by(submission_id=sub.id, question_id=q.id).first()
    if q.q_type == "mcq":
        return jsonify({
            "type": "mcq",
            "order": q.order,
            "title": q.title,
            "prompt": q.prompt,
            "options": q.options_json or [],
            "multiple": bool(q.multiple_select),
            "points": q.points,
            "answer": (ans.answer_json if ans else None)
        })
    exo = q.code_exercise
    # remove test_results from answer_json
    saved = (dict(ans.answer_json) if ans and ans.answer_json else None)
    if saved:
        saved.pop("test_results", None)
    if exo:
        visible_tests = [t for t in (exo.test_cases_json or []) if not t.get("hidden")]
        starter = q.code_starter_code or exo.starter_code
        return jsonify({
            "type": "code",
            "order": q.order,
            "title": q.title or exo.title,
            "prompt": q.prompt or exo.description,
            "points": q.points,
            "starter_code": starter,
            "default_input": exo.default_input or "",
            "visible_test_cases": visible_tests,
            "answer": saved
        })
    # Inline code (no linked exercise/tests)
    vis = [t for t in (q.code_test_cases_json or []) if not t.get("hidden")]
    return jsonify({
        "type": "code",
        "order": q.order,
        "title": q.title,
        "prompt": q.prompt,
        "starter_code": q.code_starter_code or "# Write your code here\n",
        "default_input": "",
        "visible_test_cases": vis,
        "points": q.points,
        "answer": saved
    })

@app.get("/api/exam/<code>/question/<int:order>/all-tests")
@require_student()
def api_exam_question_all_tests(code, order):
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        abort(403)
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        abort(403)
    _exam_submission(exm, s)
    q = ExamQuestion.query.filter_by(exam_id=exm.id, order=order).first_or_404()
    if q.q_type != "code":
        abort(400)
    # Return ONLY visible (non-hidden) tests to the client
    if not q.code_exercise:
        visible = [t for t in (q.code_test_cases_json or []) if not t.get("hidden")]
        return jsonify({"test_cases": visible})
    exo = q.code_exercise
    visible = [t for t in (exo.test_cases_json or []) if not t.get("hidden")]
    return jsonify({"test_cases": visible})

@app.post("/api/exam/<code>/answer/<int:order>")
@require_student()
def api_exam_answer(code, order):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        abort(403)
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        abort(403)
    sub = sub or _exam_submission(exm, s)
    q = ExamQuestion.query.filter_by(exam_id=exm.id, order=order).first_or_404()
    data = request.get_json(silent=True) or {}
    if q.q_type == "mcq":
        selected = data.get("selected") or []
        try:
            selected_set = sorted(set(int(i) for i in selected))
        except Exception:
            selected_set = []
        correct = sorted((q.correct_indices_json or []))
        ok = (selected_set == correct)
        award = float(q.points if ok else 0)
        ans = ExamAnswer.query.filter_by(submission_id=sub.id, question_id=q.id).first()
        if not ans:
            ans = ExamAnswer(submission_id=sub.id, question_id=q.id)
            db.session.add(ans)
        ans.answer_json = {"selected": selected_set}
        ans.score_awarded = award
        db.session.commit()
        return jsonify({"ok": True})
    exo = q.code_exercise
    # Grade against ALL tests (visible + hidden) on the server
    expected_tests_all = (exo.test_cases_json if exo else (q.code_test_cases_json or [])) or []
    validated_results = []
    for i, exp in enumerate(expected_tests_all):
        run_res = _run_python_code_isolated(data.get("code", ""), exp.get("input") or "", timeout_sec=3.0)
        actual_output = run_res.get("output") or ""
        expected_output = exp.get("expected_output")
        is_correct = compare_outputs(str(actual_output), str(expected_output))
        item = {
            "test_num": i + 1,
            "hidden": bool(exp.get("hidden", False)),
            "passed": bool(is_correct),
            "input": exp.get("input", ""),
            "expected": expected_output,
            "actual": actual_output,
            "time_ms": int(run_res.get("time_ms") or 0),
        }
        validated_results.append(item)
    ok_all = all(t.get("passed") for t in validated_results) if validated_results else False
    award = float(q.points if ok_all else 0)
    ans = ExamAnswer.query.filter_by(submission_id=sub.id, question_id=q.id).first()
    if not ans:
        ans = ExamAnswer(submission_id=sub.id, question_id=q.id)
        db.session.add(ans)
    ans.answer_json = {"code": data.get("code", ""), "test_results": validated_results}
    ans.score_awarded = award
    db.session.commit()
    return jsonify({"ok": True})

@app.post("/api/exam/<code>/submit")
@require_student()
def api_exam_submit(code):
    hdr = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(hdr, csrf_token()):
        abort(400, description="Bad CSRF")
    exm = Exam.query.filter_by(code=code).first_or_404()
    s = current_student()
    if not _exam_accessible(exm):
        abort(403)
    sub = _find_exam_submission(exm, s)
    if sub and sub.submitted_at:
        abort(400, description="Already submitted")
    sub = sub or _exam_submission(exm, s)
    sub.submitted_at = datetime.now()
    total = db.session.query(db.func.coalesce(db.func.sum(ExamAnswer.score_awarded), 0)).filter_by(submission_id=sub.id).scalar() or 0
    sub.score = float(total)
    db.session.commit()
    return jsonify({"ok": True})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
