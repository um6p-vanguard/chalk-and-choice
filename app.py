
import os, io, base64, hashlib, secrets, argparse, csv, functools
from datetime import timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, make_response, jsonify, abort, Response,
                   send_file)
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Poll, Vote, Student, User, Form, FormResponse
import qrcode
from itsdangerous import URLSafeSerializer
import time
import json
import hmac, hashlib  # add

APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(32)
DB_PATH = os.path.abspath(os.environ.get("CLASSVOTE_DB", "classvote.db"))
DB_URI  = os.environ.get("DATABASE_URL") or f"sqlite:///{DB_PATH}"
SHARE_HOST = os.environ.get("CLASSVOTE_SHARE_HOST")



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

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

def current_user():
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None

def require_user(role=None):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("user_login", next=request.path))
            if role == "admin" and u.role != "admin":
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

signer = URLSafeSerializer(APP_SECRET, salt="student-cookie")
STUDENT_COOKIE = "cv_student"

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
    sid = data.get("id"); name = data.get("name")
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

@app.route("/user/login", methods=["GET","POST"])
def user_login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        u = User.query.filter_by(email=email).first()
        if not u or not check_password_hash(u.password_hash, password):
            return render_template("user_login.html", error="Invalid email or password", user=current_user(), student_name=session.get("student_name"))
        session["user_id"] = u.id
        session.permanent = True
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("user_login.html", user=current_user(), student_name=session.get("student_name"))

@app.route("/user/logout")
def user_logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))

@app.route("/")
def index():
    u = current_user()
    polls = Poll.query.order_by(Poll.created_at.desc()).all() if u else []
    return render_template("index.html", user=u, polls=polls, student_name=session.get("student_name"))

@app.route("/student/login", methods=["GET","POST"])
def student_login():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            return render_template("student_login.html", error="Enter your name", user=current_user(), student_name=session.get("student_name"))
        stu = Student.query.filter_by(name=name).first()
        if not stu:
            stu = Student(name=name)
            db.session.add(stu); db.session.commit()
        session["student_id"] = stu.id
        session["student_name"] = stu.name
        session.permanent = True
        resp = make_response(redirect(request.args.get("next") or url_for("index")))
        resp = set_student_cookie(resp, stu)
        return resp
    return render_template("student_login.html", user=current_user(), student_name=session.get("student_name"))

@app.route("/student/logout")
def student_logout():
    session.pop("student_id", None)
    session.pop("student_name", None)
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie(STUDENT_COOKIE)
    return resp

@app.route("/poll/new", methods=["GET","POST"])
@require_user()
def poll_new():
    if request.method == "POST":
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
        question = (request.form.get("question") or "").strip()
        options = [((request.form.get(f"opt{i}") or "").strip()) for i in range(1,9)]
        options = [o for o in options if o]
        correct_raw = request.form.get("correct")
        correct_index = int(correct_raw) if (correct_raw not in (None,"") and correct_raw.isdigit()) else None
        if not question or len(options) < 2:
            return render_template("poll_edit.html", poll=p, error="Enter a question and at least 2 options.", user=current_user())
        if correct_index is not None and (correct_index < 0 or correct_index >= len(options)):
            return render_template("poll_edit.html", poll=p, error="Correct answer index out of range.", user=current_user())
        p.question = question
        p.options = options
        p.correct_index = correct_index
        db.session.commit()
        return redirect(url_for("poll_results", code=p.code))
    return render_template("poll_edit.html", poll=p, user=current_user())

@app.route("/poll/<code>/delete", methods=["POST"])
@require_user()
def poll_delete(code):
    p = Poll.query.filter_by(code=code).first_or_404()
    db.session.delete(p); db.session.commit()
    return redirect(url_for("poll_list"))

@app.route("/share/<code>")
@require_user()
def share(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    host = SHARE_HOST or request.host
    link = f"http://{host}{url_for('poll_view', code=poll.code)}"
    img = qrcode.make(link)
    buf = io.BytesIO(); img.save(buf, format="PNG")
    data_url = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    return render_template("share.html", poll=poll, link=link, data_url=data_url, user=current_user(), student_name=session.get("student_name"))

def current_student():
    sid = session.get("student_id")
    if not sid: return None
    return Student.query.get(sid)

@app.route("/poll/<code>", methods=["GET", "POST"])
def poll_view(code):
    poll = Poll.query.filter_by(code=code).first_or_404()

    # If voting is closed, block POSTs immediately
    if request.method == "POST" and not poll.is_open:
        return render_template(
            "poll_view.html",
            poll=poll,
            error="Voting is closed.",
            already=False,
            user=current_user(),
            student_name=session.get("student_name"),
        )

    # Require a logged-in student (by name)
    if not session.get("student_id"):
        nxt = url_for("poll_view", code=code)
        return redirect(url_for("student_login", next=nxt))

    # Optional CSRF check (only if verify_csrf helper is present)
    if request.method == "POST":
        try:
            if not verify_csrf():
                abort(400, "bad csrf")
        except NameError:
            # verify_csrf not defined; skip (you can remove this block once you add CSRF helpers)
            pass

    # Ensure the device/browser has a stable voter cookie
    token, _ = ensure_voter_cookie(None)

    if request.method == "POST":
        # 1) Block repeat votes by device/browser cookie
        existing_cookie = Vote.query.filter_by(
            poll_id=poll.id, voter_token_hash=token_hash(token)
        ).first()

        # 2) Block repeat votes by student account (even if cookie changes)
        stu = current_student()
        existing_student = (
            Vote.query.filter_by(poll_id=poll.id, student_id=stu.id).first()
            if stu
            else None
        )

        if existing_cookie or existing_student:
            return render_template(
                "poll_view.html",
                poll=poll,
                already=True,
                user=current_user(),
                student_name=session.get("student_name"),
            )

        # Validate choice
        try:
            choice = int(request.form.get("choice", "-1"))
        except Exception:
            choice = -1

        if choice < 0 or choice >= len(poll.options):
            return render_template(
                "poll_view.html",
                poll=poll,
                error="Pick an option",
                user=current_user(),
                student_name=session.get("student_name"),
            )

        # Record the vote
        v = Vote(
            poll_id=poll.id,
            choice=choice,
            voter_token_hash=token_hash(token),
            student_id=stu.id if stu else None,
            student_name=stu.name if stu else None,
        )
        db.session.add(v)
        db.session.commit()

        # Persist the voter cookie and redirect to thanks
        r = make_response(redirect(url_for("thanks", code=code)))
        _, r = ensure_voter_cookie(r)
        return r

    # GET: render the voting form (and set voter cookie if missing)
    r = make_response(
        render_template(
            "poll_view.html",
            poll=poll,
            already=False,
            user=current_user(),
            student_name=session.get("student_name"),
        )
    )
    _, r = ensure_voter_cookie(r)
    return r

@app.route("/thanks")
def thanks():
    return render_template("thanks.html", user=current_user(), student_name=session.get("student_name"))

@app.route("/poll/<code>/thanks")
def poll_thanks(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    return render_template("thanks.html", poll=poll, user=current_user(), student_name=session.get("student_name"))

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

@app.route("/poll/<code>/stream")
@require_user()  # instructor-only stream
def poll_stream(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    def event_stream():
        last = None
        while True:
            counts = [0]*len(poll.options)
            for v in poll.votes:
                counts[v.choice] += 1
            payload = dict(
                counts=counts,
                total=sum(counts),
                correct_index=poll.correct_index,
                options=poll.options
            )
            blob = json.dumps(payload, separators=(",", ":"))
            if blob != last:
                yield f"data: {blob}\n\n"
                last = blob
            time.sleep(1.5)
    return Response(event_stream(), mimetype="text/event-stream")


# --------- FORMS: create, render, submit, results, list ----------

@app.route("/forms")
@require_user()
def forms_list():
    forms = Form.query.order_by(Form.created_at.desc()).all()
    return render_template("forms_list.html", forms=forms, user=current_user(), student_name=session.get("student_name"))

@app.route("/forms/new", methods=["GET", "POST"])
@require_user()
def forms_new():
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = (request.form.get("title") or "").strip()
        schema_text = request.form.get("schema_json") or ""
        if not title or not schema_text:
            return render_template("forms_new.html", error="Title and JSON are required.", schema_json=schema_text, user=current_user(), student_name=session.get("student_name"))
        import json
        try:
            schema = json.loads(schema_text)
        except Exception as e:
            return render_template("forms_new.html", error=f"Invalid JSON: {e}", schema_json=schema_text, user=current_user(), student_name=session.get("student_name"))

        code = gen_code()
        while Form.query.filter_by(code=code).first() is not None:
            code = gen_code()
        schema_text = request.form.get("schema_json") or ""
        try:
            schema = json.loads(schema_text)
        except Exception as e:
            return render_template("forms_new.html", error=f"Invalid JSON: {e}",
                                   schema_json=schema_text, user=current_user(),
                                   student_name=session.get("student_name"))
        f = Form(code=code, title=title, schema_json=schema, creator_user_id=current_user().id)
        db.session.add(f); db.session.commit()
        return redirect(url_for("forms_results", code=f.code))
    return render_template("forms_new.html", schema_json="", user=current_user(), student_name=session.get("student_name"))

@app.route("/f/<code>")
def form_render(code):
    # student-facing form renderer
    form = Form.query.filter_by(code=code).first_or_404()
    if not session.get("student_id"):
        return redirect(url_for("student_login", next=url_for("form_render", code=code)))
    # Pass form schema to template; it will load SurveyJS from CDN and POST results
    return render_template("form_render.html", form=form, user=current_user(), student_name=session.get("student_name"))

@app.route("/api/forms/<code>/responses", methods=["POST"])
def form_submit(code):
    form = Form.query.filter_by(code=code).first_or_404()
    if not session.get("student_id"):
        abort(401)
    # Optional but recommended CSRF for JSON POST: expect header X-CSRF
    token = request.headers.get("X-CSRF", "")
    try:
        if not hmac.compare_digest(token, csrf_token()):
            abort(400, "bad csrf")
    except Exception:
        abort(400, "bad csrf")

    data = request.get_json(silent=True) or {}
    stu = current_student()
    resp = FormResponse(
        form_id=form.id,
        student_id=stu.id if stu else None,
        student_name=stu.name if stu else None,
        payload_json=data
    )
    db.session.add(resp); db.session.commit()
    return jsonify({"ok": True})

@app.route("/forms/<code>/results")
@require_user()
def forms_results(code):
    form = Form.query.filter_by(code=code).first_or_404()
    rows = []
    for r in form.responses:
        rows.append({
            "name": r.student_name or "(anonymous)",
            "when": r.created_at,
            "payload": r.payload_json
        })
    return render_template("forms_results.html", form=form, rows=rows, user=current_user(), student_name=session.get("student_name"))



@app.route("/export/<code>.csv")
@require_user()
def export_csv(code):
    poll = Poll.query.filter_by(code=code).first_or_404()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["poll_code","question","student_name","choice_index","choice_text","correct","timestamp"])
    for v in poll.votes:
        choice_text = poll.options[v.choice] if 0 <= v.choice < len(poll.options) else ""
        correct = (poll.correct_index is not None and v.choice == poll.correct_index)
        w.writerow([poll.code, poll.question, v.student_name or "", v.choice, choice_text, int(correct), v.created_at.isoformat()])
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=f"{poll.code}.csv")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
