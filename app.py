import os, io, base64, secrets, argparse, csv, random, functools, time, json, hmac, hashlib, traceback, builtins, sys, multiprocessing, re, ast, uuid
from datetime import datetime, timedelta, timezone
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound
from itsdangerous import URLSafeSerializer
from markupsafe import Markup, escape

from models import (db, Student, User, Form,
                    FormResponse,
                    StudentStats, Intervention, Exam, ExamSubmission, Grade,
                    Project, ProjectTask, ProjectTaskSubmission, ProjectTaskAttempt, ProjectDependency,
                    StudentGroup, StudentGroupMembership, StudentGroupReviewer, ProjectGroupAssignment,
                    AttendanceSheet, AttendanceEntry, StudentLogSession,
                    BlogPost, BlogComment, Leaderboard,
                    ProficiencyExercise, ProficiencyTestConfig, ProficiencyTestAttempt,
                    ProficiencyExerciseSubmission, StudentProficiencyTag)
import qrcode
from sqlalchemy import func
from sqlalchemy.orm import subqueryload
from sqlalchemy.orm.attributes import flag_modified

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

def _parse_date_only(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
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
UPLOAD_ROOT = os.path.join(os.path.dirname(__file__), "uploads")
UPLOAD_MAX_MB = 5
UPLOAD_MAX_BYTES = UPLOAD_MAX_MB * 1024 * 1024
UPLOAD_DEFAULT_ACCEPT = ".zip"
TASK_RESOURCE_MAX_MB = 10
TASK_RESOURCE_MAX_BYTES = TASK_RESOURCE_MAX_MB * 1024 * 1024
LOG_SESSION_GAP_SEC = 10 * 60
LOG_ACTIVITY_UPDATE_SEC = 60

# Warning system configuration
WARNING_SPEED_THRESHOLD_SEC = 60  # Completing task in less than this triggers warning
WARNING_IP_CHANGE_ENABLED = True  # Detect IP changes during exam/project
WARNING_SIMILARITY_THRESHOLD = 0.90  # Code similarity threshold (0-1)
WARNING_AUTO_FLAG_COUNT = 3  # Auto-flag student after this many warnings

ATTENDANCE_STATUS_OPTIONS = [
    ("present", "Present"),
    ("late", "Late"),
    ("absent", "Absent"),
]
ATTENDANCE_STATUS_VALUES = {value for value, _ in ATTENDANCE_STATUS_OPTIONS}

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

LEADERBOARD_METRICS = {
    "total_points": {"label": "Total points", "description": "Sum of all recorded grade scores."},
    "projects_done": {"label": "Projects done", "description": "Count of projects with required tasks accepted."},
    "logtime": {"label": "Log time", "description": "Student activity time based on online sessions."},
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
# Upload helpers
# --------------------------------------------------------------------
def _parse_accept_extensions(accept_value):
    tokens = []
    for raw in (accept_value or "").split(","):
        token = raw.strip().lower()
        if token.startswith("."):
            tokens.append(token)
    return tokens or [UPLOAD_DEFAULT_ACCEPT]

def _question_upload_limits(question):
    accept_value = (question.get("accept") or UPLOAD_DEFAULT_ACCEPT) if isinstance(question, dict) else UPLOAD_DEFAULT_ACCEPT
    extensions = set(_parse_accept_extensions(accept_value))
    try:
        max_mb = int(question.get("max_mb") or UPLOAD_MAX_MB) if isinstance(question, dict) else UPLOAD_MAX_MB
    except Exception:
        max_mb = UPLOAD_MAX_MB
    max_mb = max(1, min(max_mb, UPLOAD_MAX_MB))
    return extensions, max_mb * 1024 * 1024, max_mb

def _safe_upload_path(rel_path):
    if not rel_path:
        return None
    base = os.path.abspath(UPLOAD_ROOT)
    target = os.path.abspath(os.path.join(base, rel_path))
    if not target.startswith(base + os.sep):
        return None
    return target

def _extract_file_info(answer):
    if isinstance(answer, dict) and answer.get("path"):
        return answer
    return None

def _remove_uploaded_file(file_info):
    info = _extract_file_info(file_info)
    if not info:
        return
    full_path = _safe_upload_path(info.get("path"))
    if full_path and os.path.isfile(full_path):
        try:
            os.remove(full_path)
        except Exception:
            pass

def _save_task_upload(submission, question, qid, file_storage, existing_info=None):
    if not submission or not file_storage:
        return None, "Missing submission or file."
    filename = file_storage.filename or ""
    if not filename:
        return None, "No file selected."
    original_name = os.path.basename(filename)
    extension = os.path.splitext(original_name)[1].lower()
    allowed_exts, max_bytes, max_mb = _question_upload_limits(question)
    if extension not in allowed_exts:
        allowed_str = ", ".join(sorted(allowed_exts))
        return None, f"Only {allowed_str} files are allowed."
    try:
        file_storage.stream.seek(0, os.SEEK_END)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
    except Exception:
        size = None
    if size is not None and size > max_bytes:
        return None, f"File must be {max_mb} MB or smaller."
    safe_name = secure_filename(original_name) or "submission.zip"
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    upload_dir = os.path.join(
        UPLOAD_ROOT,
        "project_tasks",
        str(submission.project_id),
        str(submission.task_id),
        str(submission.id),
        str(qid),
    )
    os.makedirs(upload_dir, exist_ok=True)
    full_path = os.path.join(upload_dir, stored_name)
    try:
        file_storage.save(full_path)
    except Exception:
        return None, "Unable to save file."
    rel_path = os.path.relpath(full_path, UPLOAD_ROOT)
    file_info = {
        "original_name": original_name or safe_name,
        "stored_name": stored_name,
        "path": rel_path,
        "size": size or os.path.getsize(full_path),
        "uploaded_at": datetime.now(timezone.utc).isoformat() + "Z",
    }
    if existing_info:
        _remove_uploaded_file(existing_info)
    return file_info, None

def _save_task_resource(task, file_storage, existing_info=None):
    if not task or not file_storage:
        return None, "Missing task or file."
    filename = file_storage.filename or ""
    if not filename:
        return None, "No file selected."
    original_name = os.path.basename(filename)
    
    # Log file details for debugging
    print(f"DEBUG: Uploading task resource - Task ID: {task.id}, File: {original_name}")
    
    try:
        file_storage.stream.seek(0, os.SEEK_END)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
        print(f"DEBUG: File size: {size} bytes")
    except Exception as e:
        print(f"DEBUG: Error reading file size: {e}")
        size = None
    if size is not None and size > TASK_RESOURCE_MAX_BYTES:
        return None, f"File must be {TASK_RESOURCE_MAX_MB} MB or smaller."
    safe_name = secure_filename(original_name) or "task_resource"
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    upload_dir = os.path.join(
        UPLOAD_ROOT,
        "task_resources",
        str(task.project_id),
        str(task.id),
    )
    os.makedirs(upload_dir, exist_ok=True)
    full_path = os.path.join(upload_dir, stored_name)
    try:
        file_storage.save(full_path)
    except PermissionError:
        return None, "Unable to save file: Permission denied. Check server permissions."
    except OSError as e:
        return None, f"Unable to save file: {str(e)}"
    except Exception as e:
        return None, f"Unable to save file: {str(e)}"
    rel_path = os.path.relpath(full_path, UPLOAD_ROOT)
    file_info = {
        "original_name": original_name or safe_name,
        "stored_name": stored_name,
        "path": rel_path,
        "size": size or os.path.getsize(full_path),
        "uploaded_at": datetime.now(timezone.utc).isoformat() + "Z",
        "content_type": file_storage.mimetype or "",
    }
    if existing_info:
        _remove_uploaded_file(existing_info)
    return file_info, None

def _touch_student_log_session(student, now):
    if not student:
        return
    session_row = StudentLogSession.query.filter_by(student_id=student.id).order_by(
        StudentLogSession.last_activity_at.desc()
    ).first()
    if session_row and session_row.last_activity_at:
        delta = (now - session_row.last_activity_at).total_seconds()
        if delta <= LOG_SESSION_GAP_SEC:
            session_row.last_activity_at = now
            session_row.ended_at = now
            return
    new_session = StudentLogSession(
        student_id=student.id,
        started_at=now,
        last_activity_at=now,
        ended_at=now,
    )
    db.session.add(new_session)

# --------------------------------------------------------------------
# Warning System Helpers
# --------------------------------------------------------------------

def _add_warning(student, warning_type, description, severity="medium", auto_detected=True, 
                 exam_id=None, exam_code=None, project_id=None, project_code=None, 
                 task_id=None, task_title=None, submission_id=None):
    """Add a warning to a student's record with context about the exam/project."""
    if not student:
        return
    warnings = student.warnings_json if isinstance(student.warnings_json, list) else []
    warning = {
        "type": warning_type,
        "description": description,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "auto_detected": auto_detected,
    }
    
    # Add context fields if provided
    if exam_id:
        warning["exam_id"] = exam_id
    if exam_code:
        warning["exam_code"] = exam_code
    if project_id:
        warning["project_id"] = project_id
    if project_code:
        warning["project_code"] = project_code
    if task_id:
        warning["task_id"] = task_id
    if task_title:
        warning["task_title"] = task_title
    if submission_id:
        warning["submission_id"] = submission_id
    
    warnings.append(warning)
    student.warnings_json = warnings
    flag_modified(student, 'warnings_json')
    
    # Mark the field as modified so SQLAlchemy knows to commit it
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(student, "warnings_json")
    
    # Auto-flag if threshold reached
    if len(warnings) >= WARNING_AUTO_FLAG_COUNT and not student.is_flagged:
        student.is_flagged = True
        student.flag_notes = f"Auto-flagged after {len(warnings)} warnings"

def _clear_submission_warnings(student, submission):
    """Clear warnings related to a specific submission when it receives a review."""
    if not student or not submission:
        return
    
    warnings = student.warnings_json if isinstance(student.warnings_json, list) else []
    if not warnings:
        return
    
    # Determine which warnings to remove based on submission type
    filtered_warnings = []
    submission_id = submission.id
    
    # Check if it's an exam submission or project task submission
    if hasattr(submission, 'exam_id'):
        # Remove warnings for this exam
        exam_id = submission.exam_id
        filtered_warnings = [w for w in warnings if w.get('exam_id') != exam_id]
    elif hasattr(submission, 'task_id'):
        # Remove warnings for this specific submission or task
        task_id = submission.task_id
        filtered_warnings = [w for w in warnings 
                           if not (w.get('task_id') == task_id or w.get('submission_id') == submission_id)]
    else:
        # Unknown submission type, keep all warnings
        return
    
    # Update warnings and mark as modified
    student.warnings_json = filtered_warnings
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(student, "warnings_json")
    
    # Re-evaluate flag status based on remaining warnings
    if student.is_flagged and len(filtered_warnings) < WARNING_AUTO_FLAG_COUNT:
        # Check if all remaining warnings are low severity
        high_warnings = [w for w in filtered_warnings if w.get('severity') == 'high']
        if not high_warnings:
            student.is_flagged = False
            student.flag_notes = None

def _submission_has_warnings(student, submission):
    """Check if a specific submission has associated warnings."""
    if not student or not submission:
        return False
    
    warnings = student.warnings_json if isinstance(student.warnings_json, list) else []
    if not warnings:
        return False
    
    # Check based on submission type
    if hasattr(submission, 'exam_id'):
        # Check for exam-specific warnings
        exam_id = submission.exam_id
        return any(w.get('exam_id') == exam_id for w in warnings)
    elif hasattr(submission, 'task_id'):
        # Check for task-specific warnings
        task_id = submission.task_id
        submission_id = submission.id
        return any(w.get('task_id') == task_id or w.get('submission_id') == submission_id 
                  for w in warnings)
    
    return False

def _detect_speed_anomaly(student, submission, task_duration_sec):
    """Detect if submission was completed suspiciously fast."""
    if task_duration_sec < WARNING_SPEED_THRESHOLD_SEC:
        # Extract context
        context = {}
        if hasattr(submission, 'exam_id'):
            context['exam_id'] = submission.exam_id
            if hasattr(submission, 'exam'):
                context['exam_code'] = submission.exam.code
        elif hasattr(submission, 'task_id'):
            context['task_id'] = submission.task_id
            context['submission_id'] = submission.id
            if hasattr(submission, 'project_id'):
                context['project_id'] = submission.project_id
            if hasattr(submission, 'task') and submission.task:
                context['task_title'] = submission.task.title
                if hasattr(submission.task, 'project') and submission.task.project:
                    context['project_code'] = submission.task.project.code
        
        _add_warning(
            student,
            "speed_anomaly",
            f"Completed in {task_duration_sec:.1f} seconds (threshold: {WARNING_SPEED_THRESHOLD_SEC}s)",
            severity="high",
            **context
        )
        return True
    return False

def _detect_ip_change(student, submission, current_ip):
    """Detect IP address changes during exam/project."""
    if not WARNING_IP_CHANGE_ENABLED or not current_ip:
        return False
    
    if hasattr(submission, 'ip_address') and submission.ip_address:
        if submission.ip_address != current_ip:
            # Extract context
            context = {}
            if hasattr(submission, 'exam_id'):
                context['exam_id'] = submission.exam_id
                if hasattr(submission, 'exam'):
                    context['exam_code'] = submission.exam.code
            elif hasattr(submission, 'task_id'):
                context['task_id'] = submission.task_id
                context['submission_id'] = submission.id
                if hasattr(submission, 'project_id'):
                    context['project_id'] = submission.project_id
                if hasattr(submission, 'task') and submission.task:
                    context['task_title'] = submission.task.title
                    if hasattr(submission.task, 'project') and submission.task.project:
                        context['project_code'] = submission.task.project.code
            
            _add_warning(
                student,
                "ip_change",
                f"IP changed from {submission.ip_address} to {current_ip}",
                severity="medium",
                **context
            )
            return True
    return False

def _calculate_code_similarity(code1, code2):
    """Simple token-based code similarity (Jaccard similarity)."""
    if not code1 or not code2:
        return 0.0
    
    # Normalize whitespace and tokenize
    tokens1 = set(re.findall(r'\w+', str(code1).lower()))
    tokens2 = set(re.findall(r'\w+', str(code2).lower()))
    
    if not tokens1 or not tokens2:
        return 0.0
    
    intersection = len(tokens1.intersection(tokens2))
    union = len(tokens1.union(tokens2))
    
    return intersection / union if union > 0 else 0.0

def _detect_code_similarity(student, submission, question_id, submitted_code):
    """Detect similar code submissions from other students."""
    if not submitted_code or len(str(submitted_code).strip()) < 20:
        return False
    
    # Get other students' submissions for same task/exam
    similar_found = False
    
    # Extract context
    context = {}
    
    if hasattr(submission, 'exam_id'):  # Exam submission
        context['exam_id'] = submission.exam_id
        if hasattr(submission, 'exam'):
            context['exam_code'] = submission.exam.code
        
        other_submissions = ExamSubmission.query.filter(
            ExamSubmission.exam_id == submission.exam_id,
            ExamSubmission.student_id != student.id,
            ExamSubmission.status == "submitted"
        ).all()
        
        for other_sub in other_submissions:
            if not isinstance(other_sub.answers_json, dict):
                continue
            other_code = other_sub.answers_json.get(question_id)
            if not other_code:
                continue
            
            similarity = _calculate_code_similarity(submitted_code, other_code)
            if similarity >= WARNING_SIMILARITY_THRESHOLD:
                other_student = db.session.get(Student, other_sub.student_id)
                other_name = other_student.name if other_student else "Unknown"
                _add_warning(
                    student,
                    "code_similarity",
                    f"Code {similarity*100:.0f}% similar to {other_name} (Question: {question_id})",
                    severity="high",
                    **context
                )
                similar_found = True
                break
    
    elif hasattr(submission, 'task_id'):  # Project task submission
        context['task_id'] = submission.task_id
        context['submission_id'] = submission.id
        if hasattr(submission, 'project_id'):
            context['project_id'] = submission.project_id
        if hasattr(submission, 'task') and submission.task:
            context['task_title'] = submission.task.title
            if hasattr(submission.task, 'project') and submission.task.project:
                context['project_code'] = submission.task.project.code
        
        other_submissions = ProjectTaskSubmission.query.filter(
            ProjectTaskSubmission.task_id == submission.task_id,
            ProjectTaskSubmission.student_id != student.id,
            ProjectTaskSubmission.status.in_(["submitted", "accepted", "pending_review"])
        ).all()
        
        for other_sub in other_submissions:
            if not isinstance(other_sub.answers_json, dict):
                continue
            other_code = other_sub.answers_json.get(question_id)
            if not other_code:
                continue
            
            similarity = _calculate_code_similarity(submitted_code, other_code)
            if similarity >= WARNING_SIMILARITY_THRESHOLD:
                other_student = db.session.get(Student, other_sub.student_id)
                other_name = other_student.name if other_student else "Unknown"
                _add_warning(
                    student,
                    "code_similarity",
                    f"Code {similarity*100:.0f}% similar to {other_name} (Question: {question_id})",
                    severity="high",
                    **context
                )
                similar_found = True
                break
    
    return similar_found

def _detect_paste_pattern(student, submission, answers_data):
    """Detect if large amounts of code were likely pasted (heuristic: very long answers)."""
    if not isinstance(answers_data, dict):
        return False
    
    # Extract context
    context = {}
    if hasattr(submission, 'exam_id'):
        context['exam_id'] = submission.exam_id
        if hasattr(submission, 'exam'):
            context['exam_code'] = submission.exam.code
    elif hasattr(submission, 'task_id'):
        context['task_id'] = submission.task_id
        context['submission_id'] = submission.id
        if hasattr(submission, 'project_id'):
            context['project_id'] = submission.project_id
        if hasattr(submission, 'task') and submission.task:
            context['task_title'] = submission.task.title
            if hasattr(submission.task, 'project') and submission.task.project:
                context['project_code'] = submission.task.project.code
    
    for qid, answer in answers_data.items():
        if isinstance(answer, str) and len(answer) > 500:
            # Very long answer - possible paste
            lines = answer.count('\n')
            if lines > 20:  # More than 20 lines
                _add_warning(
                    student,
                    "paste_pattern",
                    f"Large code block detected ({lines} lines, {len(answer)} chars) in question {qid}",
                    severity="low",
                    **context
                )
                return True
    return False

def _run_cheating_detection(student, submission, current_ip=None):
    """Run all cheating detection algorithms on a submission."""
    if not student or not submission:
        return
    
    # Speed detection
    if hasattr(submission, 'started_at') and hasattr(submission, 'submitted_at'):
        if submission.started_at and submission.submitted_at:
            duration = (submission.submitted_at - submission.started_at).total_seconds()
            _detect_speed_anomaly(student, submission, duration)
    
    # IP change detection
    if current_ip:
        _detect_ip_change(student, submission, current_ip)
    
    # Paste pattern detection
    if hasattr(submission, 'answers_json'):
        _detect_paste_pattern(student, submission, submission.answers_json)
    
    # Code similarity detection (for code questions)
    if hasattr(submission, 'answers_json') and isinstance(submission.answers_json, dict):
        for qid, answer in submission.answers_json.items():
            if isinstance(answer, str) and len(answer) > 50:
                # Likely code answer
                _detect_code_similarity(student, submission, qid, answer)

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

# Minimal markdown renderer with headings, inline code, fenced code blocks, lists.
def render_md(text):
    if text is None:
        return Markup("")

    raw = str(text).replace("\r\n", "\n")

    def fmt_inline(chunk: str) -> str:
        esc = escape(chunk)
        esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
        esc = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", esc)
        esc = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", esc)
        return esc

    out = []
    in_list = False
    in_code = False
    code_lines = []
    code_lang = ""

    lines = raw.split("\n")
    for line in lines:
        fence = re.match(r"^```(.*)$", line.strip())
        if fence:
            if in_code:
                lang_attr = f' data-lang="{escape(code_lang)}"' if code_lang else ""
                code_html = escape("\n".join(code_lines))
                out.append(f"<pre class=\"md-code\"><code{lang_attr}>{code_html}</code></pre>")
                in_code = False
                code_lines = []
                code_lang = ""
            else:
                in_code = True
                code_lang = fence.group(1).strip()
            continue

        if in_code:
            code_lines.append(line)
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            if in_list:
                out.append("</ul>")
                in_list = False
            level = len(heading.group(1))
            content = fmt_inline(heading.group(2).strip())
            out.append(f"<h{level} class=\"md-heading\">{content}</h{level}>")
            continue

        is_list = line.strip().startswith("- ")
        if is_list:
            if not in_list:
                out.append("<ul class=\"md-list\">")
                in_list = True
            out.append(f"<li>{fmt_inline(line.strip()[2:])}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            if line.strip() == "":
                out.append("<br>")
            else:
                out.append(f"<p class=\"md-p\">{fmt_inline(line)}</p>")

    if in_code:
        lang_attr = f' data-lang="{escape(code_lang)}"' if code_lang else ""
        code_html = escape("\n".join(code_lines))
        out.append(f"<pre class=\"md-code\"><code{lang_attr}>{code_html}</code></pre>")

    if in_list:
        out.append("</ul>")

    return Markup("".join(out))

@app.template_filter("markdown")
def markdown_filter(text):
    return render_md(text)

@app.template_filter("from_json")
def from_json_filter(text):
    """Parse JSON string to Python object for use in templates."""
    try:
        return json.loads(text) if text else {}
    except (json.JSONDecodeError, TypeError):
        return {}

@app.before_request
def update_student_last_seen():
    try:
        s = current_student()
    except Exception:
        s = None
    if not s:
        return
    now = datetime.now(timezone.utc)
    if not s.last_seen_at or (now - s.last_seen_at).total_seconds() >= LOG_ACTIVITY_UPDATE_SEC:
        s.last_seen_at = now
        _touch_student_log_session(s, now)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

# --------------------------------------------------------------------
# Auth/session helpers
# --------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None

def current_student():
    sid = session.get("student_id")
    return db.session.get(Student, sid) if sid else None

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
    stu = db.session.get(Student, sid)
    if not stu or stu.name != name:
        return
    session["student_id"] = stu.id
    session["student_name"] = stu.name
    session.permanent = True

@app.before_request
def _restore_student():
    try_restore_student_from_cookie()

@app.post("/api/student/ping")
def student_ping():
    student = current_student()
    if not student:
        abort(401)
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    now = datetime.now(timezone.utc)
    student.last_seen_at = now
    _touch_student_log_session(student, now)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({"ok": True})

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
                acct_user.last_login = datetime.now(timezone.utc)
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
                acct_student.last_login = datetime.now(timezone.utc)
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
                    u = db.session.get(User, must["id"]);  assert u
                    u.set_password(pw1); u.first_login = False
                    db.session.commit()
                    session.pop("must_change_pw", None)
                    session["user_id"] = u.id; session["user_role"] = u.role
                    return redirect(url_for("dashboard_for_role"))
                else:
                    s = db.session.get(Student, must["id"]);  assert s
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
    if student and not u:
        return blog_index()
    exams = Exam.query.order_by(Exam.created_at.desc()).all() if (u or student) else []
    available_exams = [ex for ex in exams if ex.is_available] if student else []
    return render_template(
        "index.html",
        user=u,
        student_name=session.get("student_name"),
        exams=exams,
        available_exams=available_exams,
        now_utc=datetime.now(timezone.utc),
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

# --------------------------------------------------------------------
# Blog helpers and views
# --------------------------------------------------------------------

PAGE_SIZE = 10

def _is_staff(user):
    if not user:
        return False
    role = getattr(user, "role", "")
    return role in ("instructor", "admin", "mentor", "staff")

def _paginate_posts(query, page, per_page=10):
    total = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    posts = query.order_by(BlogPost.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "posts": posts,
        "page": page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }

def blog_index():
    page = 1
    try:
        page = int(request.args.get("page", "1"))
    except Exception:
        page = 1
    base_query = BlogPost.query.filter_by(is_published=True)
    pagination = _paginate_posts(base_query, page, PAGE_SIZE)
    return render_template(
        "blog_index.html",
        posts=pagination["posts"],
        page=pagination["page"],
        total_pages=pagination["total_pages"],
        has_prev=pagination["has_prev"],
        has_next=pagination["has_next"],
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/blog")
def blog_list():
    return blog_index()

@app.route("/blog/<int:post_id>")
def blog_post_detail(post_id):
    post = BlogPost.query.filter_by(id=post_id, is_published=True).first_or_404()
    comments = BlogComment.query.filter_by(post_id=post.id).order_by(BlogComment.created_at.asc()).all()
    return render_template(
        "blog_post_detail.html",
        post=post,
        comments=comments,
        error=None,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/blog/<int:post_id>/comments")
def blog_add_comment(post_id):
    post = BlogPost.query.filter_by(id=post_id, is_published=True).first_or_404()
    author = current_user() or current_student()
    if not author:
        abort(401)
    if not verify_csrf():
        abort(400, "bad csrf")
    body = (request.form.get("body") or "").strip()
    error = None
    if not body:
        error = "Comment cannot be empty."
    if body and len(body) > 5000:
        error = "Comment is too long (max 5000 characters)."
    if error:
        comments = BlogComment.query.filter_by(post_id=post.id).order_by(BlogComment.created_at.asc()).all()
        return render_template(
            "blog_post_detail.html",
            post=post,
            comments=comments,
            error=error,
            user=current_user(),
            student_name=session.get("student_name"),
        ), 400
    comment = BlogComment(
        post_id=post.id,
        author_id=getattr(author, "id", None) if isinstance(author, User) else None,
        author_name=getattr(author, "name", None),
        body=body,
    )
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for("blog_post_detail", post_id=post.id) + "#comments")

@app.route("/blog/new", methods=["GET", "POST"])
@require_user()
def blog_new():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    form = {
        "title": request.form.get("title") or "",
        "body": request.form.get("body") or "",
        "is_published": request.form.get("is_published") == "1",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        if not form["title"].strip():
            error = "Title is required."
        if not error and not form["body"].strip():
            error = "Body is required."
        if not error:
            post = BlogPost(
                title=form["title"].strip(),
                body=form["body"],
                is_published=form["is_published"],
                author_id=user.id,
            )
            db.session.add(post)
            db.session.commit()
            return redirect(url_for("blog_post_detail", post_id=post.id))
    return render_template(
        "blog_form.html",
        form=form,
        editing=False,
        error=error,
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/blog/<int:post_id>/edit", methods=["GET", "POST"])
@require_user()
def blog_edit(post_id):
    user = current_user()
    post = BlogPost.query.get_or_404(post_id)
    if not (_is_staff(user) or (user and user.id == post.author_id)):
        abort(403)
    if request.method == "POST":
        form = {
            "title": request.form.get("title") or "",
            "body": request.form.get("body") or "",
            "is_published": request.form.get("is_published") == "1",
        }
    else:
        form = {
            "title": post.title,
            "body": post.body,
            "is_published": post.is_published,
        }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        if not form["title"].strip():
            error = "Title is required."
        if not error and not form["body"].strip():
            error = "Body is required."
        if not error:
            post.title = form["title"].strip()
            post.body = form["body"]
            post.is_published = form["is_published"]
            db.session.commit()
            return redirect(url_for("blog_post_detail", post_id=post.id))
    return render_template(
        "blog_form.html",
        form=form,
        editing=True,
        error=error,
        user=user,
        student_name=session.get("student_name"),
    )

@app.post("/blog/<int:post_id>/delete")
@require_user()
def blog_delete(post_id):
    user = current_user()
    post = BlogPost.query.get_or_404(post_id)
    if not (_is_staff(user) or (user and user.id == post.author_id)):
        abort(403)
    if not verify_csrf():
        abort(400, "bad csrf")
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("blog_list"))

@app.route("/students/online")
@require_user()
def students_online():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    try:
        minutes = int(request.args.get("minutes", "10"))
    except Exception:
        minutes = 10
    minutes = max(1, min(minutes, 120))
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    students = Student.query.filter(Student.last_seen_at != None, Student.last_seen_at >= cutoff).order_by(Student.last_seen_at.desc()).all()
    return render_template(
        "students_online.html",
        students=students,
        minutes=minutes,
        user=user,
        student_name=session.get("student_name"),
    )

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
        iv.started_at = datetime.now(timezone.utc)
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

    iv.ended_at = datetime.now(timezone.utc)
    iv.status = "completed"

    # Update StudentStats
    ss = StudentStats.query.filter_by(student_id=iv.student_id).first()
    if not ss:
        ss = StudentStats(student_id=iv.student_id, times_spoken=0, current_round_done=False)
        db.session.add(ss)
    ss.times_spoken += 1
    ss.last_spoken_at = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
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
        if q_type not in ("mcq", "multi", "text", "code", "tokens", "fill", "file"):
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
        elif q_type == "file":
            accept = (raw.get("accept") or ".zip").strip() or ".zip"
            try:
                max_mb = int(raw.get("max_mb") or 5)
            except Exception:
                max_mb = 5
            normalized["accept"] = accept
            normalized["max_mb"] = max(1, min(max_mb, UPLOAD_MAX_MB))
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

def _latest_task_attempt(submission):
    if not submission:
        return None
    return ProjectTaskAttempt.query.filter_by(submission_id=submission.id).order_by(ProjectTaskAttempt.attempt_number.desc()).first()

def _next_task_attempt_number(submission_id):
    if not submission_id:
        return 1
    last_number = db.session.query(func.max(ProjectTaskAttempt.attempt_number)).filter(
        ProjectTaskAttempt.submission_id == submission_id,
    ).scalar()
    return int(last_number or 0) + 1

def _grading_by_question(details):
    if not isinstance(details, list):
        return {}
    return {
        str(item.get("question_id")): item
        for item in details
        if item.get("question_id") is not None
    }

def _record_task_attempt_review(submission, status=None, notes=None, reviewer=None):
    if not submission:
        return
    attempt = _latest_task_attempt(submission)
    if not attempt:
        return
    if status:
        attempt.status = status
    if notes:
        attempt.review_notes = notes
    if reviewer:
        attempt.reviewed_by_user_id = reviewer.id
    attempt.reviewed_at = datetime.now(timezone.utc)

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
    # Check proficiency requirement first
    if project.required_proficiency_tag:
        has_tag = StudentProficiencyTag.query.filter_by(
            student_id=student.id, 
            tag_name=project.required_proficiency_tag
        ).first()
        if not has_tag:
            return False
    
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

def _student_has_proficiency_tag(student, tag_name):
    """Check if student has a specific proficiency tag."""
    return StudentProficiencyTag.query.filter_by(
        student_id=student.id, 
        tag_name=tag_name
    ).first() is not None

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

def _leaderboard_students(group_id=None):
    q = Student.query
    if group_id:
        q = q.join(StudentGroupMembership).filter(StudentGroupMembership.group_id == group_id)
    return q.distinct().order_by(Student.name.asc()).all()

def _project_completion_counts(student_ids):
    if not student_ids:
        return {}
    projects = Project.query.options(subqueryload(Project.tasks)).all()
    accepted = ProjectTaskSubmission.query.filter(
        ProjectTaskSubmission.student_id.in_(student_ids),
        ProjectTaskSubmission.status == "accepted",
    ).all()
    accepted_map = {}
    for sub in accepted:
        key = (sub.student_id, sub.project_id)
        accepted_map.setdefault(key, set()).add(sub.task_id)
    counts = {sid: 0 for sid in student_ids}
    for project in projects:
        required_count = _project_required_count(project)
        tasks_to_check = [t for t in project.tasks if t.required] or list(project.tasks)
        task_ids = [t.id for t in tasks_to_check]
        for sid in student_ids:
            if required_count <= 0:
                counts[sid] = counts.get(sid, 0) + 1
                continue
            accepted_tasks = accepted_map.get((sid, project.id), set())
            completed = sum(1 for tid in task_ids if tid in accepted_tasks)
            if completed >= required_count:
                counts[sid] = counts.get(sid, 0) + 1
    return counts

def _format_duration(seconds):
    try:
        total = float(seconds or 0)
    except Exception:
        total = 0.0
    if total >= 3600:
        return f"{total / 3600:.2f} hr"
    return f"{total / 60:.1f} min"

def _parse_iso_datetime(val):
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(str(val))
    except Exception:
        return None

def _logtime_range_from_params(params):
    now = datetime.now(timezone.utc)
    params = params if isinstance(params, dict) else {}
    range_type = params.get("range") or "all_time"
    start = None
    end = None
    if range_type == "last_7_days":
        start = now - timedelta(days=7)
        end = now
    elif range_type == "last_30_days":
        start = now - timedelta(days=30)
        end = now
    elif range_type == "last_90_days":
        start = now - timedelta(days=90)
        end = now
    elif range_type == "custom":
        start = _parse_iso_datetime(params.get("start"))
        end = _parse_iso_datetime(params.get("end"))
        if start and end and end < start:
            start, end = end, start
    return start, end, range_type

def _compute_logtime_values(student_ids, params=None):
    values = {sid: 0 for sid in student_ids}
    display = {sid: "0.0 min" for sid in student_ids}
    if not student_ids:
        return values, display
    params = params if isinstance(params, dict) else {}
    start, end, _ = _logtime_range_from_params(params)
    try:
        min_minutes = int(params.get("min_minutes")) if params.get("min_minutes") not in (None, "") else None
    except Exception:
        min_minutes = None
    try:
        max_minutes = int(params.get("max_minutes")) if params.get("max_minutes") not in (None, "") else None
    except Exception:
        max_minutes = None
    try:
        cap_minutes = int(params.get("cap_minutes")) if params.get("cap_minutes") not in (None, "") else None
    except Exception:
        cap_minutes = None
    mode = params.get("mode") or "total_time"
    min_seconds = min_minutes * 60 if min_minutes else None
    max_seconds = max_minutes * 60 if max_minutes else None
    cap_seconds = cap_minutes * 60 if cap_minutes else None

    query = StudentLogSession.query.filter(StudentLogSession.student_id.in_(student_ids))
    if start:
        query = query.filter(StudentLogSession.ended_at >= start)
    if end:
        query = query.filter(StudentLogSession.started_at <= end)
    sessions = query.all()

    session_counts = {sid: 0 for sid in student_ids}
    active_days = {sid: set() for sid in student_ids}
    longest = {sid: 0 for sid in student_ids}

    for sess in sessions:
        sid = sess.student_id
        if sid not in values:
            continue
        session_start = sess.started_at or sess.created_at
        session_end = sess.ended_at or sess.last_activity_at or session_start
        if not session_start or not session_end:
            continue
        overlap_start = max(session_start, start) if start else session_start
        overlap_end = min(session_end, end) if end else session_end
        if overlap_end < overlap_start:
            continue
        duration = (overlap_end - overlap_start).total_seconds()
        if min_seconds is not None and duration < min_seconds:
            continue
        if max_seconds is not None and duration > max_seconds:
            continue
        if cap_seconds is not None and duration > cap_seconds:
            duration = cap_seconds
        if mode == "session_count":
            session_counts[sid] += 1
        elif mode == "active_days":
            day_cursor = overlap_start.date()
            end_date = overlap_end.date()
            while day_cursor <= end_date:
                active_days[sid].add(day_cursor)
                day_cursor += timedelta(days=1)
        else:
            values[sid] += duration
            if duration > longest[sid]:
                longest[sid] = duration
            session_counts[sid] += 1

    if mode == "session_count":
        for sid in values:
            values[sid] = session_counts[sid]
            display[sid] = f"{values[sid]} sessions"
    elif mode == "avg_session":
        for sid in values:
            total = values[sid]
            count = session_counts[sid]
            avg = total / count if count else 0
            values[sid] = avg
            display[sid] = _format_duration(avg)
    elif mode == "longest_session":
        for sid in values:
            values[sid] = longest[sid]
            display[sid] = _format_duration(values[sid])
    elif mode == "active_days":
        for sid in values:
            values[sid] = len(active_days[sid])
            display[sid] = f"{values[sid]} days"
    else:
        for sid in values:
            display[sid] = _format_duration(values[sid])
    return values, display

def _summarize_logtime_params(params):
    params = params if isinstance(params, dict) else {}
    parts = []
    range_type = params.get("range") or "all_time"
    if range_type == "last_7_days":
        parts.append("Range: last 7 days")
    elif range_type == "last_30_days":
        parts.append("Range: last 30 days")
    elif range_type == "last_90_days":
        parts.append("Range: last 90 days")
    elif range_type == "custom":
        start = params.get("start") or "?"
        end = params.get("end") or "?"
        parts.append(f"Range: {start} to {end}")
    else:
        parts.append("Range: all time")
    mode = params.get("mode") or "total_time"
    mode_labels = {
        "total_time": "Total time",
        "session_count": "Session count",
        "avg_session": "Average session",
        "longest_session": "Longest session",
        "active_days": "Active days",
    }
    parts.append(f"Mode: {mode_labels.get(mode, mode)}")
    if params.get("min_minutes"):
        parts.append(f"Min session: {params.get('min_minutes')}m")
    if params.get("max_minutes"):
        parts.append(f"Max session: {params.get('max_minutes')}m")
    if params.get("cap_minutes"):
        parts.append(f"Cap session: {params.get('cap_minutes')}m")
    return " • ".join(parts)

def _compute_leaderboard_rows(metric, group_id=None, params=None):
    students = _leaderboard_students(group_id=group_id)
    student_ids = [s.id for s in students]
    if not student_ids:
        return []
    values = {sid: 0 for sid in student_ids}
    display = {}
    if metric == "total_points":
        totals = db.session.query(
            Grade.student_id,
            func.coalesce(func.sum(Grade.score), 0),
        ).filter(Grade.student_id.in_(student_ids)).group_by(Grade.student_id).all()
        for sid, total in totals:
            values[sid] = float(total or 0)
    elif metric == "projects_done":
        values.update(_project_completion_counts(student_ids))
    elif metric == "logtime":
        values, display = _compute_logtime_values(student_ids, params=params)
    else:
        return []
    rows = []
    for st in students:
        entry = {"student": st, "value": values.get(st.id, 0)}
        if display:
            entry["display"] = display.get(st.id)
        rows.append(entry)
    rows.sort(key=lambda row: row["value"], reverse=True)
    for idx, row in enumerate(rows):
        row["rank"] = idx + 1
    return rows

# --------------------------------------------------------------------
# Blog helpers
# --------------------------------------------------------------------

def _is_staff(user):
    if not user:
        return False
    role = getattr(user, "role", "")
    return role in ("instructor", "admin", "mentor", "staff")

def _paginate_posts(query, page, per_page=10):
    total = query.count()
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    posts = query.order_by(BlogPost.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "posts": posts,
        "page": page,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }

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
        elif qtype == "file":
            res["manual_review"] = True
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

# Essential dunder methods needed for Python to function properly
REQUIRED_DUNDER_BUILTINS = {
    "__build_class__",  # Required for class definitions
    "__name__",         # Module name
}

def build_safe_builtins():
    safe = {}
    for name in dir(builtins):
        # Skip private methods except those explicitly required
        if name.startswith("_") and name not in REQUIRED_DUNDER_BUILTINS:
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
            expected_display = expected_output
            expected_trimmed = expected_output.strip()
            expected_literal = None
            expected_literal_defined = False
            if expected_trimmed:
                try:
                    expected_literal = ast.literal_eval(expected_trimmed)
                    expected_literal_defined = True
                except Exception:
                    expected_literal_defined = False
            status = "passed"
            error_text = ""
            output_value = ""
            result_value = None
            if not call_expr:
                status = "error"
                error_text = "Missing call expression."
            else:
                # Create environment for this test, preserving functions from env_base
                env = {}
                if env_base:
                    env.update(env_base)
                else:
                    env = safe_env()
                stdout = io.StringIO()
                original_stdout = sys.stdout
                sys.stdout = stdout
                try:
                    result = eval(call_expr, env, env)
                    result_value = result
                    output_value = repr(result)
                except Exception:
                    status = "error"
                    error_text = traceback.format_exc()
                finally:
                    sys.stdout = original_stdout
            if status == "passed" and expected_trimmed:
                if expected_literal_defined:
                    if result_value != expected_literal:
                        status = "mismatch"
                else:
                    if output_value.strip() != expected_trimmed:
                        status = "mismatch"
            results.append({
                "name": name,
                "status": status,
                "input": call_expr,
                "output": output_value,
                "expected": expected_display,
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
            submission.started_at = datetime.now(timezone.utc)
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
        time_remaining = int((deadline - datetime.now(timezone.utc)).total_seconds())
        if time_remaining <= 0 and submission.status != "submitted":
            answers = dict(base_answers)
            answers.update(draft_answers)
            submission.answers_json = answers
            submission.status = "submitted"
            submission.submitted_at = datetime.now(timezone.utc)
            submission.last_activity_at = submission.submitted_at
            grade_score, grade_total, grade_details = _grade_exam_submission(exam, answers)
            submission.score = grade_score
            submission.max_score = grade_total
            submission.grading_json = grade_details
            # Run cheating detection
            _run_cheating_detection(student, submission, request.remote_addr)
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
            submission.submitted_at = datetime.now(timezone.utc)
            submission.last_activity_at = submission.submitted_at
            submission.score = grade_score
            submission.max_score = grade_total
            submission.grading_json = grade_details
            # Run cheating detection
            _run_cheating_detection(student, submission, request.remote_addr)
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
                submission.last_activity_at = datetime.now(timezone.utc)
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
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
    }
    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append(summary)
    submission.run_logs = logs
    submission.last_activity_at = datetime.now(timezone.utc)
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
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
    })
    submission.run_logs = logs
    submission.last_activity_at = datetime.now(timezone.utc)
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
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
    })
    submission.run_logs = logs
    submission.last_activity_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True, "tests": visible + hidden, "summary": summary})

# --------------------------------------------------------------------
# Student Groups (admin)
# --------------------------------------------------------------------

@app.route("/groups", methods=["GET", "POST"])
@require_user()
def groups_list():
    raw_selected_ids = request.form.getlist("student_ids")
    selected_student_ids = []
    for raw_id in raw_selected_ids:
        try:
            selected_student_ids.append(int(raw_id))
        except (ValueError, TypeError):
            continue
    form_data = {
        "name": (request.form.get("name") or "").strip(),
        "description": request.form.get("description") or "",
        "student_ids": selected_student_ids,
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
                db.session.flush()
                for student_id in form_data["student_ids"]:
                    student = db.session.get(Student, student_id)
                    if not student:
                        continue
                    membership = StudentGroupMembership(group_id=group.id, student_id=student.id)
                    db.session.add(membership)
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
                group = db.session.get(StudentGroup, group_id)
                student = db.session.get(Student, student_id)
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
                membership = db.session.get(StudentGroupMembership, membership_id)
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
                group = db.session.get(StudentGroup, group_id)
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
                group = db.session.get(StudentGroup, group_id)
                mentor = db.session.get(User, user_id)
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
                reviewer = db.session.get(StudentGroupReviewer, reviewer_id)
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

# --------------------------------------------------------------------
# Attendance
# --------------------------------------------------------------------

def _attendance_group_label(sheet):
    if sheet.group and sheet.group.name:
        return sheet.group.name
    if sheet.group_name:
        return sheet.group_name
    return "Unknown group"

def _attendance_title(sheet):
    title = (sheet.title or "").strip()
    return title or "Session"

def _attendance_counts(entries):
    counts = {"present": 0, "late": 0, "absent": 0, "total": len(entries)}
    for entry in entries:
        status = entry.status or "present"
        if status in counts:
            counts[status] += 1
    return counts

@app.route("/attendance")
@require_user()
def attendance_list():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    message = session.pop("attendance_status", None)
    error = session.pop("attendance_error", None)
    groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    filter_group = request.args.get("group_id") or "all"
    filter_date = request.args.get("date") or ""
    query = AttendanceSheet.query.options(
        subqueryload(AttendanceSheet.entries),
        subqueryload(AttendanceSheet.group),
        subqueryload(AttendanceSheet.creator),
    )
    if filter_group and filter_group != "all":
        try:
            group_id = int(filter_group)
        except ValueError:
            group_id = None
        if group_id:
            query = query.filter_by(group_id=group_id)
    if filter_date:
        date_value = _parse_date_only(filter_date)
        if date_value:
            query = query.filter_by(date=date_value)
    sheets = query.order_by(AttendanceSheet.date.desc(), AttendanceSheet.id.desc()).all()
    sheet_rows = []
    for sheet in sheets:
        entries = sheet.entries or []
        counts = _attendance_counts(entries)
        sheet_rows.append({
            "sheet": sheet,
            "group_label": _attendance_group_label(sheet),
            "title_label": _attendance_title(sheet),
            "counts": counts,
        })
    return render_template(
        "attendance_list.html",
        sheet_rows=sheet_rows,
        groups=groups,
        filter_group=filter_group,
        filter_date=filter_date,
        message=message,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/attendance/new", methods=["GET", "POST"])
@require_user()
def attendance_new():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    default_date = datetime.now(timezone.utc).date().isoformat()
    form_data = {
        "group_id": request.form.get("group_id") or "",
        "date": request.form.get("date") or default_date,
        "title": request.form.get("title") or "",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        if not title:
            error = "Session title is required."
        try:
            group_id = int(form_data["group_id"])
        except Exception:
            group_id = 0
        if not group_id and not error:
            error = "Group selection is required."
        date_value = _parse_date_only(form_data["date"])
        if not date_value and not error:
            error = "Valid date is required."
        group = db.session.get(StudentGroup, group_id) if group_id else None
        if not error and not group:
            error = "Selected group was not found."
        if not error:
            existing = AttendanceSheet.query.filter_by(
                group_id=group.id,
                date=date_value,
                title=title,
            ).first()
            if existing:
                session["attendance_status"] = "Attendance sheet already exists for that title. You can edit it below."
                return redirect(url_for("attendance_sheet", sheet_id=existing.id))
            memberships = sorted(
                group.memberships,
                key=lambda m: (m.student.name.lower() if m.student and m.student.name else ""),
            )
            students = [m.student for m in memberships if m.student]
            if not students:
                error = "Selected group has no students."
            else:
                sheet = AttendanceSheet(
                    group_id=group.id,
                    group_name=group.name,
                    title=title,
                    date=date_value,
                    created_by_user_id=user.id if user else None,
                )
                db.session.add(sheet)
                db.session.flush()
                for student in students:
                    entry = AttendanceEntry(
                        sheet_id=sheet.id,
                        student_id=student.id,
                        student_name=student.name,
                        status="present",
                    )
                    db.session.add(entry)
                db.session.commit()
                session["attendance_status"] = (
                    f"Attendance sheet created for {group.name} on {date_value.isoformat()} ({title})."
                )
                return redirect(url_for("attendance_sheet", sheet_id=sheet.id))
    return render_template(
        "attendance_new.html",
        groups=groups,
        form_data=form_data,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/attendance/sheets/<int:sheet_id>", methods=["GET", "POST"])
@require_user()
def attendance_sheet(sheet_id):
    user = current_user()
    if not _is_staff(user):
        abort(403)
    sheet = AttendanceSheet.query.options(
        subqueryload(AttendanceSheet.entries),
        subqueryload(AttendanceSheet.group),
        subqueryload(AttendanceSheet.creator),
    ).get_or_404(sheet_id)
    message = session.pop("attendance_status", None)
    error = session.pop("attendance_error", None)
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title_raw = (request.form.get("sheet_title") or "").strip()
        title_error = False
        updated = 0
        invalid_status = False
        if title_raw:
            if title_raw != sheet.title:
                sheet.title = title_raw
                updated += 1
        else:
            title_error = True
        for entry in sheet.entries or []:
            status = request.form.get(f"status_{entry.id}") or entry.status
            if status not in ATTENDANCE_STATUS_VALUES:
                invalid_status = True
                continue
            notes_raw = (request.form.get(f"notes_{entry.id}") or "").strip()
            notes = notes_raw or None
            if status != entry.status or notes != entry.notes:
                entry.status = status
                entry.notes = notes
                updated += 1
        db.session.commit()
        if title_error and invalid_status:
            session["attendance_error"] = "Session title is required and some status values were invalid."
        elif title_error:
            session["attendance_error"] = "Session title is required."
        elif invalid_status:
            session["attendance_error"] = "Some status values were invalid and ignored."
        if updated:
            session["attendance_status"] = f"Attendance updated ({updated} change(s))."
        else:
            session["attendance_status"] = "Attendance saved."
        return redirect(url_for("attendance_sheet", sheet_id=sheet.id))
    entries = sorted(
        sheet.entries or [],
        key=lambda e: (e.student_name or (e.student.name if e.student else "")),
    )
    counts = _attendance_counts(entries)
    return render_template(
        "attendance_sheet.html",
        sheet=sheet,
        entries=entries,
        counts=counts,
        status_options=ATTENDANCE_STATUS_OPTIONS,
        group_label=_attendance_group_label(sheet),
        title_label=_attendance_title(sheet),
        message=message,
        error=error,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/leaderboards", methods=["GET", "POST"])
@require_user()
def leaderboards_admin():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    form_data = {
        "title": request.form.get("title") or "",
        "metric": request.form.get("metric") or "total_points",
        "group_id": request.form.get("group_id") or "all",
        "log_range": request.form.get("log_range") or "all_time",
        "log_start": request.form.get("log_start") or "",
        "log_end": request.form.get("log_end") or "",
        "log_min_minutes": request.form.get("log_min_minutes") or "",
        "log_max_minutes": request.form.get("log_max_minutes") or "",
        "log_cap_minutes": request.form.get("log_cap_minutes") or "",
        "log_mode": request.form.get("log_mode") or "total_time",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        action = request.form.get("action") or "create"
        if action == "create":
            metric = form_data["metric"]
            if metric not in LEADERBOARD_METRICS:
                error = "Pick a valid metric."
            title = (form_data["title"] or "").strip()
            if not title and not error:
                title = LEADERBOARD_METRICS[metric]["label"]
            group_id = None
            group_raw = form_data["group_id"]
            if group_raw and group_raw != "all":
                try:
                    gid = int(group_raw)
                    group = db.session.get(StudentGroup, gid)
                    if not group:
                        error = "Group not found."
                    else:
                        group_id = gid
                except Exception:
                    error = "Invalid group selection."
            if not title and not error:
                error = "Title is required."
            params = None
            if not error and metric == "logtime":
                def _parse_int(val):
                    try:
                        return int(val)
                    except Exception:
                        return None
                params = {
                    "range": form_data["log_range"] or "all_time",
                    "start": (parse_dt_local(form_data["log_start"]).isoformat()
                              if form_data["log_start"] else None),
                    "end": (parse_dt_local(form_data["log_end"]).isoformat()
                            if form_data["log_end"] else None),
                    "min_minutes": _parse_int(form_data["log_min_minutes"]),
                    "max_minutes": _parse_int(form_data["log_max_minutes"]),
                    "cap_minutes": _parse_int(form_data["log_cap_minutes"]),
                    "mode": form_data["log_mode"] or "total_time",
                }
            if not error:
                lb = Leaderboard(
                    title=title,
                    metric=metric,
                    group_id=group_id,
                    params_json=params,
                    is_published=False,
                )
                db.session.add(lb)
                db.session.commit()
                return redirect(url_for("leaderboards_admin"))
        elif action in ("publish", "unpublish", "delete"):
            try:
                lb_id = int(request.form.get("leaderboard_id") or 0)
            except Exception:
                lb_id = 0
            if not lb_id:
                abort(400)
            lb = Leaderboard.query.get_or_404(lb_id)
            if action == "delete":
                db.session.delete(lb)
            elif action == "publish":
                lb.is_published = True
            elif action == "unpublish":
                lb.is_published = False
            db.session.commit()
            return redirect(url_for("leaderboards_admin"))

    leaderboards = Leaderboard.query.order_by(Leaderboard.created_at.desc()).all()
    leaderboard_rows = {}
    logtime_summaries = {}
    for lb in leaderboards:
        rows = _compute_leaderboard_rows(lb.metric, lb.group_id, params=lb.params_json)
        leaderboard_rows[lb.id] = rows[:5]
        if lb.metric == "logtime":
            logtime_summaries[lb.id] = _summarize_logtime_params(lb.params_json)
    return render_template(
        "leaderboards_admin.html",
        leaderboards=leaderboards,
        leaderboard_rows=leaderboard_rows,
        logtime_summaries=logtime_summaries,
        groups=groups,
        metrics=LEADERBOARD_METRICS,
        form_data=form_data,
        error=error,
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/leaderboards/published")
def leaderboards_public():
    user = current_user()
    student = current_student()
    if not (user or student):
        return redirect(url_for("login", next=request.path))
    boards = Leaderboard.query.filter_by(is_published=True).order_by(Leaderboard.created_at.desc()).all()
    leaderboard_rows = {}
    logtime_summaries = {}
    for lb in boards:
        leaderboard_rows[lb.id] = _compute_leaderboard_rows(lb.metric, lb.group_id, params=lb.params_json)
        if lb.metric == "logtime":
            logtime_summaries[lb.id] = _summarize_logtime_params(lb.params_json)
    viewer_name = student.name if student else session.get("student_name")
    return render_template(
        "leaderboards_public.html",
        leaderboards=boards,
        leaderboard_rows=leaderboard_rows,
        logtime_summaries=logtime_summaries,
        metrics=LEADERBOARD_METRICS,
        user=user,
        student_name=viewer_name,
    )

@app.route("/leaderboards/<int:leaderboard_id>")
def leaderboard_view(leaderboard_id):
    user = current_user()
    student = current_student()
    if not (user or student):
        return redirect(url_for("login", next=request.path))
    lb = Leaderboard.query.get_or_404(leaderboard_id)
    if not lb.is_published and not _is_staff(user):
        abort(403)
    rows = _compute_leaderboard_rows(lb.metric, lb.group_id, params=lb.params_json)
    logtime_summary = _summarize_logtime_params(lb.params_json) if lb.metric == "logtime" else ""
    viewer_name = student.name if student else session.get("student_name")
    return render_template(
        "leaderboard_view.html",
        leaderboard=lb,
        rows=rows,
        logtime_summary=logtime_summary,
        metrics=LEADERBOARD_METRICS,
        user=user,
        student_name=viewer_name,
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
        "retry_cooldown_minutes": request.form.get("retry_cooldown_minutes") or "",
        "starts_at": request.form.get("starts_at") or "",
        "due_at": request.form.get("due_at") or "",
        "hard_deadline_at": request.form.get("hard_deadline_at") or "",
        "late_penalty_percent": request.form.get("late_penalty_percent") or "",
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
        retry_minutes_value = 0
        retry_raw = form_data["retry_cooldown_minutes"].strip()
        if retry_raw and not error:
            try:
                retry_minutes_value = max(0, int(retry_raw))
            except Exception:
                error = "Retry cooldown must be a number (minutes)."
        
        # Parse deadline fields
        starts_at_val = None
        due_at_val = None
        hard_deadline_at_val = None
        late_penalty_val = 0.0
        
        if form_data["starts_at"].strip() and not error:
            try:
                starts_at_val = datetime.strptime(form_data["starts_at"].strip(), "%Y-%m-%dT%H:%M")
            except Exception:
                error = "Invalid start date format."
        
        if form_data["due_at"].strip() and not error:
            try:
                due_at_val = datetime.strptime(form_data["due_at"].strip(), "%Y-%m-%dT%H:%M")
            except Exception:
                error = "Invalid due date format."
        
        if form_data["hard_deadline_at"].strip() and not error:
            try:
                hard_deadline_at_val = datetime.strptime(form_data["hard_deadline_at"].strip(), "%Y-%m-%dT%H:%M")
            except Exception:
                error = "Invalid hard deadline format."
        
        if form_data["late_penalty_percent"].strip() and not error:
            try:
                late_penalty_val = max(0.0, min(100.0, float(form_data["late_penalty_percent"].strip())))
            except Exception:
                error = "Late penalty must be a number (0-100)."
        
        # Parse time window availability
        availability_enabled = request.form.get("availability_enabled") == "1"
        availability_rules_json = None
        
        if availability_enabled and not error:
            rules = {}
            days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
            for day in days:
                if request.form.get(f"day_{day}") == "1":
                    start_time = request.form.get(f"time_{day}_start", "09:00")
                    end_time = request.form.get(f"time_{day}_end", "17:00")
                    rules[day] = [{"start": start_time, "end": end_time}]
            
            if rules:
                availability_rules_json = json.dumps(rules)
        
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
                retry_cooldown_minutes=retry_minutes_value,
                starts_at=starts_at_val,
                due_at=due_at_val,
                hard_deadline_at=hard_deadline_at_val,
                late_penalty_percent=late_penalty_val,
                availability_enabled=availability_enabled,
                availability_rules=availability_rules_json,
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
    status_message = session.pop("projects_status", None)
    return render_template(
        "projects_show.html",
        project=project,
        tasks=tasks,
        dependencies=deps,
        other_projects=other_projects,
        group_assignments=assignments,
        student_groups=student_groups,
        status_message=status_message,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/edit", methods=["GET", "POST"])
@require_user()
def projects_edit(code):
    project = Project.query.filter_by(code=code).first_or_404()
    error = None
    
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        instructions = (request.form.get("instructions") or "").strip()
        required_task_count = (request.form.get("required_task_count") or "").strip()
        required_proficiency_tag = (request.form.get("required_proficiency_tag") or "").strip()
        
        if not title:
            error = "Project title is required."
        
        if not error:
            project.title = title
            project.description = description or None
            project.instructions = instructions or None
            project.required_proficiency_tag = required_proficiency_tag or None
            
            if required_task_count:
                try:
                    project.required_task_count = max(0, int(required_task_count))
                except Exception:
                    error = "Required task count must be a number."
            else:
                project.required_task_count = None
            
            if not error:
                db.session.commit()
                return redirect(url_for("projects_show", code=project.code))
    
    form_data = {
        "title": project.title,
        "description": project.description or "",
        "instructions": project.instructions or "",
        "required_task_count": str(project.required_task_count) if project.required_task_count else "",
        "required_proficiency_tag": project.required_proficiency_tag or "",
    }
    
    return render_template(
        "projects_edit.html",
        project=project,
        form_data=form_data,
        error=error,
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
    retry_raw = (request.form.get("retry_cooldown_minutes") or "").strip()
    try:
        points_val = int(points_raw) if points_raw else project.points or 0
        retry_val = int(retry_raw) if retry_raw else project.retry_cooldown_minutes or 0
    except Exception:
        abort(400, "Points and retry cooldown must be numbers.")
    project.points = max(0, points_val)
    project.retry_cooldown_minutes = max(0, retry_val)
    
    # Update deadline fields
    starts_at_raw = (request.form.get("starts_at") or "").strip()
    due_at_raw = (request.form.get("due_at") or "").strip()
    hard_deadline_raw = (request.form.get("hard_deadline_at") or "").strip()
    late_penalty_raw = (request.form.get("late_penalty_percent") or "").strip()
    
    project.starts_at = datetime.strptime(starts_at_raw, "%Y-%m-%dT%H:%M") if starts_at_raw else None
    project.due_at = datetime.strptime(due_at_raw, "%Y-%m-%dT%H:%M") if due_at_raw else None
    project.hard_deadline_at = datetime.strptime(hard_deadline_raw, "%Y-%m-%dT%H:%M") if hard_deadline_raw else None
    project.late_penalty_percent = max(0.0, min(100.0, float(late_penalty_raw))) if late_penalty_raw else 0.0
    
    # Update time window availability
    availability_enabled = request.form.get("availability_enabled") == "1"
    project.availability_enabled = availability_enabled
    
    if availability_enabled:
        rules = {}
        days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        for day in days:
            if request.form.get(f"day_{day}") == "1":
                start_time = request.form.get(f"time_{day}_start", "09:00")
                end_time = request.form.get(f"time_{day}_end", "17:00")
                rules[day] = [{"start": start_time, "end": end_time}]
        
        project.availability_rules = json.dumps(rules) if rules else None
    else:
        project.availability_rules = None
    
    db.session.commit()
    return redirect(url_for("projects_show", code=project.code))

@app.post("/projects/<code>/recalculate-points")
@require_user()
def projects_recalculate_points(code):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    assignment_name = f"Project: {project.title}"
    deleted = Grade.query.filter_by(assignment=assignment_name).delete(synchronize_session=False)
    awarded = 0
    if project.points and project.points > 0:
        student_ids = [
            row[0]
            for row in db.session.query(ProjectTaskSubmission.student_id)
            .filter(
                ProjectTaskSubmission.project_id == project.id,
                ProjectTaskSubmission.student_id != None,
            )
            .distinct()
            .all()
        ]
        if student_ids:
            students = Student.query.filter(Student.id.in_(student_ids)).all()
            for student in students:
                if _project_completed(project, student):
                    _create_grade_entry(
                        student,
                        assignment_name,
                        float(project.points),
                        float(project.points),
                        remarks=f"Auto-awarded for completing project '{project.title}'.",
                    )
                    awarded += 1
    db.session.commit()
    session["projects_status"] = (
        f"Reassigned project points: removed {deleted} grade(s), awarded {awarded}."
    )
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

@app.post("/projects/<code>/tasks/<int:task_id>/move")
@require_user()
def projects_task_move(code, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    direction = request.form.get("direction") or "up"
    
    # Get all tasks ordered by order_index
    tasks = ProjectTask.query.filter_by(project_id=project.id).order_by(
        ProjectTask.order_index.asc(), ProjectTask.id.asc()
    ).all()
    
    current_idx = None
    for idx, t in enumerate(tasks):
        if t.id == task.id:
            current_idx = idx
            break
    
    if current_idx is not None:
        if direction == "up" and current_idx > 0:
            tasks[current_idx], tasks[current_idx - 1] = tasks[current_idx - 1], tasks[current_idx]
        elif direction == "down" and current_idx < len(tasks) - 1:
            tasks[current_idx], tasks[current_idx + 1] = tasks[current_idx + 1], tasks[current_idx]
        
        for idx, t in enumerate(tasks):
            t.order_index = idx
        
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
            group = db.session.get(StudentGroup, group_id)
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
    auto_flag_vals = request.form.getlist("auto_grade")
    review_flag = request.form.get("requires_review")
    resource_upload = request.files.get("resource_file")
    form_data = {
        "title": request.form.get("title") or "",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "questions_payload": request.form.get("questions_payload") or "[]",
        "required": True if request.method != "POST" and req_flag is None else bool(req_flag),
        "auto_grade": True if request.method != "POST" and not auto_flag_vals else ("1" in auto_flag_vals),
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
            db.session.flush()
            if resource_upload and resource_upload.filename:
                file_info, upload_error = _save_task_resource(task, resource_upload)
                if upload_error:
                    db.session.rollback()
                    error = upload_error
                else:
                    task.resource_file = file_info
            if not error:
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
    auto_flag_vals = request.form.getlist("auto_grade")
    review_flag = request.form.get("requires_review")
    resource_upload = request.files.get("resource_file")
    remove_resource = request.form.get("remove_resource") == "1"
    if request.method == "POST":
        form_data = {
            "title": request.form.get("title") or "",
            "description": request.form.get("description") or "",
            "instructions": request.form.get("instructions") or "",
            "questions_payload": request.form.get("questions_payload") or "[]",
            "required": bool(req_flag),
            "auto_grade": ("1" in auto_flag_vals),
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
            
            # Handle resource file removal
            if remove_resource:
                if task.resource_file:
                    _remove_uploaded_file(task.resource_file)
                    task.resource_file = None
            # Handle resource file upload (only if not removing and file provided)
            elif resource_upload and resource_upload.filename:
                existing_info = _extract_file_info(task.resource_file)
                file_info, upload_error = _save_task_resource(task, resource_upload, existing_info)
                if upload_error:
                    db.session.rollback()
                    error = upload_error
                else:
                    task.resource_file = file_info
            if not error:
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
        _remove_uploaded_file(task.resource_file)
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
        
        # Check deadline status
        deadline_status = _check_project_deadline_status(project)
        
        # Check time window availability
        time_window_status = _check_time_window_availability(project)
        
        # Check if student has any submissions for this project
        has_submissions = ProjectTaskSubmission.query.filter_by(
            project_id=project.id,
            student_id=student.id
        ).first() is not None
        
        # If time windows are enabled and student has no submissions, hide project outside windows
        if project.availability_enabled and not has_submissions and not time_window_status["available"]:
            continue
        
        unlocked = _project_dependencies_met(project, student) and deadline_status["available"] and time_window_status["available"]
        completed = _project_completed(project, student) if unlocked else False
        tasks = []
        completed_count = 0
        for task in project.tasks:
            submission = _project_task_submission(task, student)
            status = submission.status if submission and submission.status else "not_started"
            latest_attempt = _latest_task_attempt(submission) if submission else None
            review_notes = None
            reviewer_name = None
            if latest_attempt:
                review_notes = latest_attempt.review_notes
                if latest_attempt.reviewer:
                    reviewer_name = latest_attempt.reviewer.name
            if not review_notes and submission and submission.review_notes:
                review_notes = submission.review_notes
            if status in ("submitted", "accepted", "pending_review"):
                completed_count += 1
            cooldown_seconds = 0
            can_retry_now = True
            if submission:
                if status in ("pending_review", "submitted", "accepted"):
                    can_retry_now = False
                elif status == "rejected":
                    retry_minutes = project.retry_cooldown_minutes or 0
                    if retry_minutes > 0 and submission.submitted_at:
                        elapsed = (datetime.now(timezone.utc) - submission.submitted_at).total_seconds()
                        wait_seconds = int(retry_minutes * 60 - elapsed)
                        if wait_seconds > 0:
                            can_retry_now = False
                            cooldown_seconds = wait_seconds
            tasks.append({
                "task": task,
                "status": status,
                "submission": submission,
                "review_notes": review_notes,
                "reviewer_name": reviewer_name,
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
            "deadline_status": deadline_status,
            "time_window_status": time_window_status,
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

@app.route("/student/projects/<code>")
@require_student()
def student_project_detail(code):
    project = Project.query.filter_by(code=code).first_or_404()
    student = current_student()
    if not _project_visible_to_student(project, student):
        abort(403)
    unlocked = _project_dependencies_met(project, student)
    tasks = []
    for task in project.tasks:
        submission = _project_task_submission(task, student)
        status = submission.status if submission and submission.status else "not_started"
        latest_attempt = _latest_task_attempt(submission) if submission else None
        review_notes = None
        reviewer_name = None
        if latest_attempt:
            review_notes = latest_attempt.review_notes
            if latest_attempt.reviewer:
                reviewer_name = latest_attempt.reviewer.name
        if not review_notes and submission and submission.review_notes:
            review_notes = submission.review_notes
        cooldown_seconds = 0
        can_retry_now = True
        if submission:
            if status in ("pending_review", "submitted", "accepted"):
                can_retry_now = False
            elif status == "rejected":
                retry_minutes = project.retry_cooldown_minutes or 0
                if retry_minutes > 0 and submission.submitted_at:
                    elapsed = (datetime.now(timezone.utc) - submission.submitted_at).total_seconds()
                    wait_seconds = int(retry_minutes * 60 - elapsed)
                    if wait_seconds > 0:
                        can_retry_now = False
                        cooldown_seconds = wait_seconds
        tasks.append({
            "task": task,
            "submission": submission,
            "status": status,
            "review_notes": review_notes,
            "reviewer_name": reviewer_name,
            "can_retry_now": can_retry_now,
            "cooldown_seconds_remaining": cooldown_seconds,
        })
    return render_template(
        "projects_student_detail.html",
        project=project,
        unlocked=unlocked,
        tasks=tasks,
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
        "task_id": task.id,
        "resource_file": task.resource_file if isinstance(task.resource_file, dict) else None,
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
    
    # Check deadline status
    deadline_status = _check_project_deadline_status(project)
    if not deadline_status["available"]:
        # Redirect to projects page - the project will appear in locked section
        return redirect(url_for("student_projects"))
    
    # Check time window availability
    time_window_status = _check_time_window_availability(project)
    if not time_window_status["available"]:
        # Redirect to projects page - the project will appear in locked section
        return redirect(url_for("student_projects"))
    
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
    now = datetime.now(timezone.utc)
    cooldown_minutes = project.retry_cooldown_minutes or 0
    cooldown_seconds_remaining = 0
    status = submission.status if submission and submission.status else "in_progress"
    can_submit = status not in ("submitted", "pending_review", "accepted")
    if can_submit and cooldown_minutes > 0 and status == "rejected":
        if submission.submitted_at:
            elapsed = (now - submission.submitted_at).total_seconds()
            wait_seconds = int(cooldown_minutes * 60 - elapsed)
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
        
        # Check deadline before allowing submission
        deadline_status = _check_project_deadline_status(project)
        if not deadline_status["available"]:
            return render_template(
                "projects_take.html",
                project=project,
                task=task,
                question=questions[q_index] if total_questions else None,
                total_questions=total_questions,
                current_index=q_index,
                has_prev=(q_index > 0),
                has_next=(q_index + 1 < total_questions),
                can_submit=False,
                preview=False,
                already_submitted=False,
                previous_answers=previous_answers,
                time_remaining_seconds=None,
                user=current_user(),
                student_name=student.name,
                run_log_url=url_for("projects_task_log_run", code=project.code, task_id=task.id),
                cooldown_seconds_remaining=0,
                submission_id=submission.id,
                upload_error=f"Cannot submit: {deadline_status['status_message']}",
            ), 403
        
        # Check time window availability before allowing submission
        time_window_status = _check_time_window_availability(project)
        if not time_window_status["available"]:
            error_message = time_window_status.get("reason", "Not available at this time")
            if time_window_status.get("next_window"):
                error_message += f". Next available: {time_window_status['next_window']}"
            
            return render_template(
                "projects_take.html",
                project=project,
                task=task,
                question=questions[q_index] if total_questions else None,
                total_questions=total_questions,
                current_index=q_index,
                has_prev=(q_index > 0),
                has_next=(q_index + 1 < total_questions),
                can_submit=False,
                preview=False,
                already_submitted=False,
                previous_answers=previous_answers,
                time_remaining_seconds=None,
                user=current_user(),
                student_name=student.name,
                run_log_url=url_for("projects_task_log_run", code=project.code, task_id=task.id),
                cooldown_seconds_remaining=0,
                submission_id=submission.id,
                upload_error=f"Cannot submit: {deadline_status['status_message']}",
            ), 403
        
        post_q_index = clamp_q(request.form.get("q_index", q_index))
        q_index = post_q_index
        current_question = questions[q_index] if total_questions else None
        upload_error = None
        if current_question:
            qid = current_question.get("id")
            if qid:
                field = f"answer_{qid}"
                qtype = current_question.get("type")
                if qtype == "multi":
                    vals = request.form.getlist(field)
                    val = "||".join(vals)
                elif qtype == "file":
                    uploaded = request.files.get(field)
                    existing_info = _extract_file_info(previous_answers.get(qid))
                    if uploaded and uploaded.filename:
                        file_info, error = _save_task_upload(submission, current_question, qid, uploaded, existing_info)
                        if error:
                            upload_error = error
                            val = existing_info or ""
                        else:
                            val = file_info
                    else:
                        val = existing_info or ""
                else:
                    val = request.form.get(field, "")
                if upload_error:
                    return render_template(
                        "projects_take.html",
                        project=project,
                        task=task,
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
                        submission_id=submission.id,
                        upload_error=upload_error,
                    ), 400
                draft_answers[qid] = val
                previous_answers[qid] = val
                _save_task_draft(task.id, draft_answers)
        action = request.form.get("nav_action") or request.form.get("nav_action_auto")
        if not action:
            if total_questions and q_index >= total_questions - 1:
                action = "submit"
            else:
                action = "next"
        if action == "save":
            answers = dict(base_answers)
            answers.update(draft_answers)
            submission.answers_json = answers
            submission.last_activity_at = datetime.now(timezone.utc)
            db.session.commit()
            return redirect(url_for("student_projects"))
        if action == "submit":
            if not can_submit:
                return render_template(
                    "projects_take.html",
                    project=project,
                    task=task,
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
                    submission_id=submission.id,
                ), 403
            answers = dict(base_answers)
            answers.update(draft_answers)
            grade_score = 0
            grade_total = 0
            grade_details = []
            if task.auto_grade:
                grade_score, grade_total, grade_details = _grade_exam_submission(task, answers)
                try:
                    app.logger.info(
                        "TASK AUTO-GRADE DEBUG",
                        extra={
                            "project": project.code,
                            "task_id": task.id,
                            "student_id": student.id,
                            "answers": answers,
                            "grade_score": grade_score,
                            "grade_total": grade_total,
                            "grade_details": grade_details,
                        },
                    )
                except Exception:
                    app.logger.info(f"TASK AUTO-GRADE DEBUG [{project.code}-{task.id}] score={grade_score}/{grade_total} answers={answers}")
            
            # Apply late penalty if past due date
            late_penalty_applied = 0.0
            if deadline_status["is_late"] and deadline_status["late_penalty"] > 0:
                penalty_percent = deadline_status["late_penalty"]
                late_penalty_applied = (grade_score * penalty_percent) / 100.0
                grade_score = max(0, grade_score - late_penalty_applied)
                grade_details.append({
                    "question_id": "_late_penalty",
                    "description": f"Late submission penalty ({penalty_percent}%)",
                    "score": -late_penalty_applied,
                    "max_score": 0,
                    "is_correct": False,
                })
            
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
            grade_details_for_history = grade_details
            if not grade_details_for_history and ENABLE_BACKEND_CODE_RUNS:
                has_code_questions = any((q.get("type") == "code") for q in questions)
                if has_code_questions:
                    try:
                        _, _, grade_details_for_history = _grade_exam_submission(task, answers)
                    except Exception:
                        grade_details_for_history = []
            attempt = ProjectTaskAttempt(
                submission_id=submission.id,
                attempt_number=_next_task_attempt_number(submission.id),
                answers_json=answers,
                run_logs=submission.run_logs if isinstance(submission.run_logs, list) else [],
                status=submission.status,
                score=grade_score,
                max_score=grade_total,
                grading_json=grade_details_for_history or None,
                submitted_at=now,
            )
            db.session.add(attempt)
            # Run cheating detection
            _run_cheating_detection(student, submission, request.remote_addr)
            print("----------- Checking request data:", request)
            print("------------ Request ip:", request.remote_addr)
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
            submission.last_activity_at = datetime.now(timezone.utc)
            db.session.commit()
            target = q_index
            if action == "prev":
                target = max(0, q_index - 1)
            elif action == "next":
                target = min(total_questions - 1, q_index + 1) if total_questions else 0
            return redirect(url_for("project_task_take", code=project.code, task_id=task.id, q=target))

    current_question = dict(questions[q_index]) if total_questions else None
    
    # Calculate time remaining until deadline
    time_remaining_seconds = None
    now = datetime.utcnow()
    
    if project.hard_deadline_at:
        time_remaining_seconds = int((project.hard_deadline_at - now).total_seconds())
        if time_remaining_seconds < 0:
            time_remaining_seconds = 0
    elif project.due_at:
        time_remaining_seconds = int((project.due_at - now).total_seconds())
        if time_remaining_seconds < 0:
            time_remaining_seconds = 0
    
    return render_template(
        "projects_take.html",
        project=project,
        task=task,
        question=current_question,
        total_questions=total_questions,
        current_index=q_index,
        has_prev=(q_index > 0),
        has_next=(q_index + 1 < total_questions),
        can_submit=can_submit,
        preview=preview,
        already_submitted=(submission.status in ("submitted", "pending_review", "accepted", "rejected")),
        previous_answers=previous_answers,
        time_remaining_seconds=time_remaining_seconds,
        user=current_user(),
        student_name=student.name,
        run_log_url=url_for("projects_task_log_run", code=project.code, task_id=task.id),
        cooldown_seconds_remaining=cooldown_seconds_remaining,
        submission_id=submission.id,
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
    latest_attempt = _latest_task_attempt(submission)
    if latest_attempt and isinstance(latest_attempt.answers_json, dict):
        answers = latest_attempt.answers_json
    else:
        answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_source = latest_attempt.run_logs if latest_attempt and hasattr(latest_attempt, "run_logs") else submission.run_logs
    logs_by_question = _run_logs_by_question(logs_source if isinstance(logs_source, list) else None)
    return render_template(
        "projects_submission_task_detail.html",
        project=project,
        student=student,
        task=task,
        submission=submission,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        grading_by_question={},
        attempt_rows=[],
        latest_attempt_id=(latest_attempt.id if latest_attempt else None),
        latest_attempt=latest_attempt,
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
        user=current_user(),
        student_name=student.name,
    )

@app.route("/projects/tasks/<int:task_id>/resource")
def project_task_resource_download(task_id):
    task = ProjectTask.query.get_or_404(task_id)
    project = task.project
    user = current_user()
    student = current_student()
    if not user and not student:
        return redirect(url_for("login", next=request.path))
    if student:
        if not _project_visible_to_student(project, student):
            abort(403)
        if not _project_dependencies_met(project, student):
            abort(403)
    file_info = _extract_file_info(task.resource_file)
    if not file_info:
        abort(404)
    full_path = _safe_upload_path(file_info.get("path"))
    if not full_path or not os.path.isfile(full_path):
        abort(404)
    download_name = secure_filename(file_info.get("original_name") or file_info.get("stored_name") or "resource") or "resource"
    return send_file(full_path, as_attachment=True, download_name=download_name)

@app.route("/projects/submissions/<int:submission_id>/files/<question_id>")
def project_task_file_download(submission_id, question_id):
    submission = ProjectTaskSubmission.query.get_or_404(submission_id)
    user = current_user()
    student = current_student()
    if not user and not student:
        return redirect(url_for("login", next=request.path))
    if student:
        if submission.student_id != student.id:
            abort(403)
        if submission.project and not _project_visible_to_student(submission.project, student):
            abort(403)
    attempt_id = request.args.get("attempt_id")
    attempt = None
    if attempt_id:
        try:
            attempt_id = int(attempt_id)
        except Exception:
            attempt_id = None
    if attempt_id:
        attempt = ProjectTaskAttempt.query.filter_by(id=attempt_id, submission_id=submission.id).first()
    questions = submission.task.questions_json if submission.task and isinstance(submission.task.questions_json, list) else []
    question = next((q for q in questions if str(q.get("id")) == str(question_id)), None)
    if not question or question.get("type") != "file":
        abort(404)
    if attempt and isinstance(attempt.answers_json, dict):
        answers = attempt.answers_json
    else:
        answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    file_info = _extract_file_info(answers.get(str(question_id)))
    if not file_info:
        abort(404)
    full_path = _safe_upload_path(file_info.get("path"))
    if not full_path or not os.path.isfile(full_path):
        abort(404)
    download_name = secure_filename(file_info.get("original_name") or file_info.get("stored_name") or "submission.zip") or "submission.zip"
    return send_file(full_path, as_attachment=True, download_name=download_name)

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

@app.post("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>/validate")
@require_user()
def projects_submission_task_validate(code, student_id, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student.id).first_or_404()
    submission.status = "accepted"
    if not submission.submitted_at:
        submission.submitted_at = datetime.now(timezone.utc)
    submission.last_activity_at = datetime.now(timezone.utc)
    _record_task_attempt_review(submission, status="accepted", reviewer=current_user())
    if submission.student and _project_completed(project, submission.student):
        _award_project_points_if_needed(project, submission.student)
    db.session.commit()
    return redirect(url_for("projects_student_submissions", code=project.code, student_id=student.id))

@app.post("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>/need-rework")
@require_user()
def projects_submission_task_need_rework(code, student_id, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student.id).first_or_404()
    submission.status = "rejected"
    submission.last_activity_at = datetime.now(timezone.utc)
    _record_task_attempt_review(submission, status="rejected", reviewer=current_user())
    db.session.commit()
    return redirect(url_for("projects_student_submissions", code=project.code, student_id=student.id))

@app.post("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>/reset")
@require_user()
def projects_submission_task_reset(code, student_id, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student.id).first()
    if submission:
        db.session.delete(submission)
        db.session.commit()
    # Also clear any session draft for this task (in case the student has one)
    _clear_task_draft(task_id)
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
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
    }
    logs = submission.run_logs if isinstance(submission.run_logs, list) else []
    logs.append(summary)
    submission.run_logs = logs
    submission.last_activity_at = datetime.now(timezone.utc)
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
    latest_attempt = _latest_task_attempt(submission)
    if latest_attempt and isinstance(latest_attempt.answers_json, dict):
        answers = latest_attempt.answers_json
    else:
        answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_source = latest_attempt.run_logs if latest_attempt and hasattr(latest_attempt, "run_logs") else submission.run_logs
    logs_by_question = _run_logs_by_question(logs_source if isinstance(logs_source, list) else None)
    grading_by_question = _grading_by_question(latest_attempt.grading_json) if latest_attempt else {}
    attempts = ProjectTaskAttempt.query.filter_by(submission_id=submission.id).order_by(ProjectTaskAttempt.attempt_number.desc()).all()
    attempt_rows = []
    for attempt in attempts:
        attempt_rows.append({
            "attempt": attempt,
            "answers": attempt.answers_json if isinstance(attempt.answers_json, dict) else {},
            "logs_by_question": _run_logs_by_question(attempt.run_logs if isinstance(attempt.run_logs, list) else None),
            "grading_by_question": _grading_by_question(attempt.grading_json),
        })
    return render_template(
        "projects_submission_task_detail.html",
        project=project,
        student=student,
        task=task,
        submission=submission,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        grading_by_question=grading_by_question,
        attempt_rows=attempt_rows,
        latest_attempt_id=(latest_attempt.id if latest_attempt else None),
        latest_attempt=latest_attempt,
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews")
@require_user()
def projects_reviews():
    user = current_user()
    sort_mode = request.args.get("sort", "newest")
    project_filter = request.args.get("project_id")
    warning_filter = request.args.get("warning_filter", "all")  # all, flagged, warned, clean
    
    try:
        project_filter_id = int(project_filter) if project_filter else None
    except ValueError:
        project_filter_id = None
    
    query = ProjectTaskSubmission.query.filter_by(status="pending_review")
    
    if project_filter_id:
        query = query.filter_by(project_id=project_filter_id)
    
    # Apply warning filter
    if warning_filter == "flagged":
        # Only flagged students
        flagged_ids = [s.id for s in Student.query.filter_by(is_flagged=True).all()]
        if flagged_ids:
            query = query.filter(ProjectTaskSubmission.student_id.in_(flagged_ids))
        else:
            query = query.filter(ProjectTaskSubmission.student_id == -1)  # No results
    elif warning_filter == "warned":
        # Students with warnings but not flagged
        warned_students = Student.query.filter(Student.warnings_json != None).all()
        warned_ids = [s.id for s in warned_students if not s.is_flagged and s.warnings_json and len(s.warnings_json) > 0]
        if warned_ids:
            query = query.filter(ProjectTaskSubmission.student_id.in_(warned_ids))
        else:
            query = query.filter(ProjectTaskSubmission.student_id == -1)  # No results
    elif warning_filter == "clean":
        # Only students with no warnings and not flagged
        warned_or_flagged = Student.query.filter(
            db.or_(Student.is_flagged == True, Student.warnings_json != None)
        ).all()
        problematic_ids = [s.id for s in warned_or_flagged if s.is_flagged or (s.warnings_json and len(s.warnings_json) > 0)]
        if problematic_ids:
            query = query.filter(~ProjectTaskSubmission.student_id.in_(problematic_ids))
    
    if sort_mode == "oldest":
        query = query.order_by(ProjectTaskSubmission.submitted_at.asc())
    else:
        sort_mode = "newest"
        query = query.order_by(ProjectTaskSubmission.submitted_at.desc())
    
    submissions = query.all()
    
    # Add warning information for each submission
    for sub in submissions:
        sub.has_warnings_for_this_task = _submission_has_warnings(sub.student, sub) if sub.student else False
    
    # Get warning counts for statistics
    flagged_count = Student.query.filter_by(is_flagged=True).count()
    warned_students = Student.query.filter(Student.warnings_json != None).all()
    warned_count = sum(1 for s in warned_students if not s.is_flagged and s.warnings_json and len(s.warnings_json) > 0)
    
    # Mentors can see all pending reviews, regardless of group assignments.
    projects = Project.query.order_by(Project.title.asc()).all()
    return render_template(
        "projects_reviews.html",
        submissions=submissions,
        filter_sort=sort_mode,
        filter_project_id=project_filter_id,
        filter_warning=warning_filter,
        flagged_count=flagged_count,
        warned_count=warned_count,
        projects=projects,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews/mine")
@require_user()
def projects_reviews_mine():
    user = current_user()
    attempts = ProjectTaskAttempt.query.filter(
        ProjectTaskAttempt.reviewed_by_user_id == user.id,
        ProjectTaskAttempt.reviewed_at != None,
    ).order_by(ProjectTaskAttempt.reviewed_at.desc()).all()
    return render_template(
        "projects_reviews_mine.html",
        attempts=attempts,
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
    attempt_id = request.args.get("attempt_id")
    review_attempt = None
    if attempt_id:
        try:
            attempt_id = int(attempt_id)
        except Exception:
            attempt_id = None
    if attempt_id:
        review_attempt = ProjectTaskAttempt.query.filter_by(id=attempt_id, submission_id=submission.id).first()
    latest_attempt = _latest_task_attempt(submission)
    active_attempt = review_attempt or latest_attempt
    is_latest_attempt = bool(active_attempt and latest_attempt and active_attempt.id == latest_attempt.id)
    if active_attempt and isinstance(active_attempt.answers_json, dict):
        answers = active_attempt.answers_json
    else:
        answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    logs_source = active_attempt.run_logs if active_attempt and hasattr(active_attempt, "run_logs") else submission.run_logs
    logs_by_question = _run_logs_by_question(logs_source if isinstance(logs_source, list) else None)
    grading_by_question = _grading_by_question(active_attempt.grading_json) if active_attempt else {}
    has_code_questions = any((q.get("type") == "code") for q in questions)
    if not grading_by_question and task and questions and has_code_questions and ENABLE_BACKEND_CODE_RUNS:
        try:
            _, _, grading_details = _grade_exam_submission(task, answers)
        except Exception:
            grading_details = []
        grading_by_question = _grading_by_question(grading_details)
    return render_template(
        "projects_review_detail.html",
        submission=submission,
        project=project,
        task=task,
        questions=questions,
        answers=answers,
        logs_by_question=logs_by_question,
        grading_by_question=grading_by_question,
        latest_attempt_id=(active_attempt.id if active_attempt else None),
        review_attempt=review_attempt,
        active_attempt=active_attempt,
        is_latest_attempt=is_latest_attempt,
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
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
    attempt_id = request.form.get("attempt_id")
    reviewer = current_user()
    reviewed_status = None
    if action == "accept":
        reviewed_status = "accepted"
    elif action in ("reject", "need_rework"):
        reviewed_status = "rejected"
    review_attempt = None
    if attempt_id:
        try:
            attempt_id = int(attempt_id)
        except Exception:
            attempt_id = None
    if attempt_id:
        review_attempt = ProjectTaskAttempt.query.filter_by(id=attempt_id, submission_id=submission.id).first()
    if review_attempt:
        now = datetime.now(timezone.utc)
        if reviewed_status:
            review_attempt.status = reviewed_status
        if notes:
            review_attempt.review_notes = notes
        review_attempt.reviewed_by_user_id = reviewer.id if reviewer else None
        review_attempt.reviewed_at = now
        latest_attempt = _latest_task_attempt(submission)
        if latest_attempt and latest_attempt.id == review_attempt.id:
            if reviewed_status:
                submission.status = reviewed_status
            if notes:
                submission.review_notes = notes
            submission.last_activity_at = now
            if reviewed_status == "accepted" and submission.student:
                if _project_completed(submission.project, submission.student):
                    _award_project_points_if_needed(submission.project, submission.student)
        # Clear warnings for this submission since it has been reviewed
        if submission.student and notes:
            _clear_submission_warnings(submission.student, submission)
    elif reviewed_status:
        submission.status = reviewed_status
        if notes:
            submission.review_notes = notes
        _record_task_attempt_review(submission, status=reviewed_status, notes=notes, reviewer=reviewer)
        # Clear warnings for this submission since it has been reviewed
        if submission.student and notes:
            _clear_submission_warnings(submission.student, submission)
    submission.last_activity_at = datetime.now(timezone.utc)
    if submission.status == "accepted" and submission.student:
        if _project_completed(submission.project, submission.student):
            _award_project_points_if_needed(submission.project, submission.student)
    db.session.commit()
    if review_attempt:
        return redirect(url_for("projects_reviews_mine"))
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

@app.post("/grades/<int:grade_id>/update")
@require_user()
def grades_update(grade_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    grade = Grade.query.get_or_404(grade_id)
    score_raw = request.form.get("score") or ""
    max_raw = request.form.get("max_score") or ""
    remarks = (request.form.get("remarks") or "").strip()
    try:
        grade.score = float(score_raw)
        grade.max_score = float(max_raw)
    except Exception:
        session["grades_error"] = "Score and maximum score must be numbers."
        return redirect(url_for("grades_admin"))
    grade.remarks = remarks or None
    db.session.commit()
    session["grades_status"] = f"Updated grade for {grade.student_name}."
    return redirect(url_for("grades_admin"))

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

# --------------------------------------------------------------------
# Warning System / Academic Integrity
# --------------------------------------------------------------------

@app.route("/warnings")
@require_user()
def warnings_list():
    """View all students with warnings or flags."""
    # Get all flagged students
    flagged = Student.query.filter_by(is_flagged=True).order_by(Student.name.asc()).all()
    
    # Get students with warnings but not flagged
    all_students = Student.query.filter(Student.warnings_json != None).order_by(Student.name.asc()).all()
    warned = [s for s in all_students if not s.is_flagged and s.warnings_json and len(s.warnings_json) > 0]
    
    return render_template(
        "warnings_list.html",
        flagged_students=flagged,
        warned_students=warned,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/warnings/student/<int:student_id>")
@require_user()
def warnings_student_detail(student_id):
    """View detailed warnings for a specific student."""
    student = Student.query.get_or_404(student_id)
    warnings = student.warnings_json if isinstance(student.warnings_json, list) else []
    
    # Get student's submissions for context
    exam_submissions = ExamSubmission.query.filter_by(student_id=student.id).order_by(ExamSubmission.submitted_at.desc()).limit(20).all()
    task_submissions = ProjectTaskSubmission.query.filter_by(student_id=student.id).order_by(ProjectTaskSubmission.submitted_at.desc()).limit(20).all()
    
    return render_template(
        "warnings_detail.html",
        student=student,
        warnings=warnings,
        exam_submissions=exam_submissions,
        task_submissions=task_submissions,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/warnings/student/<int:student_id>/flag")
@require_user()
def warnings_flag_student(student_id):
    """Manually flag a student."""
    if not verify_csrf():
        abort(400, "bad csrf")
    
    student = Student.query.get_or_404(student_id)
    notes = (request.form.get("notes") or "").strip()
    
    student.is_flagged = True
    student.flag_notes = notes or "Manually flagged by instructor"
    db.session.commit()
    
    return redirect(url_for("warnings_student_detail", student_id=student.id))

@app.post("/warnings/student/<int:student_id>/unflag")
@require_user()
def warnings_unflag_student(student_id):
    """Remove flag from a student."""
    if not verify_csrf():
        abort(400, "bad csrf")
    
    student = Student.query.get_or_404(student_id)
    student.is_flagged = False
    student.flag_notes = None
    db.session.commit()
    
    return redirect(url_for("warnings_student_detail", student_id=student.id))

@app.post("/warnings/student/<int:student_id>/add")
@require_user()
def warnings_add_manual(student_id):
    """Manually add a warning to a student."""
    if not verify_csrf():
        abort(400, "bad csrf")
    
    student = Student.query.get_or_404(student_id)
    warning_type = (request.form.get("type") or "manual").strip()
    description = (request.form.get("description") or "").strip()
    severity = (request.form.get("severity") or "medium").strip()
    
    if not description:
        abort(400, "Description is required")
    
    _add_warning(student, warning_type, description, severity=severity, auto_detected=False)
    db.session.commit()
    
    return redirect(url_for("warnings_student_detail", student_id=student.id))

@app.post("/warnings/student/<int:student_id>/clear")
@require_user()
def warnings_clear_all(student_id):
    """Clear all warnings for a student."""
    if not verify_csrf():
        abort(400, "bad csrf")
    
    student = Student.query.get_or_404(student_id)
    student.warnings_json = []
    student.is_flagged = False
    student.flag_notes = None
    db.session.commit()
    
    return redirect(url_for("warnings_student_detail", student_id=student.id))

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
# Proficiency Test System
# --------------------------------------------------------------------

def _get_proficiency_config():
    """Get or create the global proficiency test configuration."""
    config = ProficiencyTestConfig.query.first()
    if not config:
        config = ProficiencyTestConfig(
            title="Python Proficiency Test",
            description="Demonstrate your Python skills to unlock advanced projects.",
            exercise_count=3,
            duration_minutes=60,
            cooldown_hours=48,
            is_active=True,
        )
        db.session.add(config)
        db.session.commit()
    return config

def _student_can_start_proficiency_test(student):
    """Check if student can start a new proficiency test."""
    # Already passed?
    has_tag = StudentProficiencyTag.query.filter_by(student_id=student.id, tag_name="python").first()
    if has_tag:
        return False, "already_passed"
    
    # Has an in-progress test?
    in_progress = ProficiencyTestAttempt.query.filter_by(
        student_id=student.id, status="in_progress"
    ).first()
    if in_progress:
        if not in_progress.is_expired:
            return False, "in_progress"
        # Auto-submit expired test
        in_progress.status = "submitted"
        in_progress.submitted_at = datetime.now(timezone.utc)
        db.session.commit()
    
    # Has a pending review?
    pending = ProficiencyTestAttempt.query.filter_by(
        student_id=student.id, status="submitted"
    ).first()
    if pending:
        return False, "pending_review"
    
    # Check cooldown from last failed attempt
    config = _get_proficiency_config()
    last_failed = ProficiencyTestAttempt.query.filter_by(
        student_id=student.id, status="failed"
    ).order_by(ProficiencyTestAttempt.reviewed_at.desc()).first()
    
    if last_failed and last_failed.reviewed_at:
        cooldown_end = last_failed.reviewed_at + timedelta(hours=config.cooldown_hours)
        if datetime.now(timezone.utc) < cooldown_end:
            return False, "cooldown"
    
    return True, "ok"

def _run_proficiency_tests(code_text, test_cases, time_limit=3.0):
    """Run test cases against student code. Returns (visible_results, hidden_results)."""
    visible_tests = []
    hidden_tests = []
    
    for tc in test_cases.get("visible", []):
        visible_tests.append({
            "name": tc.get("description", "Test"),
            "call": tc.get("input", ""),
            "expected": tc.get("expected_output", ""),
            "hidden": False,
        })
    
    for tc in test_cases.get("hidden", []):
        hidden_tests.append({
            "name": tc.get("description", "Hidden test"),
            "call": tc.get("input", ""),
            "expected": tc.get("expected_output", ""),
            "hidden": True,
        })
    
    all_tests = visible_tests + hidden_tests
    if not all_tests:
        return [], []
    
    results, timed_out = _run_code_tests_backend(code_text, all_tests, "function")
    visible_results = [r for r in results if not r.get("hidden")]
    hidden_results = [r for r in results if r.get("hidden")]
    
    return visible_results, hidden_results

# --- Admin/Mentor: Manage Exercises ---

@app.route("/proficiency/exercises")
@require_user()
def proficiency_exercises_list():
    """List all proficiency exercises."""
    user = current_user()
    exercises = ProficiencyExercise.query.order_by(ProficiencyExercise.created_at.desc()).all()
    config = _get_proficiency_config()
    return render_template("proficiency_exercises_list.html", 
                           user=user, exercises=exercises, config=config)

@app.route("/proficiency/exercises/new", methods=["GET", "POST"])
@require_user()
def proficiency_exercises_new():
    """Create a new proficiency exercise."""
    user = current_user()
    
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        instructions = (request.form.get("instructions") or "").strip()
        starter_code = (request.form.get("starter_code") or "").strip()
        time_limit = float(request.form.get("time_limit") or 3.0)
        
        # Parse test cases
        visible_tests = []
        hidden_tests = []
        
        # Visible tests
        visible_inputs = request.form.getlist("visible_input[]")
        visible_outputs = request.form.getlist("visible_output[]")
        visible_descs = request.form.getlist("visible_desc[]")
        for i, inp in enumerate(visible_inputs):
            if inp.strip() or (i < len(visible_outputs) and visible_outputs[i].strip()):
                visible_tests.append({
                    "input": inp,
                    "expected_output": visible_outputs[i] if i < len(visible_outputs) else "",
                    "description": visible_descs[i] if i < len(visible_descs) else f"Test {i+1}",
                })
        
        # Hidden tests
        hidden_inputs = request.form.getlist("hidden_input[]")
        hidden_outputs = request.form.getlist("hidden_output[]")
        hidden_descs = request.form.getlist("hidden_desc[]")
        for i, inp in enumerate(hidden_inputs):
            if inp.strip() or (i < len(hidden_outputs) and hidden_outputs[i].strip()):
                hidden_tests.append({
                    "input": inp,
                    "expected_output": hidden_outputs[i] if i < len(hidden_outputs) else "",
                    "description": hidden_descs[i] if i < len(hidden_descs) else f"Hidden test {i+1}",
                })
        
        if not title:
            return render_template("proficiency_exercise_form.html", 
                                   user=user, error="Title is required", exercise=None)
        
        exercise = ProficiencyExercise(
            title=title,
            description=description,
            instructions=instructions,
            starter_code=starter_code,
            test_cases_json={"visible": visible_tests, "hidden": hidden_tests},
            time_limit_sec=time_limit,
            is_active=True,
            created_by_user_id=user.id,
        )
        db.session.add(exercise)
        db.session.commit()
        
        return redirect(url_for("proficiency_exercises_list"))
    
    return render_template("proficiency_exercise_form.html", user=user, exercise=None)

@app.route("/proficiency/exercises/<int:exercise_id>/edit", methods=["GET", "POST"])
@require_user()
def proficiency_exercises_edit(exercise_id):
    """Edit an existing proficiency exercise."""
    user = current_user()
    exercise = ProficiencyExercise.query.get_or_404(exercise_id)
    
    if request.method == "POST":
        exercise.title = (request.form.get("title") or "").strip()
        exercise.description = (request.form.get("description") or "").strip()
        exercise.instructions = (request.form.get("instructions") or "").strip()
        exercise.starter_code = (request.form.get("starter_code") or "").strip()
        exercise.time_limit_sec = float(request.form.get("time_limit") or 3.0)
        exercise.is_active = request.form.get("is_active") == "1"
        
        # Parse test cases
        visible_tests = []
        hidden_tests = []
        
        visible_inputs = request.form.getlist("visible_input[]")
        visible_outputs = request.form.getlist("visible_output[]")
        visible_descs = request.form.getlist("visible_desc[]")
        for i, inp in enumerate(visible_inputs):
            if inp.strip() or (i < len(visible_outputs) and visible_outputs[i].strip()):
                visible_tests.append({
                    "input": inp,
                    "expected_output": visible_outputs[i] if i < len(visible_outputs) else "",
                    "description": visible_descs[i] if i < len(visible_descs) else f"Test {i+1}",
                })
        
        hidden_inputs = request.form.getlist("hidden_input[]")
        hidden_outputs = request.form.getlist("hidden_output[]")
        hidden_descs = request.form.getlist("hidden_desc[]")
        for i, inp in enumerate(hidden_inputs):
            if inp.strip() or (i < len(hidden_outputs) and hidden_outputs[i].strip()):
                hidden_tests.append({
                    "input": inp,
                    "expected_output": hidden_outputs[i] if i < len(hidden_outputs) else "",
                    "description": hidden_descs[i] if i < len(hidden_descs) else f"Hidden test {i+1}",
                })
        
        exercise.test_cases_json = {"visible": visible_tests, "hidden": hidden_tests}
        
        if not exercise.title:
            return render_template("proficiency_exercise_form.html", 
                                   user=user, error="Title is required", exercise=exercise)
        
        db.session.commit()
        return redirect(url_for("proficiency_exercises_list"))
    
    return render_template("proficiency_exercise_form.html", user=user, exercise=exercise)

@app.route("/proficiency/exercises/<int:exercise_id>/delete", methods=["POST"])
@require_user()
def proficiency_exercises_delete(exercise_id):
    """Delete a proficiency exercise."""
    exercise = ProficiencyExercise.query.get_or_404(exercise_id)
    db.session.delete(exercise)
    db.session.commit()
    return redirect(url_for("proficiency_exercises_list"))

@app.route("/proficiency/config", methods=["GET", "POST"])
@require_user()
def proficiency_config():
    """Configure proficiency test settings."""
    user = current_user()
    config = _get_proficiency_config()
    
    if request.method == "POST":
        config.title = (request.form.get("title") or "").strip() or "Python Proficiency Test"
        config.description = (request.form.get("description") or "").strip()
        config.exercise_count = int(request.form.get("exercise_count") or 3)
        config.duration_minutes = int(request.form.get("duration_minutes") or 60)
        config.cooldown_hours = int(request.form.get("cooldown_hours") or 48)
        config.is_active = request.form.get("is_active") == "1"
        db.session.commit()
        return redirect(url_for("proficiency_exercises_list"))
    
    return render_template("proficiency_config.html", user=user, config=config)

# --- Admin/Mentor: Review Submissions ---

@app.route("/proficiency/reviews")
@require_user()
def proficiency_reviews():
    """List all proficiency test submissions pending review."""
    user = current_user()
    pending = ProficiencyTestAttempt.query.filter_by(status="submitted").order_by(
        ProficiencyTestAttempt.submitted_at.asc()
    ).all()
    reviewed = ProficiencyTestAttempt.query.filter(
        ProficiencyTestAttempt.status.in_(["passed", "failed"])
    ).order_by(ProficiencyTestAttempt.reviewed_at.desc()).limit(50).all()
    
    return render_template("proficiency_reviews_list.html", 
                           user=user, pending=pending, reviewed=reviewed)

@app.route("/proficiency/reviews/<int:attempt_id>", methods=["GET", "POST"])
@require_user()
def proficiency_review_detail(attempt_id):
    """Review a specific proficiency test attempt."""
    user = current_user()
    attempt = ProficiencyTestAttempt.query.get_or_404(attempt_id)
    
    if request.method == "POST":
        action = request.form.get("action")
        if action == "pass":
            attempt.status = "passed"
            attempt.reviewed_at = datetime.now(timezone.utc)
            attempt.reviewed_by_user_id = user.id
            
            # Award proficiency tag
            existing_tag = StudentProficiencyTag.query.filter_by(
                student_id=attempt.student_id, tag_name="python"
            ).first()
            if not existing_tag:
                tag = StudentProficiencyTag(
                    student_id=attempt.student_id,
                    tag_name="python",
                    attempt_id=attempt.id,
                    awarded_by_user_id=user.id,
                )
                db.session.add(tag)
            
            db.session.commit()
        elif action == "fail":
            attempt.status = "failed"
            attempt.reviewed_at = datetime.now(timezone.utc)
            attempt.reviewed_by_user_id = user.id
            db.session.commit()
        
        return redirect(url_for("proficiency_reviews"))
    
    return render_template("proficiency_review_detail.html", user=user, attempt=attempt)

@app.route("/proficiency/reviews/<int:attempt_id>/change-status", methods=["POST"])
@require_user()
def proficiency_change_status(attempt_id):
    """Change the status of an already-reviewed proficiency test attempt."""
    user = current_user()
    attempt = ProficiencyTestAttempt.query.get_or_404(attempt_id)
    
    # Only allow changing status for already-reviewed attempts
    if attempt.status not in ["passed", "failed"]:
        abort(400, "Can only change status of reviewed attempts")
    
    new_status = request.form.get("new_status")
    if new_status not in ["passed", "failed"]:
        abort(400, "Invalid status")
    
    old_status = attempt.status
    attempt.status = new_status
    attempt.reviewed_at = datetime.now(timezone.utc)
    attempt.reviewed_by_user_id = user.id
    
    # Handle proficiency tag based on new status
    if new_status == "passed":
        # Award proficiency tag if not already present
        existing_tag = StudentProficiencyTag.query.filter_by(
            student_id=attempt.student_id, tag_name="python"
        ).first()
        if not existing_tag:
            tag = StudentProficiencyTag(
                student_id=attempt.student_id,
                tag_name="python",
                attempt_id=attempt.id,
                awarded_by_user_id=user.id,
            )
            db.session.add(tag)
    elif new_status == "failed" and old_status == "passed":
        # Remove proficiency tag if changing from passed to failed
        # Only remove if this attempt was the one that awarded the tag
        tag = StudentProficiencyTag.query.filter_by(
            student_id=attempt.student_id, 
            tag_name="python",
            attempt_id=attempt.id
        ).first()
        if tag:
            db.session.delete(tag)
    
    db.session.commit()
    
    return redirect(url_for("proficiency_reviews"))

# --- Student: Take Proficiency Test ---

@app.route("/student/proficiency")
@require_student()
def student_proficiency():
    """Student proficiency test hub."""
    student = current_student()
    config = _get_proficiency_config()
    
    # Check student status
    has_tag = StudentProficiencyTag.query.filter_by(student_id=student.id, tag_name="python").first()
    
    # Check for in-progress test
    in_progress = ProficiencyTestAttempt.query.filter_by(
        student_id=student.id, status="in_progress"
    ).first()
    
    if in_progress and in_progress.is_expired:
        # Auto-submit expired test
        in_progress.status = "submitted"
        in_progress.submitted_at = datetime.now(timezone.utc)
        # Run hidden tests on submission
        for sub in in_progress.submissions:
            if sub.exercise:
                test_cases = sub.exercise_test_cases_json or {}
                visible_results, hidden_results = _run_proficiency_tests(
                    sub.code or "", test_cases, sub.exercise.time_limit_sec
                )
                sub.visible_results_json = visible_results
                sub.hidden_results_json = hidden_results
                sub.visible_passed = sum(1 for r in visible_results if r.get("status") == "passed")
                sub.visible_total = len(visible_results)
                sub.hidden_passed = sum(1 for r in hidden_results if r.get("status") == "passed")
                sub.hidden_total = len(hidden_results)
        db.session.commit()
        in_progress = None
    
    pending = ProficiencyTestAttempt.query.filter_by(
        student_id=student.id, status="submitted"
    ).first()
    
    # Get past attempts
    past_attempts = ProficiencyTestAttempt.query.filter(
        ProficiencyTestAttempt.student_id == student.id,
        ProficiencyTestAttempt.status.in_(["passed", "failed"])
    ).order_by(ProficiencyTestAttempt.reviewed_at.desc()).all()
    
    can_start, reason = _student_can_start_proficiency_test(student)
    
    # Calculate cooldown remaining
    cooldown_remaining = None
    if reason == "cooldown":
        last_failed = ProficiencyTestAttempt.query.filter_by(
            student_id=student.id, status="failed"
        ).order_by(ProficiencyTestAttempt.reviewed_at.desc()).first()
        if last_failed and last_failed.reviewed_at:
            cooldown_end = last_failed.reviewed_at + timedelta(hours=config.cooldown_hours)
            cooldown_remaining = cooldown_end - datetime.now(timezone.utc)
    
    exercise_count = ProficiencyExercise.query.filter_by(is_active=True).count()
    
    return render_template("proficiency_student.html",
                           student=student,
                           student_name=session.get("student_name"),
                           config=config,
                           has_tag=has_tag,
                           in_progress=in_progress,
                           pending=pending,
                           past_attempts=past_attempts,
                           can_start=can_start,
                           reason=reason,
                           cooldown_remaining=cooldown_remaining,
                           exercise_count=exercise_count)

@app.route("/student/proficiency/start", methods=["POST"])
@require_student()
def student_proficiency_start():
    """Start a new proficiency test."""
    student = current_student()
    config = _get_proficiency_config()
    
    if not config.is_active:
        abort(403, "Proficiency tests are currently disabled.")
    
    can_start, reason = _student_can_start_proficiency_test(student)
    if not can_start:
        return redirect(url_for("student_proficiency"))
    
    # Get random exercises
    exercises = ProficiencyExercise.query.filter_by(is_active=True).all()
    if len(exercises) < config.exercise_count:
        abort(400, f"Not enough exercises in pool. Need {config.exercise_count}, have {len(exercises)}.")
    
    selected = random.sample(exercises, config.exercise_count)
    
    # Create attempt
    attempt = ProficiencyTestAttempt(
        student_id=student.id,
        duration_minutes=config.duration_minutes,
        status="in_progress",
        ip_address=(request.remote_addr or "")[:64],
    )
    db.session.add(attempt)
    db.session.flush()
    
    # Create submissions for each exercise
    for idx, exercise in enumerate(selected):
        sub = ProficiencyExerciseSubmission(
            attempt_id=attempt.id,
            exercise_id=exercise.id,
            exercise_title=exercise.title,
            exercise_description=exercise.description,
            exercise_instructions=exercise.instructions,
            exercise_starter_code=exercise.starter_code,
            exercise_test_cases_json=exercise.test_cases_json,
            code=exercise.starter_code or "",
            order_index=idx,
        )
        db.session.add(sub)
    
    db.session.commit()
    
    return redirect(url_for("student_proficiency_take", attempt_id=attempt.id))

@app.route("/student/proficiency/test/<int:attempt_id>", methods=["GET", "POST"])
@require_student()
def student_proficiency_take(attempt_id):
    """Take a proficiency test."""
    student = current_student()
    attempt = ProficiencyTestAttempt.query.get_or_404(attempt_id)
    
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status != "in_progress":
        return redirect(url_for("student_proficiency"))
    
    # Check if expired
    if attempt.is_expired:
        attempt.status = "submitted"
        attempt.submitted_at = datetime.now(timezone.utc)
        # Run all tests on submission
        for sub in attempt.submissions:
            test_cases = sub.exercise_test_cases_json or {}
            visible_results, hidden_results = _run_proficiency_tests(
                sub.code or "", test_cases
            )
            sub.visible_results_json = visible_results
            sub.hidden_results_json = hidden_results
            sub.visible_passed = sum(1 for r in visible_results if r.get("status") == "passed")
            sub.visible_total = len(visible_results)
            sub.hidden_passed = sum(1 for r in hidden_results if r.get("status") == "passed")
            sub.hidden_total = len(hidden_results)
        db.session.commit()
        return redirect(url_for("student_proficiency"))
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "save":
            # Save code for each exercise
            for sub in attempt.submissions:
                code_key = f"code_{sub.id}"
                if code_key in request.form:
                    sub.code = request.form.get(code_key) or ""
            db.session.commit()
            return redirect(url_for("student_proficiency_take", attempt_id=attempt_id))
        
        elif action == "submit":
            # Save and submit
            for sub in attempt.submissions:
                code_key = f"code_{sub.id}"
                if code_key in request.form:
                    sub.code = request.form.get(code_key) or ""
                
                # Run all tests
                test_cases = sub.exercise_test_cases_json or {}
                visible_results, hidden_results = _run_proficiency_tests(
                    sub.code or "", test_cases
                )
                sub.visible_results_json = visible_results
                sub.hidden_results_json = hidden_results
                sub.visible_passed = sum(1 for r in visible_results if r.get("status") == "passed")
                sub.visible_total = len(visible_results)
                sub.hidden_passed = sum(1 for r in hidden_results if r.get("status") == "passed")
                sub.hidden_total = len(hidden_results)
            
            attempt.status = "submitted"
            attempt.submitted_at = datetime.now(timezone.utc)
            db.session.commit()
            return redirect(url_for("student_proficiency"))
    
    deadline = attempt.started_at + timedelta(minutes=attempt.duration_minutes)
    
    return render_template("proficiency_take.html",
                           student=student,
                           student_name=session.get("student_name"),
                           attempt=attempt,
                           deadline=deadline)

@app.route("/api/proficiency/test/<int:attempt_id>/run", methods=["POST"])
@require_student()
def api_proficiency_run_tests(attempt_id):
    """Run visible tests for an exercise during the test."""
    if not ENABLE_BACKEND_CODE_RUNS:
        return jsonify({"ok": False, "error": "Backend code runs are disabled."}), 503
    
    student = current_student()
    attempt = ProficiencyTestAttempt.query.get_or_404(attempt_id)
    
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status != "in_progress" or attempt.is_expired:
        return jsonify({"ok": False, "error": "Test is no longer active."}), 400
    
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    
    data = request.get_json(silent=True) or {}
    submission_id = data.get("submission_id")
    code_text = data.get("code") or ""
    
    sub = db.session.get(ProficiencyExerciseSubmission, submission_id)
    if not sub or sub.attempt_id != attempt_id:
        return jsonify({"ok": False, "error": "Invalid submission."}), 400
    
    # Save current code
    sub.code = code_text
    
    # Run only visible tests
    test_cases = sub.exercise_test_cases_json or {}
    visible_only = {"visible": test_cases.get("visible", []), "hidden": []}
    visible_results, _ = _run_proficiency_tests(code_text, visible_only)
    
    # Log the run
    logs = sub.run_logs if isinstance(sub.run_logs, list) else []
    logs.append({
        "ts": datetime.now(timezone.utc).isoformat() + "Z",
        "results": visible_results,
    })
    sub.run_logs = logs
    db.session.commit()
    
    return jsonify({
        "ok": True,
        "results": visible_results,
        "passed": sum(1 for r in visible_results if r.get("status") == "passed"),
        "total": len(visible_results),
    })

@app.route("/api/proficiency/test/<int:attempt_id>/save", methods=["POST"])
@require_student()
def api_proficiency_save_code(attempt_id):
    """Auto-save code during the test."""
    student = current_student()
    attempt = ProficiencyTestAttempt.query.get_or_404(attempt_id)
    
    if attempt.student_id != student.id:
        abort(403)
    
    if attempt.status != "in_progress":
        return jsonify({"ok": False, "error": "Test is no longer active."}), 400
    
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    
    data = request.get_json(silent=True) or {}
    submission_id = data.get("submission_id")
    code_text = data.get("code") or ""
    
    sub = db.session.get(ProficiencyExerciseSubmission, submission_id)
    if not sub or sub.attempt_id != attempt_id:
        return jsonify({"ok": False, "error": "Invalid submission."}), 400
    
    sub.code = code_text
    db.session.commit()
    
    return jsonify({"ok": True})

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
