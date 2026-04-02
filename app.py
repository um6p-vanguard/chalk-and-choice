import os, io, base64, secrets, argparse, csv, random, functools, time, json, hmac, hashlib, traceback, builtins, sys, multiprocessing, re, ast, uuid, importlib, signal, struct, tempfile, shutil, zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, make_response, jsonify, abort, Response, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound
from itsdangerous import URLSafeSerializer
from markupsafe import Markup, escape
try:
    import markdown as markdown_lib
except Exception:
    markdown_lib = None
try:
    import bleach
except Exception:
    bleach = None

from models import (db, Student, User, Form,
                    FormResponse,
                    StudentStats, Intervention, Exam, ExamSubmission, Grade,
                    Project, ProjectTask, ProjectTaskSubmission, ProjectTaskAttempt, ProjectDependency, JudgeJob,
                    StudentGroup, StudentGroupMembership, StudentGroupReviewer, StudentPrivateNote, ProjectGroupAssignment,
                    AttendanceSheet, AttendanceEntry, StudentLogSession,
                    Announcement, AnnouncementDelivery,
                    BlogPost, BlogComment, Leaderboard)
import qrcode
from sqlalchemy import func, inspect, text
from sqlalchemy.orm import subqueryload

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

def _grades_search_filters_from_request(values):
    return {
        "student_query": (values.get("student_query") or "").strip(),
        "assignment_query": (values.get("assignment_query") or "").strip(),
    }

def _grades_admin_url(filters=None):
    filters = filters or {}
    params = {}
    if filters.get("student_query"):
        params["student_query"] = filters["student_query"]
    if filters.get("assignment_query"):
        params["assignment_query"] = filters["assignment_query"]
    return url_for("grades_admin", **params)

def _grades_query(filters=None):
    filters = filters or {}
    student_query = (filters.get("student_query") or "").strip().lower()
    assignment_query = (filters.get("assignment_query") or "").strip().lower()
    query = Grade.query.options(subqueryload(Grade.student))
    if student_query:
        pattern = f"%{student_query}%"
        query = query.outerjoin(Student, Student.id == Grade.student_id).filter(
            db.or_(
                func.lower(Grade.student_name).like(pattern),
                func.lower(Student.email).like(pattern),
            )
        )
    if assignment_query:
        query = query.filter(func.lower(Grade.assignment).like(f"%{assignment_query}%"))
    return query.order_by(Grade.created_at.desc())

def _serialize_grade_export_row(grade):
    return {
        "id": grade.id,
        "student_name": grade.student_name,
        "student_email": (grade.student.email if grade.student else ""),
        "assignment": grade.assignment,
        "score": grade.score,
        "max_score": grade.max_score,
        "remarks": grade.remarks or "",
        "created_at": (grade.created_at.isoformat() if grade.created_at else ""),
        "updated_at": (grade.updated_at.isoformat() if grade.updated_at else ""),
    }

def _iso_or_none(value):
    return value.isoformat() if value else None

def _export_code_expected(value):
    text = _coerce_string(value).strip()
    if not text:
        return ""
    try:
        return ast.literal_eval(text)
    except Exception:
        return text

def _serialize_project_task_resource_export(resource_file):
    info = _extract_file_info(resource_file)
    if not info:
        return None
    payload = {
        "original_name": info.get("original_name") or info.get("stored_name") or "resource",
        "included_in_export": False,
    }
    if info.get("size") is not None:
        payload["size"] = info.get("size")
    content_type = _coerce_string(info.get("content_type")).strip()
    if content_type:
        payload["content_type"] = content_type
    uploaded_at = _coerce_string(info.get("uploaded_at")).strip()
    if uploaded_at:
        payload["uploaded_at"] = uploaded_at
    return payload

def _serialize_project_task_judge_bundle_export(judge_bundle_file):
    info = _extract_file_info(judge_bundle_file)
    if not info:
        return None
    payload = {
        "original_name": info.get("original_name") or info.get("stored_name") or "judge_bundle.zip",
        "included_in_export": False,
    }
    if info.get("size") is not None:
        payload["size"] = info.get("size")
    content_type = _coerce_string(info.get("content_type")).strip()
    if content_type:
        payload["content_type"] = content_type
    uploaded_at = _coerce_string(info.get("uploaded_at")).strip()
    if uploaded_at:
        payload["uploaded_at"] = uploaded_at
    return payload

def _serialize_project_question_export(question):
    if not isinstance(question, dict):
        return {}
    try:
        points = max(0, int(question.get("points") or 1))
    except Exception:
        points = 1
    payload = {
        "id": _coerce_string(question.get("id")).strip(),
        "type": _normalize_question_type_name(question.get("type")),
        "prompt": _coerce_string(question.get("prompt")).strip(),
        "points": points,
    }
    title = _coerce_string(question.get("title")).strip()
    if title:
        payload["title"] = title
    code_snippet = _coerce_string(question.get("code_snippet")).strip("\n")
    if code_snippet:
        payload["code_snippet"] = code_snippet

    q_type = payload["type"]
    if q_type in ("mcq", "multi"):
        correct_indices = {
            idx for idx in _coerce_int_list(question.get("correct_indices"))
            if idx >= 0
        }
        choices = []
        for idx, option in enumerate(question.get("options") or []):
            choice = {"text": _coerce_string(option)}
            if idx in correct_indices:
                choice["is_correct"] = True
            choices.append(choice)
        payload["choices"] = choices
        payload["shuffle"] = bool(question.get("shuffle"))
    elif q_type == "text":
        payload["placeholder"] = _coerce_string(question.get("placeholder")).strip()
        try:
            payload["lines"] = max(1, int(question.get("lines") or 4))
        except Exception:
            payload["lines"] = 4
    elif q_type == "tokens":
        payload["template"] = _coerce_string(question.get("template"))
        payload["correct_tokens"] = _coerce_token_list(question.get("correct_tokens"))
        payload["distractor_tokens"] = _coerce_token_list(question.get("distractor_tokens"))
    elif q_type == "fill":
        payload["template"] = _coerce_string(question.get("template"))
        payload["answers"] = _coerce_token_list(question.get("answers"))
        payload["case_sensitive"] = bool(question.get("case_sensitive"))
    elif q_type == "file":
        payload["accept"] = _coerce_string(question.get("accept")).strip() or UPLOAD_DEFAULT_ACCEPT
        try:
            payload["max_mb"] = max(1, int(question.get("max_mb") or UPLOAD_MAX_MB))
        except Exception:
            payload["max_mb"] = UPLOAD_MAX_MB
    elif q_type == "plot":
        payload["problem_statement"] = _coerce_string(question.get("statement")).strip()
        starter_code = _coerce_string(question.get("starter"))
        if starter_code:
            payload["starter_code"] = starter_code
    elif q_type == "code":
        payload["problem_statement"] = _coerce_string(question.get("statement")).strip()
        starter_code = _coerce_string(question.get("starter"))
        if starter_code:
            payload["starter_code"] = starter_code
        mode = _normalize_code_mode_name(question.get("mode") or "script")
        payload["code_mode"] = mode
        if mode == "function":
            payload["function_signature"] = _coerce_string(question.get("function_signature")).strip()
        elif mode == "class":
            payload["class_signature"] = _coerce_string(question.get("class_signature")).strip()
            payload["class_init"] = _coerce_string(question.get("class_init")).strip()
        tests = []
        class_init = _coerce_string(question.get("class_init")).strip()
        for sample in question.get("samples") or []:
            if not isinstance(sample, dict):
                continue
            name = _coerce_string(sample.get("name")).strip()
            compare_mode = _coerce_string(sample.get("compare_mode")).strip()
            hidden = bool(sample.get("hidden"))
            if mode == "script":
                item = {
                    "name": name or "Sample",
                    "stdin": _coerce_string(sample.get("input")),
                    "expected_stdout": _coerce_string(sample.get("output")),
                }
            elif mode == "function":
                item = {
                    "name": name or "Sample",
                    "function_call": _coerce_string(sample.get("call") or sample.get("input")).strip(),
                    "expected_return": _export_code_expected(sample.get("expected")),
                }
            else:
                item = {
                    "name": name or "Method test",
                    "method_call": _coerce_string(sample.get("call") or sample.get("input")).strip(),
                    "expected_return": _export_code_expected(sample.get("expected")),
                }
                sample_init = _coerce_string(sample.get("init_call")).strip()
                if sample_init and sample_init != class_init:
                    item["init_call"] = sample_init
            if compare_mode:
                item["compare_mode"] = compare_mode
            if hidden:
                item["hidden"] = True
            if sample.get("tolerance") is not None:
                try:
                    item["tolerance"] = float(sample.get("tolerance"))
                except Exception:
                    item["tolerance"] = sample.get("tolerance")
            tests.append(item)
        payload["tests"] = tests
        hidden_tests = []
        for sample in question.get("hidden_tests") or []:
            if not isinstance(sample, dict):
                continue
            item = {
                "name": _coerce_string(sample.get("name")).strip() or "Hidden test",
            }
            compare_mode = _coerce_string(sample.get("compare_mode")).strip()
            if compare_mode:
                item["compare_mode"] = compare_mode
            if sample.get("timeout_ms") is not None:
                item["timeout_ms"] = sample.get("timeout_ms")
            if sample.get("tolerance") is not None:
                item["tolerance"] = sample.get("tolerance")
            if sample.get("files"):
                item["files"] = sample.get("files")
            if sample.get("stdin_file"):
                item["stdin_file"] = sample.get("stdin_file")
            if sample.get("expected_file"):
                item["expected_file"] = sample.get("expected_file")
            if mode == "script":
                if sample.get("input"):
                    item["stdin"] = sample.get("input")
                if sample.get("output"):
                    item["expected_stdout"] = sample.get("output")
            elif mode == "function":
                item["function_call"] = _coerce_string(sample.get("call") or sample.get("input")).strip()
                if sample.get("expected") not in (None, ""):
                    item["expected_return"] = _export_code_expected(sample.get("expected"))
            else:
                item["method_call"] = _coerce_string(sample.get("call") or sample.get("input")).strip()
                if sample.get("expected") not in (None, ""):
                    item["expected_return"] = _export_code_expected(sample.get("expected"))
                sample_init = _coerce_string(sample.get("init_call")).strip()
                if sample_init and sample_init != class_init:
                    item["init_call"] = sample_init
            hidden_tests.append(item)
        if hidden_tests:
            payload["hidden_tests"] = hidden_tests
    return payload

def _serialize_project_task_export(task):
    payload = {
        "task_kind": _task_kind_value(task),
        "title": task.title,
        "description": task.description,
        "instructions": task.instructions,
        "required": bool(task.required),
        "auto_grade": bool(task.auto_grade),
        "requires_review": bool(task.requires_review),
        "questions": [
            _serialize_project_question_export(question)
            for question in (task.questions_json or [])
            if isinstance(question, dict)
        ],
    }
    resource_file = _serialize_project_task_resource_export(task.resource_file)
    if resource_file:
        payload["resource_file"] = resource_file
    judge_bundle_file = _serialize_project_task_judge_bundle_export(task.judge_bundle_file)
    if judge_bundle_file:
        payload["judge_bundle_file"] = judge_bundle_file
    return payload

def _project_task_download_basename(project, task):
    project_code = secure_filename((project.code if project else "") or "project") or "project"
    task_slug = secure_filename((task.title if task else "") or "") or f"task_{getattr(task, 'id', 'item')}"
    return f"{project_code}_{task_slug}"

def _project_task_tutorial_markdown(project, task):
    lines = [f"# {task.title}", ""]
    if project:
        lines.extend([
            f"- Project: {project.title}",
            f"- Project code: `{project.code}`",
            "",
        ])
    if task.description:
        lines.extend([task.description.strip(), ""])
    body = _coerce_string(task.instructions).strip()
    if body:
        lines.extend([body, ""])
    if isinstance(task.resource_file, dict):
        resource_name = (
            task.resource_file.get("original_name")
            or task.resource_file.get("stored_name")
            or "resource"
        )
        lines.extend([
            "## Attached resource",
            "",
            f"- {resource_name}",
            "",
        ])
    text = "\n".join(lines).strip()
    return text + "\n"

def _serialize_project_export(project, tasks=None, dependencies=None, group_assignments=None):
    project_payload = {
        "code": project.code,
        "title": project.title,
        "collection": project.collection,
        "description": project.description,
        "instructions": project.instructions,
        "deadline_at": _iso_or_none(project.deadline_at),
        "required_task_count": project.required_task_count,
        "is_active": bool(project.is_active),
        "points": project.points,
        "retry_cooldown_minutes": project.retry_cooldown_minutes,
        "created_at": _iso_or_none(project.created_at),
    }
    project_payload["dependencies"] = [
        {
            "code": dep.prerequisite.code if dep.prerequisite else None,
            "title": dep.prerequisite.title if dep.prerequisite else None,
        }
        for dep in (dependencies or [])
    ]
    project_payload["group_assignments"] = [
        {
            "scope": "all" if assignment.applies_to_all else "group",
            "group_id": assignment.group_id,
            "group_name": assignment.group.name if assignment.group else None,
            "is_required": bool(assignment.is_required),
            "created_at": _iso_or_none(assignment.created_at),
        }
        for assignment in (group_assignments or [])
    ]
    return {
        "schema_name": "project_export",
        "schema_version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "task_import_schema": {
            "name": PROJECT_TASKS_SCHEMA.get("schema_name"),
            "version": PROJECT_TASKS_SCHEMA.get("schema_version"),
        },
        "project": project_payload,
        "tasks": [_serialize_project_task_export(task) for task in (tasks or [])],
    }

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
JUDGE_BUNDLE_MAX_MB = 25
JUDGE_BUNDLE_MAX_BYTES = JUDGE_BUNDLE_MAX_MB * 1024 * 1024
JUDGE_BUNDLE_MAX_EXTRACT_MB = 100
JUDGE_BUNDLE_MAX_EXTRACT_BYTES = JUDGE_BUNDLE_MAX_EXTRACT_MB * 1024 * 1024
PLOT_ARTIFACT_MAX_MB = 3
PLOT_ARTIFACT_MAX_BYTES = PLOT_ARTIFACT_MAX_MB * 1024 * 1024
PLOT_ARTIFACT_MAX_WIDTH = 1600
PLOT_ARTIFACT_MAX_HEIGHT = 1200
PLOT_ARTIFACT_MAX_PIXELS = 2_000_000
PLOT_EXPORT_MAX_WIDTH_IN = 10.0
PLOT_EXPORT_MAX_HEIGHT_IN = 7.5
PLOT_EXPORT_DPI = 120
LOG_SESSION_GAP_SEC = 10 * 60
LOG_ACTIVITY_UPDATE_SEC = 60
JUDGE_WORKER_POLL_SEC = 2.0

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

QUESTION_TYPE_ALIASES = {
    "mcq": "mcq",
    "single_choice": "mcq",
    "single_select": "mcq",
    "multiple_choice": "mcq",
    "radio": "mcq",
    "multi": "multi",
    "multi_select": "multi",
    "multiple_select": "multi",
    "checkbox": "multi",
    "checkboxes": "multi",
    "text": "text",
    "free_text": "text",
    "long_text": "text",
    "open_text": "text",
    "code": "code",
    "coding": "code",
    "python_code": "code",
    "programming": "code",
    "plot": "plot",
    "plotting": "plot",
    "matplotlib": "plot",
    "python_plot": "plot",
    "tokens": "tokens",
    "token_fill": "tokens",
    "drag_tokens": "tokens",
    "fill": "fill",
    "fill_blank": "fill",
    "fill_in_blank": "fill",
    "file": "file",
    "upload": "file",
    "file_upload": "file",
}

TASK_KIND_ALIASES = {
    "assessment": "assessment",
    "task": "assessment",
    "exercise": "assessment",
    "practice": "assessment",
    "quiz": "assessment",
    "tutorial": "tutorial",
    "lesson": "tutorial",
    "reading": "tutorial",
    "read_only": "tutorial",
    "content": "tutorial",
    "guide": "tutorial",
}

CODE_MODE_ALIASES = {
    "script": "script",
    "stdin": "script",
    "program": "script",
    "program_io": "script",
    "standard_input": "script",
    "function": "function",
    "callable": "function",
    "call_return": "function",
    "class": "class",
    "object": "class",
    "method": "class",
    "object_method": "class",
}

def _first_present(mapping, *keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key in mapping and mapping.get(key) is not None:
            return mapping.get(key)
    return None

def _coerce_bool(value, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("1", "true", "yes", "y", "on"):
            return True
        if token in ("0", "false", "no", "n", "off"):
            return False
    return bool(value)

def _coerce_string(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)

def _coerce_token_list(value):
    if isinstance(value, str):
        return [tok.strip() for tok in value.replace("\n", ",").split(",") if tok.strip()]
    if isinstance(value, list):
        return [str(tok).strip() for tok in value if str(tok).strip()]
    return []

def _coerce_int_list(value):
    items = []
    if isinstance(value, str):
        tokens = [tok.strip() for tok in value.replace(";", ",").replace("\n", ",").split(",") if tok.strip()]
    elif isinstance(value, list):
        tokens = value
    else:
        tokens = []
    for tok in tokens:
        try:
            items.append(int(tok))
        except Exception:
            continue
    return items

def _normalize_question_type_name(value):
    token = _coerce_string(value).strip().lower().replace("-", "_").replace(" ", "_")
    return QUESTION_TYPE_ALIASES.get(token, token)

def _normalize_code_mode_name(value):
    token = _coerce_string(value).strip().lower().replace("-", "_").replace(" ", "_")
    return CODE_MODE_ALIASES.get(token, token)

def _normalize_task_kind_name(value):
    token = _coerce_string(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not token:
        return "assessment"
    return TASK_KIND_ALIASES.get(token, token)

def _task_kind_value(task):
    if not task:
        return "assessment"
    return _normalize_task_kind_name(getattr(task, "task_kind", "assessment") or "assessment")

def _is_tutorial_task(task):
    return _task_kind_value(task) == "tutorial"

def _coerce_code_expected(value):
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        try:
            ast.literal_eval(text)
            return text
        except Exception:
            return repr(text)
    return repr(value)

DEFAULT_SCRIPT_SAMPLE_COMPARE_MODE = "rstrip"
DEFAULT_CALLABLE_SAMPLE_COMPARE_MODE = "exact"
DEFAULT_NUMERIC_TOLERANCE = 1e-6

SCRIPT_SAMPLE_COMPARE_ALIASES = {
    "exact": "exact",
    "exact_text": "exact",
    "strict": "exact",
    "rstrip": "rstrip",
    "ignore_trailing_whitespace": "rstrip",
    "trim_end": "rstrip",
    "trimmed": "rstrip",
    "normalize_whitespace": "normalize_whitespace",
    "normalized_whitespace": "normalize_whitespace",
    "ignore_whitespace": "normalize_whitespace",
    "contains": "contains",
    "substring": "contains",
}

CALLABLE_SAMPLE_COMPARE_ALIASES = {
    "exact": "exact",
    "equality": "exact",
    "numeric_tolerance": "numeric_tolerance",
    "tolerance": "numeric_tolerance",
    "allclose": "numeric_tolerance",
    "close": "numeric_tolerance",
    "contains": "contains",
    "repr_contains": "contains",
    "text_contains": "contains",
    "string_contains": "contains",
}

def _normalize_sample_compare_mode(value, sample_kind):
    token = _coerce_string(value).strip().lower().replace("-", "_").replace(" ", "_")
    if sample_kind == "script":
        if not token:
            return DEFAULT_SCRIPT_SAMPLE_COMPARE_MODE
        mode = SCRIPT_SAMPLE_COMPARE_ALIASES.get(token)
        if not mode:
            raise ValueError(f"Unknown script comparison mode '{value}'.")
        return mode
    if not token:
        return DEFAULT_CALLABLE_SAMPLE_COMPARE_MODE
    mode = CALLABLE_SAMPLE_COMPARE_ALIASES.get(token)
    if not mode:
        raise ValueError(f"Unknown callable comparison mode '{value}'.")
    return mode

def _coerce_sample_tolerance(value, default=DEFAULT_NUMERIC_TOLERANCE):
    if value in (None, ""):
        return float(default)
    try:
        tolerance = float(_coerce_string(value).strip())
    except Exception:
        raise ValueError("Tolerance must be a non-negative number.")
    if tolerance < 0:
        raise ValueError("Tolerance must be a non-negative number.")
    return tolerance

def _sample_compare_settings(sample, sample_kind):
    compare_mode = _normalize_sample_compare_mode(
        _first_present(sample, "compare_mode", "compare", "comparison", "match_mode", "matcher"),
        sample_kind,
    )
    tolerance = None
    if sample_kind != "script" and compare_mode == "numeric_tolerance":
        tolerance = _coerce_sample_tolerance(
            _first_present(sample, "tolerance", "abs_tolerance", "atol", "epsilon"),
        )
    return compare_mode, tolerance

def _validate_numeric_tolerance_expected(expected_text):
    text = _coerce_string(expected_text).strip()
    if not text:
        raise ValueError("Numeric tolerance comparison requires an expected value.")
    try:
        ast.literal_eval(text)
    except Exception:
        raise ValueError("Numeric tolerance comparison requires a literal expected value.")

def _coerce_timeout_ms(value):
    if value in (None, ""):
        return None
    try:
        timeout_ms = int(float(value))
    except Exception:
        raise ValueError("timeout_ms must be a positive integer.")
    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be a positive integer.")
    return timeout_ms

def _parse_json_list(value, field_name):
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be valid JSON: {exc}")
        if parsed in (None, ""):
            return []
        if not isinstance(parsed, list):
            raise ValueError(f"{field_name} must be a JSON array.")
        return parsed
    raise ValueError(f"{field_name} must be a JSON array.")

def _normalize_hidden_test_files(value):
    if value in (None, ""):
        return []
    if isinstance(value, str):
        raw_items = _parse_json_list(value, "Hidden test files")
    elif isinstance(value, list):
        raw_items = value
    else:
        raise ValueError("Hidden test files must be a list.")
    files = []
    for idx, item in enumerate(raw_items, start=1):
        if isinstance(item, str):
            source = _coerce_string(item).strip()
            target = os.path.basename(source)
        elif isinstance(item, dict):
            source = _coerce_string(_first_present(item, "source", "src", "path", "bundle_path")).strip()
            target = _coerce_string(_first_present(item, "target", "dest", "mount_as", "name")).strip() or os.path.basename(source)
        else:
            raise ValueError(f"Hidden test file #{idx} must be an object or string path.")
        if not source:
            raise ValueError(f"Hidden test file #{idx} is missing a source path.")
        if not target:
            raise ValueError(f"Hidden test file #{idx} is missing a target path.")
        files.append({"source": source, "target": target})
    return files

def _normalize_hidden_code_tests(raw_tests, mode, class_init=None):
    tests_raw = _parse_json_list(raw_tests, "hidden_tests")
    normalized = []
    sample_kind = "script" if mode == "script" else "callable"
    for idx, test in enumerate(tests_raw, start=1):
        if not isinstance(test, dict):
            raise ValueError(f"Hidden test #{idx} must be an object.")
        name = _coerce_string(_first_present(test, "name", "label")).strip() or f"Hidden test {idx}"
        compare_mode, tolerance = _sample_compare_settings(test, sample_kind)
        normalized_test = {
            "name": name,
            "hidden": True,
            "compare_mode": compare_mode,
            "files": _normalize_hidden_test_files(_first_present(test, "files", "support_files", "mounted_files")),
        }
        timeout_ms = _coerce_timeout_ms(_first_present(test, "timeout_ms", "timeout", "time_limit_ms"))
        if timeout_ms is not None:
            normalized_test["timeout_ms"] = timeout_ms
        if tolerance is not None:
            normalized_test["tolerance"] = tolerance

        stdin_file = _coerce_string(_first_present(test, "stdin_file", "input_file")).strip()
        expected_file = _coerce_string(_first_present(test, "expected_file", "output_file", "expected_file_path")).strip()
        if stdin_file:
            normalized_test["stdin_file"] = stdin_file
        if expected_file:
            normalized_test["expected_file"] = expected_file

        if mode == "script":
            input_text = _coerce_string(_first_present(test, "input", "stdin"))
            output_text = _coerce_string(_first_present(test, "output", "expected_stdout", "expected"))
            if input_text:
                normalized_test["input"] = input_text
            if output_text:
                normalized_test["output"] = output_text
            if not input_text and not stdin_file and not normalized_test["files"]:
                normalized_test["input"] = ""
        elif mode == "function":
            call_expr = _coerce_string(_first_present(test, "call", "function_call", "expression", "input")).strip()
            expected = _coerce_code_expected(_first_present(test, "expected", "expected_return", "expected_result", "output"))
            if not call_expr:
                raise ValueError(f"{name}: function hidden tests need a call expression.")
            normalized_test["call"] = call_expr
            normalized_test["input"] = call_expr
            if expected:
                normalized_test["expected"] = expected
            if compare_mode == "numeric_tolerance" and not expected and not expected_file:
                raise ValueError(f"{name}: numeric tolerance hidden tests need an expected value.")
            if compare_mode == "numeric_tolerance" and expected:
                _validate_numeric_tolerance_expected(expected)
        else:
            call_expr = _coerce_string(_first_present(test, "call", "method_call", "expression", "input")).strip()
            expected = _coerce_code_expected(_first_present(test, "expected", "expected_return", "expected_result", "output"))
            init_call = _coerce_string(_first_present(test, "init_call", "constructor_call", "object_initializer")).strip() or _coerce_string(class_init).strip()
            if not call_expr:
                raise ValueError(f"{name}: class hidden tests need a method call or expression.")
            if not init_call:
                raise ValueError(f"{name}: class hidden tests need an init_call or task-level class_init.")
            normalized_test["call"] = call_expr
            normalized_test["input"] = call_expr
            normalized_test["init_call"] = init_call
            if expected:
                normalized_test["expected"] = expected
            if compare_mode == "numeric_tolerance" and not expected and not expected_file:
                raise ValueError(f"{name}: numeric tolerance hidden tests need an expected value.")
            if compare_mode == "numeric_tolerance" and expected:
                _validate_numeric_tolerance_expected(expected)
        normalized.append(normalized_test)
    return normalized

def _code_question_hidden_tests(question):
    if not isinstance(question, dict) or question.get("type") != "code":
        return []
    hidden_tests = []
    for test in question.get("hidden_tests") or []:
        if isinstance(test, dict):
            item = dict(test)
            item["hidden"] = True
            hidden_tests.append(item)
    for sample in question.get("samples") or []:
        if isinstance(sample, dict) and sample.get("hidden"):
            item = dict(sample)
            item["hidden"] = True
            hidden_tests.append(item)
    return hidden_tests

def _code_question_has_hidden_tests(question):
    return bool(_code_question_hidden_tests(question))

def _hidden_test_requires_bundle(test):
    if not isinstance(test, dict):
        return False
    if _coerce_string(test.get("stdin_file")).strip():
        return True
    if _coerce_string(test.get("expected_file")).strip():
        return True
    return bool(test.get("files"))

def _questions_require_judge_bundle(questions):
    if not isinstance(questions, list):
        return False
    for question in questions:
        for test in _code_question_hidden_tests(question):
            if _hidden_test_requires_bundle(test):
                return True
    return False

def _task_has_async_hidden_judge(task_or_questions):
    if isinstance(task_or_questions, list):
        questions = task_or_questions
    else:
        questions = task_or_questions.questions_json if task_or_questions and isinstance(task_or_questions.questions_json, list) else []
    return any(_code_question_has_hidden_tests(question) for question in questions)

def _extract_choice_options(value):
    options = []
    implied_correct = []
    if isinstance(value, str):
        options = [line.strip() for line in value.splitlines() if line.strip()]
        return options, implied_correct
    if not isinstance(value, list):
        return options, implied_correct
    for item in value:
        if isinstance(item, dict):
            text = _coerce_string(_first_present(item, "text", "label", "option", "value")).strip()
            if not text:
                continue
            options.append(text)
            if _coerce_bool(_first_present(item, "is_correct", "correct"), False):
                implied_correct.append(len(options) - 1)
        else:
            text = _coerce_string(item).strip()
            if text:
                options.append(text)
    return options, implied_correct

def _build_project_tasks_schema():
    minimal_payload = {
        "tasks": [
            {
                "title": "Lists warmup",
                "description": "Short practice on Python lists.",
                "instructions": "Answer every question. Code questions run in Python only.",
                "required": True,
                "auto_grade": True,
                "requires_review": False,
                "questions": [
                    {
                        "id": "q_lists_mcq",
                        "type": "mcq",
                        "title": "Indexing",
                        "prompt": "Which expression returns the first element of `items`?",
                        "points": 2,
                        "choices": [
                            {"text": "items[0]", "is_correct": True},
                            {"text": "items[1]"},
                            {"text": "items[-0]"}
                        ]
                    }
                ]
            }
        ]
    }
    class_payload = {
        "tasks": [
            {
                "title": "Accumulator class",
                "description": "Implement and test a small Python class.",
                "instructions": "Write the class exactly as described. Each test creates a fresh object named `obj`.",
                "required": True,
                "auto_grade": True,
                "requires_review": False,
                "questions": [
                    {
                        "id": "q_accumulator_class",
                        "type": "code",
                        "title": "Build Accumulator",
                        "prompt": "Implement the `Accumulator` class.",
                        "points": 10,
                        "problem_statement": "Create a class `Accumulator` with `__init__(start)`, `add(amount)` that returns the updated total, and `total()` that returns the current total.",
                        "starter_code": "class Accumulator:\n    pass\n",
                        "code_mode": "class",
                        "class_signature": "class Accumulator:",
                        "class_init": "Accumulator(3)",
                        "tests": [
                            {
                                "name": "initial total",
                                "method_call": "obj.total()",
                                "expected_result": 3,
                                "compare_mode": "exact"
                            },
                            {
                                "name": "add returns new total",
                                "method_call": "obj.add(2)",
                                "expected_result": 5,
                                "compare_mode": "exact"
                            }
                        ]
                    }
                ]
            }
        ]
    }
    plot_payload = {
        "tasks": [
            {
                "title": "Line chart practice",
                "description": "Generate a labeled matplotlib plot.",
                "instructions": "Write Python that creates the requested chart. Students can preview the final PNG before submitting.",
                "required": True,
                "auto_grade": True,
                "requires_review": True,
                "questions": [
                    {
                        "id": "q_sales_plot",
                        "type": "plot",
                        "title": "Monthly sales chart",
                        "prompt": "Create the line chart described below.",
                        "points": 10,
                        "problem_statement": "Use matplotlib to plot months `[1, 2, 3, 4]` against sales `[10, 14, 11, 18]`. Add a title, axis labels, and markers on each point.",
                        "starter_code": "import matplotlib.pyplot as plt\n\nmonths = [1, 2, 3, 4]\nsales = [10, 14, 11, 18]\n\n# build your chart here\n"
                    }
                ]
            }
        ]
    }
    formatting_payload = {
        "tasks": [
            {
                "title": "Formatting reference",
                "description": "This task shows how markdown text is rendered from imported JSON.\n\n- Use `\\n` for a new line\n- Use `\\n\\n` for a blank line between paragraphs\n- Use markdown lists and fenced code blocks when structure matters",
                "instructions": "Read the prompt carefully.\n\n## Rendering rules\n- Bullet items should stay on separate lines.\n- Blank lines should stay blank.\n\n```python\nfor value in [1, 2, 3]:\n    print(value)\n```",
                "required": True,
                "auto_grade": False,
                "requires_review": True,
                "questions": [
                    {
                        "id": "q_formatting_text",
                        "type": "text",
                        "title": "Explain the rendering",
                        "prompt": "Describe what the student should notice.\n\n- The heading above\n- The bullet list\n- The fenced code block",
                        "points": 3,
                        "placeholder": "Write 2-3 sentences.\nMention both line breaks and markdown.",
                        "lines": 5
                    }
                ]
            }
        ]
    }
    comparison_payload = {
        "tasks": [
            {
                "title": "Comparison modes demo",
                "description": "Reference payload showing how JSON imports can control sample comparison rules.",
                "instructions": "Use these samples as a template when you need flexible output matching, substring checks, or numeric tolerance for floats and arrays.",
                "required": True,
                "auto_grade": True,
                "requires_review": False,
                "questions": [
                    {
                        "id": "q_compare_script",
                        "type": "code",
                        "title": "Flexible stdout checks",
                        "prompt": "Print a greeting for the provided name.",
                        "points": 5,
                        "problem_statement": "Read one name from stdin and print `Hello, <name>!`.",
                        "starter_code": "name = input().strip()\n# print your greeting here\n",
                        "code_mode": "script",
                        "tests": [
                            {
                                "name": "ignore extra spacing",
                                "stdin": "Ada\n",
                                "expected_stdout": "Hello, Ada!",
                                "compare_mode": "normalize_whitespace"
                            },
                            {
                                "name": "must mention the name",
                                "stdin": "Grace\n",
                                "expected_stdout": "Grace",
                                "compare_mode": "contains"
                            }
                        ]
                    },
                    {
                        "id": "q_compare_function",
                        "type": "code",
                        "title": "Numeric tolerance",
                        "prompt": "Implement mean(values).",
                        "points": 5,
                        "problem_statement": "Return the arithmetic mean of the numeric values.",
                        "starter_code": "def mean(values):\n    pass\n",
                        "code_mode": "function",
                        "function_signature": "def mean(values):",
                        "tests": [
                            {
                                "name": "simple average",
                                "function_call": "mean([1, 2, 3])",
                                "expected_return": 2.0,
                                "compare_mode": "numeric_tolerance",
                                "tolerance": 0.000001
                            }
                        ]
                    }
                ]
            }
        ]
    }
    hidden_judge_payload = {
        "tasks": [
            {
                "title": "Large input sum",
                "description": "Script-mode problem with public samples plus hidden tests judged from a private ZIP bundle.",
                "instructions": "Use the public sample to debug locally. Final acceptance comes from the hidden tests in the judge bundle.",
                "required": True,
                "auto_grade": True,
                "requires_review": False,
                "questions": [
                    {
                        "id": "q_sum_large",
                        "type": "code",
                        "title": "Sum many integers",
                        "prompt": "Read integers from stdin and print their sum.",
                        "points": 20,
                        "problem_statement": "The first line contains `n`. The second line contains `n` space-separated integers. Print their sum.",
                        "starter_code": "n = int(input().strip())\nvalues = list(map(int, input().split()))\n# print(sum(values))\n",
                        "code_mode": "script",
                        "tests": [
                            {
                                "name": "small public sample",
                                "stdin": "5\n1 2 3 4 5\n",
                                "expected_stdout": "15\n",
                                "compare_mode": "exact"
                            }
                        ],
                        "hidden_tests": [
                            {
                                "name": "large generated input",
                                "stdin_file": "cases/large_01.in",
                                "expected_file": "cases/large_01.out",
                                "timeout_ms": 1200
                            },
                            {
                                "name": "uses a mounted helper file",
                                "stdin": "weights.txt\n",
                                "expected_stdout": "42\n",
                                "files": [
                                    {
                                        "source": "datasets/weights.txt",
                                        "target": "weights.txt"
                                    }
                                ],
                                "timeout_ms": 1200
                            }
                        ]
                    }
                ]
            }
        ]
    }
    tutorial_payload = {
        "tasks": [
            {
                "task_kind": "tutorial",
                "title": "Python list basics",
                "description": "Short read-only tutorial introducing indexing and slicing.",
                "tutorial_markdown": "## Goal\nLearn how to read values from a Python list.\n\n## Key ideas\n- `items[0]` returns the first element.\n- Negative indexes count from the end.\n- Slices use `start:stop`.\n\n```python\nitems = ['a', 'b', 'c', 'd']\nprint(items[0])\nprint(items[1:3])\n```\n\n## Try mentally\nWhat does `items[-1]` print?",
                "required": True
            }
        ]
    }
    return {
        "schema_name": "project_task_import",
        "schema_version": 7,
        "summary": "Reference document for importing project tasks from JSON. It covers read-only tutorial tasks plus assessment tasks with MCQ, text, token-fill, file upload, code, class-mode code, plot questions, markdown escaping, public sample comparison rules, and hidden tests judged from a private bundle.",
        "paste_payload_shape": {
            "type": "object",
            "required": ["tasks"],
            "properties": {
                "tasks": {
                    "type": "array",
                    "minItems": 1,
                    "description": "List of task definitions to create. The importer also accepts the alias keys `project_tasks` and `items`.",
                    "items": {
                        "type": "object",
                        "required": ["title"],
                        "properties": {
                            "task_kind": {"type": "string", "description": "Task kind. Use `assessment` for normal answerable tasks or `tutorial` for read-only markdown lessons. Aliases: `task_type`, `mode`, `kind`."},
                            "title": {"type": "string", "description": "Task title. Alias: `name`. Rendered with inline markdown."},
                            "description": {"type": ["string", "null"], "description": "Short summary shown above the task. Rendered as a markdown block. Use \\n for line breaks and \\n\\n for paragraph breaks."},
                            "instructions": {"type": ["string", "null"], "description": "Task instructions shown to students. For tutorial tasks this is the main markdown lesson body. Supports headings, lists, fenced code blocks, and \\n / \\n\\n escapes."},
                            "tutorial_markdown": {"type": ["string", "null"], "description": "Tutorial-only alias for `instructions`. Also accepts `content_markdown`, `content`, and `body`."},
                            "required": {"type": "boolean", "default": True},
                            "auto_grade": {"type": "boolean", "default": True},
                            "requires_review": {"type": "boolean", "default": False},
                            "judge_bundle_file": {"type": ["object", "null"], "description": "Optional metadata placeholder used only in exports. Upload the actual judge bundle ZIP separately in the form UI."},
                            "questions": {
                                "type": "array",
                                "minItems": 1,
                                "description": "Question definitions for assessment tasks. Alias: `items`. Tutorial tasks must omit this field or provide an empty array."
                            }
                        },
                        "additionalProperties": True
                    }
                }
            },
            "additionalProperties": True
        },
        "task_kind_reference": {
            "default": "assessment",
            "supported_values": {
                "assessment": {
                    "description": "Regular task with one or more questions. Students submit answers and may be auto-graded or reviewed."
                },
                "tutorial": {
                    "description": "Read-only markdown tutorial. No questions or student input. The task is completed when the student opens it.",
                    "content_fields": ["instructions", "tutorial_markdown", "content_markdown", "content", "body"]
                }
            },
            "rules": [
                "Assessment tasks must include a non-empty `questions` array.",
                "Tutorial tasks must not include questions.",
                "Tutorial tasks are always read-only: auto-grading and mentor review flags are ignored."
            ]
        },
        "text_rendering_reference": {
            "summary": "Most visible text fields are rendered with markdown. Because the payload is JSON, line breaks must be escaped inside strings.",
            "markdown_block_fields": [
                "task.description",
                "task.instructions",
                "question.prompt",
                "code.problem_statement",
                "plot.problem_statement",
                "mcq/multi option text"
            ],
            "inline_markdown_fields": [
                "task.title",
                "question.title",
                "tokens/fill template text segments"
            ],
            "plain_text_fields": [
                "code_snippet",
                "starter_code",
                "function_signature",
                "class_signature",
                "class_init"
            ],
            "newline_rules": [
                "JSON strings cannot contain raw line breaks. Use escaped sequences like \\n inside the string value.",
                "Use \\n for a visible new line.",
                "Use \\n\\n to separate paragraphs or create a blank line between sections.",
                "For bullet lists, keep one item per line: - first\\n- second",
                "For code blocks inside markdown, use fenced code with escaped new lines: ```python\\nprint('hi')\\n```"
            ],
            "examples": {
                "single_line_break": {
                    "prompt": "Line one\\nLine two"
                },
                "paragraphs_and_list": {
                    "instructions": "Read carefully.\\n\\n- First requirement\\n- Second requirement"
                },
                "fenced_code_block": {
                    "problem_statement": "Starter shape:\\n```python\\ndef solve():\\n    pass\\n```"
                }
            }
        },
        "accepted_aliases": {
            "root": {
                "tasks": ["tasks", "project_tasks", "items"]
            },
            "task_fields": {
                "task_kind": ["task_kind", "task_type", "mode", "kind"],
                "title": ["title", "name"],
                "description": ["description", "summary"],
                "instructions": ["instructions", "student_instructions", "tutorial_markdown", "content_markdown", "content", "body"],
                "required": ["required", "is_required"],
                "auto_grade": ["auto_grade", "autograde", "automatic_grading"],
                "requires_review": ["requires_review", "mentor_review", "manual_review"],
                "judge_bundle_file": ["judge_bundle_file", "hidden_bundle", "private_bundle"],
                "questions": ["questions", "items"]
            },
            "question_common_fields": {
                "type": ["type", "question_type", "kind"],
                "id": ["id", "question_id"],
                "title": ["title", "name", "label"],
                "prompt": ["prompt", "question", "question_text"],
                "points": ["points", "score", "max_points"],
                "code_snippet": ["code_snippet", "context_code", "reference_code"]
            },
            "question_type_aliases": QUESTION_TYPE_ALIASES,
            "code_mode_aliases": CODE_MODE_ALIASES,
            "code_question_fields": {
                "statement": ["statement", "problem_statement", "description"],
                "starter": ["starter", "starter_code", "starter_template"],
                "mode": ["mode", "code_mode"],
                "samples": ["samples", "tests", "test_cases"],
                "hidden_tests": ["hidden_tests", "private_tests", "hidden_tests_json"],
                "function_signature": ["function_signature", "signature", "callable_signature"],
                "class_signature": ["class_signature", "signature"],
                "class_init": ["class_init", "init_call", "constructor_call", "object_initializer"]
            },
            "code_sample_fields": {
                "common": {
                    "name": ["name", "label"],
                    "hidden": ["hidden", "is_hidden"],
                    "compare_mode": ["compare_mode", "compare", "comparison", "match_mode", "matcher"]
                },
                "script_mode": {
                    "input": ["input", "stdin"],
                    "output": ["output", "expected_stdout", "expected"]
                },
                "function_mode": {
                    "call": ["call", "function_call", "expression"],
                    "expected": ["expected", "expected_return", "expected_result", "output"],
                    "tolerance": ["tolerance", "abs_tolerance", "atol", "epsilon"]
                },
                "class_mode": {
                    "call": ["call", "method_call", "expression"],
                    "expected": ["expected", "expected_return", "expected_result", "output"],
                    "init_call": ["init_call", "constructor_call", "object_initializer"],
                    "tolerance": ["tolerance", "abs_tolerance", "atol", "epsilon"]
                }
            },
            "hidden_test_fields": {
                "common": {
                    "name": ["name", "label"],
                    "compare_mode": ["compare_mode", "compare", "comparison", "match_mode", "matcher"],
                    "timeout_ms": ["timeout_ms", "timeout", "time_limit_ms"],
                    "files": ["files", "support_files", "mounted_files"],
                    "stdin_file": ["stdin_file", "input_file"],
                    "expected_file": ["expected_file", "output_file", "expected_file_path"]
                },
                "file_mapping_fields": {
                    "source": ["source", "src", "path", "bundle_path"],
                    "target": ["target", "dest", "mount_as", "name"]
                }
            }
        },
        "question_reference": {
            "common_rules": [
                "Assessment-task questions each need a `type` and a visible `prompt`.",
                "Tutorial tasks do not define questions at all; put the lesson in task-level markdown instead.",
                "Question `id` is optional. The importer will generate one if missing.",
                "For booleans, use real JSON booleans: true or false.",
                "For function/class code tests, expected values may be strings or JSON scalars/arrays/objects.",
                "Public code samples can set `compare_mode`. Callable samples may also set `tolerance` for numeric tolerance checks.",
                "Hidden tests belong in `hidden_tests`, not in the public `tests` array.",
                "If a hidden test uses `stdin_file`, `expected_file`, or mounted `files`, upload a judge bundle ZIP alongside the JSON.",
                "Visible text fields support markdown; in JSON strings use `\\n` for a new line and `\\n\\n` for a blank line.",
                "Prefer markdown lists, headings, and fenced code blocks over manual spacing."
            ],
            "types": {
                "mcq": {
                    "required_fields": ["type", "prompt", "choices", "correct answer"],
                    "recommended_shape": {
                        "type": "mcq",
                        "prompt": "Question text",
                        "choices": [
                            {"text": "Option A", "is_correct": True},
                            {"text": "Option B", "is_correct": False}
                        ]
                    },
                    "notes": [
                        "You can use `options` as a list of strings or `choices` as a list of objects.",
                        "If you do not use `is_correct`, provide `correct_indices` with 0-based indexes."
                    ]
                },
                "multi": {
                    "required_fields": ["type", "prompt", "choices", "at least one correct answer"],
                    "recommended_shape": {
                        "type": "multi",
                        "prompt": "Select all correct answers.",
                        "choices": [
                            {"text": "Option A", "is_correct": True},
                            {"text": "Option B", "is_correct": True},
                            {"text": "Option C", "is_correct": False}
                        ]
                    }
                },
                "text": {
                    "required_fields": ["type", "prompt"],
                    "recommended_shape": {
                        "type": "text",
                        "prompt": "Explain your reasoning.\n\n- Mention the main idea\n- Mention one edge case",
                        "placeholder": "Write 3-5 sentences.",
                        "lines": 5
                    },
                    "notes": [
                        "Prompt and placeholder text accept escaped new lines like `\\n`.",
                        "Prompt text is rendered as markdown."
                    ]
                },
                "tokens": {
                    "required_fields": ["type", "prompt", "template", "correct_tokens"],
                    "recommended_shape": {
                        "type": "tokens",
                        "prompt": "Drag the correct tokens into the blanks.",
                        "template": "[[blank]]([[blank]](myvar))",
                        "correct_tokens": ["print", "str"],
                        "distractor_tokens": ["len", "int"]
                    }
                },
                "fill": {
                    "required_fields": ["type", "prompt", "template", "answers"],
                    "recommended_shape": {
                        "type": "fill",
                        "prompt": "Complete the statement.",
                        "template": "carname = \"[[blank]]\"",
                        "answers": ["Volvo"],
                        "case_sensitive": False
                    }
                },
                "file": {
                    "required_fields": ["type", "prompt"],
                    "recommended_shape": {
                        "type": "file",
                        "prompt": "Upload your ZIP submission.",
                        "accept": ".zip",
                        "max_mb": 5
                    }
                },
                "plot": {
                    "required_fields": ["type", "prompt", "problem_statement"],
                    "recommended_shape": plot_payload["tasks"][0]["questions"][0],
                    "notes": [
                        "Plot questions are Python-only and always require manual review.",
                        "Students preview the latest PNG in the browser, and the final PNG is uploaded only on submit.",
                        "`problem_statement` is rendered as markdown, so use `\\n`, lists, and fenced code blocks if you need structure."
                    ]
                },
                "code": {
                    "required_fields": ["type", "prompt", "problem_statement", "code_mode"],
                    "shared_shape": {
                        "type": "code",
                        "prompt": "Short visible question prompt.",
                        "problem_statement": "Detailed coding instructions.\n\n- Requirement one\n- Requirement two",
                        "starter_code": "# optional starter code",
                        "code_mode": "script | function | class",
                        "tests": "optional public sample tests shown to students",
                        "hidden_tests": "optional private judge tests run only on submit"
                    },
                    "modes": {
                        "script": {
                            "use_when": "Students write a full program that reads stdin and prints stdout.",
                            "example": {
                                "type": "code",
                                "prompt": "Echo two lines.",
                                "problem_statement": "Read two lines and print them in reverse order.",
                                "code_mode": "script",
                                "tests": [
                                    {
                                        "name": "two words",
                                        "stdin": "apple\nbanana\n",
                                        "expected_stdout": "banana\napple\n",
                                        "compare_mode": "rstrip"
                                    }
                                ],
                                "hidden_tests": [
                                    {
                                        "name": "large input",
                                        "stdin_file": "cases/large.in",
                                        "expected_file": "cases/large.out",
                                        "timeout_ms": 1200
                                    }
                                ]
                            },
                            "notes": [
                                "Script compare modes: `rstrip` (default), `exact`, `normalize_whitespace`, `contains`.",
                                "Use `hidden_tests` for final judging. A hidden script test may use inline `stdin`/`expected_stdout` or file-backed `stdin_file`/`expected_file` entries from the private judge bundle."
                            ]
                        },
                        "function": {
                            "use_when": "Students implement a function and each test calls it directly.",
                            "example": {
                                "type": "code",
                                "prompt": "Implement square.",
                                "problem_statement": "Write a function that returns the square of n.",
                                "code_mode": "function",
                                "function_signature": "def square(n):",
                                "tests": [
                                    {
                                        "name": "square of five",
                                        "function_call": "square(5)",
                                        "expected_return": 25,
                                        "compare_mode": "numeric_tolerance",
                                        "tolerance": 0.000001
                                    }
                                ]
                            },
                            "notes": [
                                "Callable compare modes: `exact` (default), `numeric_tolerance`, `contains`.",
                                "Use `numeric_tolerance` for floats or arrays and set `tolerance` to an absolute tolerance such as `1e-6`.",
                                "Hidden function tests may also mount files from the judge bundle if the implementation is expected to read helper files."
                            ]
                        },
                        "class": {
                            "use_when": "Students implement a class. Each test creates a fresh object named `obj` using `class_init` before evaluating the method call or expression.",
                            "example": class_payload["tasks"][0]["questions"][0],
                            "notes": [
                                "Class-mode tests use the same compare modes as function-mode tests.",
                                "Class hidden tests may override `init_call` per test or inherit the task-level `class_init`."
                            ]
                        }
                    },
                    "hidden_test_bundle_reference": {
                        "summary": "Hidden tests can reference files stored in a private ZIP bundle uploaded with the task form.",
                        "bundle_examples": [
                            "cases/large_01.in",
                            "cases/large_01.out",
                            "datasets/weights.txt"
                        ],
                        "file_mapping_shape": {
                            "source": "datasets/weights.txt",
                            "target": "weights.txt"
                        }
                    }
                }
            }
        },
        "example_payloads": {
            "minimal_payload": minimal_payload,
            "tutorial_payload": tutorial_payload,
            "class_code_payload": class_payload,
            "plot_payload": plot_payload,
            "formatting_payload": formatting_payload,
            "comparison_payload": comparison_payload,
            "hidden_judge_payload": hidden_judge_payload
        }
    }

PROJECT_TASKS_SCHEMA = _build_project_tasks_schema()
PROJECT_TASKS_EXAMPLE_DOWNLOADS = {
    "minimal": "minimal_payload",
    "tutorial": "tutorial_payload",
    "class_code": "class_code_payload",
    "plot": "plot_payload",
    "formatting": "formatting_payload",
    "comparison": "comparison_payload",
    "hidden_judge": "hidden_judge_payload",
}

LEADERBOARD_METRICS = {
    "total_points": {"label": "Total points", "description": "Sum of all recorded grade scores."},
    "projects_done": {"label": "Projects done", "description": "Count of projects with required tasks accepted."},
    "logtime": {"label": "Log time", "description": "Student activity time based on online sessions."},
}

def _ensure_project_collection_column():
    try:
        inspector = inspect(db.engine)
        if "projects" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("projects")}
        if "collection" not in columns:
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE projects "
                        "ADD COLUMN collection VARCHAR(64) NOT NULL DEFAULT 'comp101'"
                    )
                )
        with db.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE projects "
                    "SET collection='comp101' "
                    "WHERE collection IS NULL OR collection=''"
                )
            )
    except Exception:
        # Fail open: don't block app start if migration fails
        pass

def _ensure_project_deadline_column():
    try:
        inspector = inspect(db.engine)
        if "projects" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("projects")}
        if "deadline_at" not in columns:
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE projects "
                        "ADD COLUMN deadline_at DATETIME NULL"
                    )
                )
    except Exception:
        # Fail open: don't block app start if migration fails
        pass

def _ensure_project_task_kind_column():
    try:
        inspector = inspect(db.engine)
        if "project_tasks" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("project_tasks")}
        if "task_kind" not in columns:
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE project_tasks "
                        "ADD COLUMN task_kind VARCHAR(32) NOT NULL DEFAULT 'assessment'"
                    )
                )
        with db.engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE project_tasks "
                    "SET task_kind='assessment' "
                    "WHERE task_kind IS NULL OR task_kind=''"
                )
            )
    except Exception:
        # Fail open: don't block app start if migration fails
        pass

def _ensure_project_task_judge_bundle_column():
    try:
        inspector = inspect(db.engine)
        if "project_tasks" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("project_tasks")}
        if "judge_bundle_file" not in columns:
            with db.engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE project_tasks "
                        "ADD COLUMN judge_bundle_file TEXT NULL"
                    )
                )
    except Exception:
        pass

def _ensure_project_task_submission_judge_columns():
    try:
        inspector = inspect(db.engine)
        if "project_task_submissions" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("project_task_submissions")}
        missing = {
            "judge_state": "ALTER TABLE project_task_submissions ADD COLUMN judge_state VARCHAR(32) NULL",
            "judge_verdict": "ALTER TABLE project_task_submissions ADD COLUMN judge_verdict VARCHAR(64) NULL",
            "judge_feedback": "ALTER TABLE project_task_submissions ADD COLUMN judge_feedback TEXT NULL",
            "judge_summary_json": "ALTER TABLE project_task_submissions ADD COLUMN judge_summary_json TEXT NULL",
        }
        for column_name, ddl in missing.items():
            if column_name not in columns:
                with db.engine.begin() as conn:
                    conn.execute(text(ddl))
    except Exception:
        pass

def _ensure_project_task_attempt_judge_columns():
    try:
        inspector = inspect(db.engine)
        if "project_task_attempts" not in inspector.get_table_names():
            return
        columns = {col["name"] for col in inspector.get_columns("project_task_attempts")}
        missing = {
            "judge_state": "ALTER TABLE project_task_attempts ADD COLUMN judge_state VARCHAR(32) NULL",
            "judge_verdict": "ALTER TABLE project_task_attempts ADD COLUMN judge_verdict VARCHAR(64) NULL",
            "judge_feedback": "ALTER TABLE project_task_attempts ADD COLUMN judge_feedback TEXT NULL",
            "judge_summary_json": "ALTER TABLE project_task_attempts ADD COLUMN judge_summary_json TEXT NULL",
        }
        for column_name, ddl in missing.items():
            if column_name not in columns:
                with db.engine.begin() as conn:
                    conn.execute(text(ddl))
    except Exception:
        pass

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
        _ensure_project_collection_column()
        _ensure_project_deadline_column()
        _ensure_project_task_kind_column()
        _ensure_project_task_judge_bundle_column()
        _ensure_project_task_submission_judge_columns()
        _ensure_project_task_attempt_judge_columns()
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

def _safe_path_within(base_path, relative_or_absolute_path):
    if not base_path or relative_or_absolute_path in (None, ""):
        return None
    base = os.path.abspath(base_path)
    target = relative_or_absolute_path
    if not os.path.isabs(target):
        target = os.path.join(base, relative_or_absolute_path)
    target = os.path.abspath(target)
    if target == base or target.startswith(base + os.sep):
        return target
    return None

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

def _save_project_task_bundle_from_bytes(task, original_name, payload, content_type="", existing_info=None):
    if not task:
        return None, "Missing task."
    filename = os.path.basename(original_name or "")
    if not filename:
        return None, "No judge bundle selected."
    extension = os.path.splitext(filename)[1].lower()
    if extension != ".zip":
        return None, "Judge bundle must be a .zip file."
    if payload is None:
        return None, "Unable to read the judge bundle."
    if len(payload) > JUDGE_BUNDLE_MAX_BYTES:
        return None, f"Judge bundle must be {JUDGE_BUNDLE_MAX_MB} MB or smaller."
    safe_name = secure_filename(filename) or "judge_bundle.zip"
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    upload_dir = os.path.join(
        UPLOAD_ROOT,
        "judge_bundles",
        str(task.project_id),
        str(task.id),
    )
    os.makedirs(upload_dir, exist_ok=True)
    full_path = os.path.join(upload_dir, stored_name)
    try:
        with open(full_path, "wb") as fh:
            fh.write(payload)
    except Exception:
        return None, "Unable to save the judge bundle."
    rel_path = os.path.relpath(full_path, UPLOAD_ROOT)
    file_info = {
        "original_name": filename or safe_name,
        "stored_name": stored_name,
        "path": rel_path,
        "size": len(payload),
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "content_type": content_type or "application/zip",
    }
    if existing_info:
        _remove_uploaded_file(existing_info)
    return file_info, None

def _save_task_judge_bundle(task, file_storage, existing_info=None):
    if not task or not file_storage:
        return None, "Missing task or file."
    filename = file_storage.filename or ""
    if not filename:
        return None, "No judge bundle selected."
    try:
        payload = file_storage.read(JUDGE_BUNDLE_MAX_BYTES + 1)
    except Exception:
        return None, "Unable to read the judge bundle."
    if payload is None:
        return None, "Unable to read the judge bundle."
    if len(payload) > JUDGE_BUNDLE_MAX_BYTES:
        return None, f"Judge bundle must be {JUDGE_BUNDLE_MAX_MB} MB or smaller."
    return _save_project_task_bundle_from_bytes(
        task,
        filename,
        payload,
        content_type=(file_storage.mimetype or ""),
        existing_info=existing_info,
    )

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
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
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
    try:
        file_storage.stream.seek(0, os.SEEK_END)
        size = file_storage.stream.tell()
        file_storage.stream.seek(0)
    except Exception:
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
    except Exception:
        return None, "Unable to save file."
    rel_path = os.path.relpath(full_path, UPLOAD_ROOT)
    file_info = {
        "original_name": original_name or safe_name,
        "stored_name": stored_name,
        "path": rel_path,
        "size": size or os.path.getsize(full_path),
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "content_type": file_storage.mimetype or "",
    }
    if existing_info:
        _remove_uploaded_file(existing_info)
    return file_info, None

def _png_dimensions_from_bytes(data):
    if not data or len(data) < 24:
        return None
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    if data[12:16] != b"IHDR":
        return None
    try:
        width, height = struct.unpack(">II", data[16:24])
    except Exception:
        return None
    if width <= 0 or height <= 0:
        return None
    return width, height

def _save_plot_artifact_upload(scope, question_id, file_storage):
    if not file_storage:
        return None, "Missing plot PNG."
    filename = file_storage.filename or ""
    if not filename:
        return None, "No plot PNG was submitted."
    try:
        payload = file_storage.read(PLOT_ARTIFACT_MAX_BYTES + 1)
    except Exception:
        return None, "Unable to read the uploaded plot."
    if not payload:
        return None, "The uploaded plot is empty."
    if len(payload) > PLOT_ARTIFACT_MAX_BYTES:
        return None, f"Plot PNG must be {PLOT_ARTIFACT_MAX_MB} MB or smaller."
    dims = _png_dimensions_from_bytes(payload)
    if not dims:
        return None, "Uploaded plot must be a valid PNG image."
    width, height = dims
    if width > PLOT_ARTIFACT_MAX_WIDTH or height > PLOT_ARTIFACT_MAX_HEIGHT:
        return None, (
            f"Plot PNG dimensions must be at most "
            f"{PLOT_ARTIFACT_MAX_WIDTH}x{PLOT_ARTIFACT_MAX_HEIGHT}."
        )
    if width * height > PLOT_ARTIFACT_MAX_PIXELS:
        return None, "Plot PNG is too large."

    question_slug = secure_filename(str(question_id)) or "plot"
    stored_name = f"{uuid.uuid4().hex}_{question_slug}.png"
    kind = (scope or {}).get("kind") or "exam"
    if kind == "project_task":
        upload_dir = os.path.join(
            UPLOAD_ROOT,
            "plot_artifacts",
            "project_tasks",
            str(scope.get("project_id") or 0),
            str(scope.get("task_id") or 0),
            str(scope.get("submission_id") or 0),
            question_slug,
        )
    else:
        upload_dir = os.path.join(
            UPLOAD_ROOT,
            "plot_artifacts",
            "exams",
            str(scope.get("exam_id") or 0),
            str(scope.get("submission_id") or 0),
            question_slug,
        )
    os.makedirs(upload_dir, exist_ok=True)
    full_path = os.path.join(upload_dir, stored_name)
    try:
        with open(full_path, "wb") as fh:
            fh.write(payload)
    except Exception:
        return None, "Unable to save the plot PNG."
    rel_path = os.path.relpath(full_path, UPLOAD_ROOT)
    return {
        "original_name": "plot.png",
        "stored_name": stored_name,
        "path": rel_path,
        "size": len(payload),
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "content_type": "image/png",
        "width": width,
        "height": height,
    }, None

def _normalize_plot_code(value):
    text = _coerce_string(value)
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)

def _plot_answer_code(answer):
    if isinstance(answer, dict):
        return _normalize_plot_code(answer.get("code"))
    return _normalize_plot_code(answer)

def _plot_answer_artifact(answer):
    if isinstance(answer, dict):
        return _extract_file_info(answer.get("artifact"))
    return None

def _plot_label(question, index):
    if isinstance(question, dict):
        title = _coerce_string(question.get("title")).strip()
        if title:
            return title
    return f"Question {index + 1}"

def _parse_plot_submission_meta(raw_value):
    if not raw_value:
        return {}
    try:
        data = json.loads(raw_value)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    meta = {}
    status = _coerce_string(data.get("status")).strip().lower()
    if status:
        meta["status"] = status[:32]
    stdout = _coerce_string(data.get("stdout"))
    if stdout:
        meta["stdout"] = stdout[:4000]
    error = _coerce_string(data.get("error"))
    if error:
        meta["error"] = error[:8000]
    code_snapshot = _coerce_string(data.get("code_snapshot"))
    if code_snapshot:
        meta["code_snapshot"] = _normalize_plot_code(code_snapshot)[:200000]
    try:
        plot_count = int(data.get("plot_count") or 0)
    except Exception:
        plot_count = 0
    if plot_count > 0:
        meta["plot_count"] = min(plot_count, 20)
    return meta

def _build_plot_answer_payload(code_text, artifact_info, meta, updated_at):
    payload = {
        "code": code_text,
        "artifact": artifact_info,
        "updated_at": updated_at,
    }
    if meta.get("status"):
        payload["status"] = meta["status"]
    if meta.get("stdout"):
        payload["stdout"] = meta["stdout"]
    if meta.get("error"):
        payload["error"] = meta["error"]
    if meta.get("plot_count"):
        payload["plot_count"] = meta["plot_count"]
    return payload

def _collect_plot_submission_updates(questions, answers, request_files, request_form, plot_scope, strict_code_match=True):
    answers = answers if isinstance(answers, dict) else {}
    updates = {}
    now_iso = datetime.utcnow().isoformat() + "Z"
    for idx, question in enumerate(questions or []):
        if not isinstance(question, dict) or question.get("type") != "plot":
            continue
        qid = str(question.get("id"))
        upload = request_files.get(f"plot_artifact_{qid}")
        if not (upload and getattr(upload, "filename", "")):
            continue
        current_answer = answers.get(qid, "")
        code_text = _plot_answer_code(current_answer)
        existing_artifact = _plot_answer_artifact(current_answer)
        meta = _parse_plot_submission_meta(request_form.get(f"plot_meta_{qid}"))
        code_snapshot = meta.get("code_snapshot")
        if strict_code_match and code_snapshot and code_snapshot != code_text:
            return None, f"{_plot_label(question, idx)}: rerun the plot after your latest code changes."
        artifact_info, error = _save_plot_artifact_upload(plot_scope, qid, upload)
        if error:
            return None, f"{_plot_label(question, idx)}: {error}"
        if existing_artifact and existing_artifact != artifact_info:
            _remove_uploaded_file(existing_artifact)
        payload_code = code_snapshot or code_text
        updates[qid] = _build_plot_answer_payload(payload_code, artifact_info, meta, now_iso)
    return updates, None

def _preserve_plot_answer_metadata(code_text, existing_answer):
    artifact = _plot_answer_artifact(existing_answer)
    if artifact and code_text == _plot_answer_code(existing_answer):
        payload = dict(existing_answer)
        payload["code"] = code_text
        return payload
    return code_text

def _prepare_plot_answers_for_submit(questions, answers, persisted_answers, request_files, request_form, plot_scope):
    prepared = dict(answers or {})
    persisted_answers = persisted_answers if isinstance(persisted_answers, dict) else {}
    plot_updates, error = _collect_plot_submission_updates(
        questions,
        prepared,
        request_files,
        request_form,
        plot_scope,
    )
    if error:
        return None, error
    prepared.update(plot_updates or {})
    now_iso = datetime.utcnow().isoformat() + "Z"
    for idx, question in enumerate(questions or []):
        if not isinstance(question, dict) or question.get("type") != "plot":
            continue
        qid = str(question.get("id"))
        current_answer = prepared.get(qid, "")
        prior_answer = persisted_answers.get(qid)
        code_text = _plot_answer_code(current_answer)

        artifact_info = _plot_answer_artifact(current_answer)
        if artifact_info and code_text == _plot_answer_code(current_answer):
            payload = dict(current_answer)
            payload["code"] = code_text
            payload.setdefault("updated_at", now_iso)
            prepared[qid] = payload
            continue

        prior_artifact = _plot_answer_artifact(prior_answer)
        if prior_artifact and code_text == _plot_answer_code(prior_answer):
            payload = dict(prior_answer)
            payload["code"] = code_text
            payload.setdefault("updated_at", now_iso)
            prepared[qid] = payload
            continue

        return None, f"{_plot_label(question, idx)}: run the code to generate a plot before submitting."
    return prepared, None

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
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
                other_student = Student.query.get(other_sub.student_id)
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
                other_student = Student.query.get(other_sub.student_id)
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

def _student_unseen_announcement_deliveries(student):
    if not student:
        return []
    return (
        AnnouncementDelivery.query
        .join(Announcement, Announcement.id == AnnouncementDelivery.announcement_id)
        .options(subqueryload(AnnouncementDelivery.announcement))
        .filter(
            AnnouncementDelivery.student_id == student.id,
            AnnouncementDelivery.seen_at.is_(None),
        )
        .order_by(Announcement.created_at.asc(), Announcement.id.asc(), AnnouncementDelivery.id.asc())
        .all()
    )

@app.context_processor
def inject_csrf():
    student = current_student()
    unseen_announcements = []
    if student and not current_user():
        unseen_announcements = _student_unseen_announcement_deliveries(student)
    return {
        "csrf_token": csrf_token,
        "student_unseen_announcements": unseen_announcements,
    }

# Markdown rendering helpers.
_MD_BLOCKED_URL_RE = re.compile(r"^(?:javascript|data|vbscript|file):", re.IGNORECASE)
_MD_EXTENSIONS = ["extra", "sane_lists", "nl2br"]


def _safe_markdown_url(url):
    value = (url or "").strip()
    if not value:
        return "#"
    return "#" if _MD_BLOCKED_URL_RE.match(value) else value


def _inline_md_basic(chunk: str) -> str:
    esc = str(escape(chunk or ""))
    esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
    esc = re.sub(r"~~([^~]+)~~", r"<del>\1</del>", esc)
    esc = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", esc)
    esc = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", esc)

    def replace_links(match):
        label = match.group(1)
        href = _safe_markdown_url(match.group(2))
        return (
            f'<a href="{escape(href)}" target="_blank" '
            f'rel="nofollow noopener noreferrer">{label}</a>'
        )

    esc = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", replace_links, esc)
    return esc


def _extract_math_blocks(raw):
    lines = raw.split("\n")
    out_lines = []
    math_blocks = {}
    in_math = False
    math_lines = []
    math_idx = 0

    def add_math_block(content):
        nonlocal math_idx
        token = f"@@MD_MATH_BLOCK_{math_idx}@@"
        math_idx += 1
        math_html = escape(content)
        math_blocks[token] = f"<div class=\"md-math\">$$\n{math_html}\n$$</div>"
        return token

    for line in lines:
        trimmed = line.strip()
        if in_math:
            if trimmed == "$$":
                out_lines.append(add_math_block("\n".join(math_lines)))
                in_math = False
                math_lines = []
                continue
            math_lines.append(line)
            continue
        single_line_math = re.match(r"^\s*\$\$(.+?)\$\$\s*$", line)
        if single_line_math:
            out_lines.append(add_math_block(single_line_math.group(1).strip()))
            continue
        if trimmed == "$$":
            in_math = True
            math_lines = []
            continue
        out_lines.append(line)

    if in_math:
        out_lines.append(add_math_block("\n".join(math_lines)))

    return "\n".join(out_lines), math_blocks


def _restore_math_blocks(rendered, math_blocks):
    if not math_blocks:
        return rendered
    html = rendered
    for token, replacement in math_blocks.items():
        html = html.replace(f"<p>{token}</p>", replacement)
        html = html.replace(token, replacement)
    return html


def _sanitize_md_html(rendered):
    if bleach is None:
        return rendered

    allowed_tags = set(getattr(bleach.sanitizer, "ALLOWED_TAGS", set()))
    allowed_tags.update(
        {
            "p", "br",
            "h1", "h2", "h3", "h4", "h5", "h6",
            "ul", "ol", "li",
            "pre", "code",
            "blockquote", "hr",
            "table", "thead", "tbody", "tr", "th", "td",
            "del",
            "img",
        }
    )
    allowed_attrs = dict(getattr(bleach.sanitizer, "ALLOWED_ATTRIBUTES", {}))
    allowed_attrs.update(
        {
            "a": ["href", "title", "rel", "target"],
            "code": ["class"],
            "img": ["src", "alt", "title"],
        }
    )
    allowed_protocols = set(getattr(bleach.sanitizer, "ALLOWED_PROTOCOLS", {"http", "https", "mailto"}))
    allowed_protocols.update({"http", "https", "mailto"})

    cleaned = bleach.clean(
        rendered,
        tags=allowed_tags,
        attributes=allowed_attrs,
        protocols=allowed_protocols,
        strip=True,
        strip_comments=True,
    )

    def link_attrs_callback(attrs, new=False):
        href = attrs.get((None, "href"), "")
        if not href:
            return attrs
        if _MD_BLOCKED_URL_RE.match(href):
            attrs[(None, "href")] = "#"
        attrs[(None, "target")] = "_blank"
        rel = set(str(attrs.get((None, "rel"), "")).split())
        rel.update({"nofollow", "noopener", "noreferrer"})
        attrs[(None, "rel")] = " ".join(sorted(rel))
        return attrs

    return bleach.linkify(cleaned, callbacks=[link_attrs_callback], skip_tags=["pre", "code"])


def _render_md_basic(raw):
    out = []
    list_kind = None
    in_code = False
    in_math = False
    code_lines = []
    code_lang = ""
    math_lines = []

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

        trimmed = line.strip()
        if not in_math:
            if trimmed.startswith("$$") and trimmed.endswith("$$") and len(trimmed) > 4:
                if list_kind:
                    out.append(f"</{list_kind}>")
                    list_kind = None
                content = trimmed[2:-2].strip()
                math_html = escape(content)
                out.append(f"<div class=\"md-math\">$$\n{math_html}\n$$</div>")
                continue
            if trimmed == "$$":
                if list_kind:
                    out.append(f"</{list_kind}>")
                    list_kind = None
                in_math = True
                math_lines = []
                continue
        else:
            if trimmed == "$$":
                math_html = escape("\n".join(math_lines))
                out.append(f"<div class=\"md-math\">$$\n{math_html}\n$$</div>")
                in_math = False
                math_lines = []
                continue
            math_lines.append(line)
            continue

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            if list_kind:
                out.append(f"</{list_kind}>")
                list_kind = None
            level = len(heading.group(1))
            content = _inline_md_basic(heading.group(2).strip())
            out.append(f"<h{level} class=\"md-heading\">{content}</h{level}>")
            continue

        unordered = re.match(r"^\s*[-*+]\s+(.*)$", line)
        ordered = re.match(r"^\s*\d+[.)]\s+(.*)$", line)
        if unordered or ordered:
            next_kind = "ul" if unordered else "ol"
            if list_kind and list_kind != next_kind:
                out.append(f"</{list_kind}>")
                list_kind = None
            if not list_kind:
                css_class = "md-list md-list-ol" if next_kind == "ol" else "md-list"
                out.append(f"<{next_kind} class=\"{css_class}\">")
                list_kind = next_kind
            item = unordered.group(1) if unordered else ordered.group(1)
            out.append(f"<li>{_inline_md_basic(item)}</li>")
        else:
            if list_kind:
                out.append(f"</{list_kind}>")
                list_kind = None
            if line.strip() == "":
                out.append("<br>")
            else:
                out.append(f"<p class=\"md-p\">{_inline_md_basic(line)}</p>")

    if in_code:
        lang_attr = f' data-lang="{escape(code_lang)}"' if code_lang else ""
        code_html = escape("\n".join(code_lines))
        out.append(f"<pre class=\"md-code\"><code{lang_attr}>{code_html}</code></pre>")
    if in_math:
        math_html = escape("\n".join(math_lines))
        out.append(f"<div class=\"md-math\">$$\n{math_html}\n$$</div>")
    if list_kind:
        out.append(f"</{list_kind}>")

    return "".join(out)


def _render_md_html(raw):
    if markdown_lib is None:
        return _render_md_basic(raw)
    try:
        source, math_blocks = _extract_math_blocks(raw)
        rendered = markdown_lib.markdown(source, extensions=_MD_EXTENSIONS, output_format="html5")
        rendered = _sanitize_md_html(rendered)
        return _restore_math_blocks(rendered, math_blocks)
    except Exception:
        return _render_md_basic(raw)


def render_md(text):
    if text is None:
        return Markup("")
    raw = str(text).replace("\r\n", "\n")
    html = _render_md_html(raw).strip()
    if not html:
        return Markup("")
    return Markup(f"<div class=\"md-block\">{html}</div>")


def render_md_inline(text):
    if text is None:
        return Markup("")
    raw = str(text).replace("\r\n", "\n")
    return Markup(_inline_md_basic(raw).replace("\n", "<br>"))

@app.template_filter("markdown")
def markdown_filter(text):
    return render_md(text)

@app.template_filter("markdown_inline")
def markdown_inline_filter(text):
    return render_md_inline(text)

@app.before_request
def update_student_last_seen():
    try:
        s = current_student()
    except Exception:
        s = None
    if not s:
        return
    now = datetime.utcnow()
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

@app.post("/api/student/ping")
def student_ping():
    student = current_student()
    if not student:
        abort(401)
    token = request.headers.get("X-CSRF", "")
    if not hmac.compare_digest(token, csrf_token()):
        abort(400, "bad csrf")
    now = datetime.utcnow()
    student.last_seen_at = now
    _touch_student_log_session(student, now)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({"ok": True})

@app.post("/student/announcements/mark-seen")
@require_student()
def student_announcements_mark_seen():
    if not verify_csrf():
        abort(400, "bad csrf")
    student = current_student()
    next_url = _safe_redirect_target(request.form.get("next"), fallback_endpoint="student_home")
    if not student:
        return redirect(next_url)
    delivery_ids = []
    for raw_id in request.form.getlist("announcement_ids"):
        try:
            delivery_ids.append(int(raw_id))
        except Exception:
            continue
    query = AnnouncementDelivery.query.filter(
        AnnouncementDelivery.student_id == student.id,
        AnnouncementDelivery.seen_at.is_(None),
    )
    if delivery_ids:
        query = query.filter(AnnouncementDelivery.id.in_(delivery_ids))
    deliveries = query.all()
    if deliveries:
        now = datetime.utcnow()
        for delivery in deliveries:
            delivery.seen_at = now
        db.session.commit()
    return redirect(next_url)

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
    if u and getattr(u, "role", "") == "mentor":
        return redirect(url_for("mentor_dashboard"))
    if u and getattr(u, "role", "") == "admin":
        return redirect(url_for("admin_review_dashboard"))
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

# --------------------------------------------------------------------
# Blog helpers and views
# --------------------------------------------------------------------

PAGE_SIZE = 10

def _is_staff(user):
    if not user:
        return False
    role = getattr(user, "role", "")
    return role in ("instructor", "admin", "mentor", "staff")

def _safe_redirect_target(raw_path, fallback_endpoint="index"):
    target = (raw_path or "").strip()
    if target.startswith("/") and not target.startswith("//"):
        return target
    return url_for(fallback_endpoint)

def _announcement_target_label(announcement):
    if announcement.target_group and announcement.target_group.name:
        return announcement.target_group.name
    if announcement.target_group_name:
        return announcement.target_group_name
    return "All students"

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
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
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
        q_type = _normalize_question_type_name(_first_present(raw, "type", "question_type", "kind"))
        if q_type not in ("mcq", "multi", "text", "code", "plot", "tokens", "fill", "file"):
            raise ValueError(f"Unsupported question type '{q_type}'.")
        prompt_value = _first_present(raw, "prompt", "question", "question_text")
        if not prompt_value and q_type in ("code", "plot"):
            prompt_value = _first_present(raw, "statement", "problem_statement", "description")
        prompt = _coerce_string(prompt_value).strip()
        if not prompt:
            raise ValueError("Every question needs a prompt.")
        q_id = _coerce_string(_first_present(raw, "id", "question_id")).strip() or f"q{idx+1}"
        if q_id in seen:
            q_id = f"{q_id}_{idx+1}"
        seen.add(q_id)
        normalized = {"id": q_id, "type": q_type, "prompt": prompt}
        title = _coerce_string(_first_present(raw, "title", "name", "label")).strip()
        if title:
            normalized["title"] = title
        snippet = _first_present(raw, "code_snippet", "context_code", "reference_code")
        if snippet is not None:
            snippet_text = _coerce_string(snippet).strip("\n")
            if snippet_text:
                normalized["code_snippet"] = snippet_text
        try:
            points = int(_first_present(raw, "points", "score", "max_points") or 1)
        except Exception:
            points = 1
        normalized["points"] = max(0, points)

        if q_type in ("mcq", "multi"):
            options_raw = _first_present(raw, "options", "choices") or []
            options, implied_correct = _extract_choice_options(options_raw)
            if len(options) < 2:
                raise ValueError("Multiple-choice questions need at least two options.")
            normalized["options"] = options
            normalized["shuffle"] = _coerce_bool(_first_present(raw, "shuffle", "shuffle_options"), False)
            correct_raw = _first_present(raw, "correct_indices", "correct_option_indexes", "correct_indexes")
            correct_indices = _coerce_int_list(correct_raw)
            if not correct_indices and implied_correct:
                correct_indices = implied_correct
            if not correct_indices:
                correct_labels = _coerce_token_list(_first_present(raw, "correct_options", "correct_answers"))
                for label in correct_labels:
                    try:
                        correct_indices.append(options.index(label))
                    except ValueError:
                        continue
            correct_indices = [idx_val for idx_val in correct_indices if 0 <= idx_val < len(options)]
            correct_indices = list(dict.fromkeys(correct_indices))
            if q_type == "mcq":
                if len(correct_indices) != 1:
                    raise ValueError("Provide exactly one correct option index for MCQ questions.")
            else:
                if not correct_indices:
                    raise ValueError("Provide at least one correct option index for multi-select questions.")
            normalized["correct_indices"] = correct_indices
        elif q_type == "text":
            normalized["placeholder"] = _coerce_string(_first_present(raw, "placeholder", "answer_placeholder", "response_placeholder")).strip()
            lines_raw = _first_present(raw, "lines", "rows", "answer_lines")
            try:
                line_count = int(lines_raw) if lines_raw not in (None, "") else 4
            except Exception:
                line_count = 4
            normalized["lines"] = max(1, min(line_count, 12))
        elif q_type == "tokens":
            template = _coerce_string(_first_present(raw, "template", "expression_template", "text_template")).strip()
            if "[[blank]]" not in template:
                raise ValueError("Token questions require [[blank]] markers.")
            blank_count = template.count("[[blank]]")
            correct_raw = _first_present(raw, "correct_tokens", "answers", "expected_tokens") or ""
            tokens = _coerce_token_list(correct_raw)
            if len(tokens) != blank_count:
                raise ValueError("Provide one correct token for each [[blank]].")
            distractor_raw = _first_present(raw, "distractor_tokens", "distractors", "extra_tokens") or ""
            distractors = _coerce_token_list(distractor_raw)
            normalized["template"] = template
            normalized["correct_tokens"] = tokens
            normalized["distractor_tokens"] = distractors
        elif q_type == "fill":
            template = _coerce_string(_first_present(raw, "template", "expression_template", "text_template")).strip()
            if "[[blank]]" not in template:
                raise ValueError("Fill questions require [[blank]] markers.")
            blank_count = template.count("[[blank]]")
            answers_raw = _first_present(raw, "answers", "correct_answers", "expected_answers") or ""
            answers = _coerce_token_list(answers_raw)
            if len(answers) != blank_count:
                raise ValueError("Provide one answer per [[blank]].")
            normalized["template"] = template
            normalized["answers"] = answers
            normalized["case_sensitive"] = _coerce_bool(_first_present(raw, "case_sensitive", "match_case"), False)
        elif q_type == "file":
            accept_raw = _first_present(raw, "accept", "accepted_extensions")
            if isinstance(accept_raw, list):
                accept = ", ".join(_coerce_token_list(accept_raw)).strip() or ".zip"
            else:
                accept = _coerce_string(accept_raw).strip() or ".zip"
            try:
                max_mb = int(_first_present(raw, "max_mb", "max_size_mb") or 5)
            except Exception:
                max_mb = 5
            normalized["accept"] = accept
            normalized["max_mb"] = max(1, min(max_mb, UPLOAD_MAX_MB))
        elif q_type == "plot":
            statement = _coerce_string(_first_present(raw, "statement", "problem_statement", "description")).strip()
            if not statement:
                raise ValueError("Plot questions need a statement/description.")
            normalized["statement"] = statement
            normalized["starter"] = _coerce_string(_first_present(raw, "starter", "starter_code", "starter_template"))
            normalized["language"] = "python"
        else:  # code
            statement = _coerce_string(_first_present(raw, "statement", "problem_statement", "description")).strip()
            if not statement:
                raise ValueError("Code questions need a statement/description.")
            normalized["statement"] = statement
            normalized["starter"] = _coerce_string(_first_present(raw, "starter", "starter_code", "starter_template"))
            normalized["language"] = "python"
            mode = _normalize_code_mode_name(_first_present(raw, "mode", "code_mode") or "script")
            if mode not in ("script", "function", "class"):
                mode = "script"
            normalized["mode"] = mode
            samples_clean = []
            hidden_tests_clean = []
            samples_raw = _first_present(raw, "samples", "tests", "test_cases") or []
            hidden_tests_raw = _first_present(raw, "hidden_tests", "private_tests", "hidden_tests_json")
            if mode == "function":
                signature = _coerce_string(_first_present(raw, "function_signature", "signature", "callable_signature")).strip()
                if not signature.startswith("def"):
                    raise ValueError("Function questions need a signature like 'def foo(x):'.")
                normalized["function_signature"] = signature
                if isinstance(samples_raw, list):
                    for s_idx, sample in enumerate(samples_raw):
                        if not isinstance(sample, dict):
                            continue
                        call_expr = _coerce_string(_first_present(sample, "call", "function_call", "expression", "input")).strip()
                        if not call_expr:
                            continue
                        name = _coerce_string(_first_present(sample, "name", "label")).strip() or f"Sample {s_idx+1}"
                        expected = _coerce_code_expected(_first_present(sample, "expected", "expected_return", "expected_result", "output"))
                        compare_mode, tolerance = _sample_compare_settings(sample, "callable")
                        if compare_mode == "numeric_tolerance":
                            try:
                                _validate_numeric_tolerance_expected(expected)
                            except ValueError as exc:
                                raise ValueError(f"{name}: {exc}")
                        sample_clean = {
                            "name": name,
                            "call": call_expr,
                            "expected": expected,
                            "input": call_expr,
                            "compare_mode": compare_mode,
                            "hidden": _coerce_bool(_first_present(sample, "hidden", "is_hidden"), False),
                        }
                        if tolerance is not None:
                            sample_clean["tolerance"] = tolerance
                        samples_clean.append(sample_clean)
                hidden_tests_clean = _normalize_hidden_code_tests(hidden_tests_raw, mode)
                if not samples_clean and not hidden_tests_clean:
                    raise ValueError("Function code questions need at least one sample call.")
            elif mode == "class":
                class_signature = _coerce_string(_first_present(raw, "class_signature", "signature")).strip()
                if not class_signature.startswith("class"):
                    raise ValueError("Class code questions need a signature like 'class Foo:'.")
                class_init = _coerce_string(_first_present(raw, "class_init", "init_call", "constructor_call", "object_initializer")).strip()
                if not class_init:
                    raise ValueError("Class code questions need an __init__ call like 'Foo(1, 2)'.")
                normalized["class_signature"] = class_signature
                normalized["class_init"] = class_init
                if isinstance(samples_raw, list):
                    for s_idx, sample in enumerate(samples_raw):
                        if not isinstance(sample, dict):
                            continue
                        call_expr = _coerce_string(_first_present(sample, "call", "method_call", "expression", "input")).strip()
                        if not call_expr:
                            continue
                        name = _coerce_string(_first_present(sample, "name", "label")).strip() or f"Method test {s_idx+1}"
                        expected = _coerce_code_expected(_first_present(sample, "expected", "expected_return", "expected_result", "output"))
                        sample_init = _coerce_string(_first_present(sample, "init_call", "constructor_call", "object_initializer")).strip() or class_init
                        compare_mode, tolerance = _sample_compare_settings(sample, "callable")
                        if compare_mode == "numeric_tolerance":
                            try:
                                _validate_numeric_tolerance_expected(expected)
                            except ValueError as exc:
                                raise ValueError(f"{name}: {exc}")
                        sample_clean = {
                            "name": name,
                            "call": call_expr,
                            "expected": expected,
                            "input": call_expr,
                            "init_call": sample_init,
                            "compare_mode": compare_mode,
                            "hidden": _coerce_bool(_first_present(sample, "hidden", "is_hidden"), False),
                        }
                        if tolerance is not None:
                            sample_clean["tolerance"] = tolerance
                        samples_clean.append(sample_clean)
                hidden_tests_clean = _normalize_hidden_code_tests(hidden_tests_raw, mode, class_init=class_init)
                if not samples_clean and not hidden_tests_clean:
                    raise ValueError("Class code questions need at least one method call.")
            else:
                if isinstance(samples_raw, list):
                    for s_idx, sample in enumerate(samples_raw):
                        if not isinstance(sample, dict):
                            continue
                        name = _coerce_string(_first_present(sample, "name", "label")).strip() or f"Sample {s_idx+1}"
                        compare_mode, _ = _sample_compare_settings(sample, "script")
                        samples_clean.append({
                            "name": name,
                            "input": _coerce_string(_first_present(sample, "input", "stdin")),
                            "output": _coerce_string(_first_present(sample, "output", "expected_stdout", "expected")),
                            "compare_mode": compare_mode,
                            "hidden": _coerce_bool(_first_present(sample, "hidden", "is_hidden"), False),
                        })
                hidden_tests_clean = _normalize_hidden_code_tests(hidden_tests_raw, mode)
            normalized["samples"] = samples_clean
            if hidden_tests_clean:
                normalized["hidden_tests"] = hidden_tests_clean

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

def _submission_judge_snapshot(submission, latest_attempt=None):
    if not submission:
        return {
            "judge_state": None,
            "judge_verdict": None,
            "judge_feedback": None,
            "judge_summary": None,
        }
    attempt = latest_attempt if latest_attempt is not None else _latest_task_attempt(submission)
    judge_state = getattr(attempt, "judge_state", None) or getattr(submission, "judge_state", None)
    judge_verdict = getattr(attempt, "judge_verdict", None) or getattr(submission, "judge_verdict", None)
    judge_feedback = getattr(attempt, "judge_feedback", None) or getattr(submission, "judge_feedback", None)
    judge_summary = getattr(attempt, "judge_summary_json", None) or getattr(submission, "judge_summary_json", None)
    return {
        "judge_state": judge_state,
        "judge_verdict": judge_verdict,
        "judge_feedback": judge_feedback,
        "judge_summary": judge_summary,
    }

def _result_is_judge_configuration_error(result):
    text = _coerce_string((result or {}).get("error")).lower()
    markers = (
        "judge bundle",
        "stdin_file",
        "expected_file",
        "hidden test file",
        "hidden tests that use",
        "hidden tests that mount",
        "invalid hidden test target path",
    )
    return any(marker in text for marker in markers)

def _hidden_test_feedback_from_result(result, test_index):
    status = (result or {}).get("status") or "error"
    if _result_is_judge_configuration_error(result):
        return "judge_error", "Judge failed. Try again later."
    if status == "timeout":
        return "time_limit_exceeded", f"Time limit exceeded on hidden test {test_index}."
    if status == "mismatch":
        return "wrong_answer", f"Wrong answer on hidden test {test_index}."
    if status == "error":
        return "runtime_error", f"Runtime error on hidden test {test_index}."
    return "judge_error", "Judge failed. Try again later."

def _run_hidden_code_tests_for_question(code_text, question, bundle_root=None):
    tests = _code_question_hidden_tests(question)
    mode = _normalize_code_mode_name(question.get("mode") or "script")
    if not tests:
        return {
            "verdict": "accepted",
            "feedback": "Accepted.",
            "hidden_passed": 0,
            "hidden_total": 0,
            "timed_out": False,
        }
    hidden_passed = 0
    hidden_total = len(tests)
    timed_out = False
    for idx, test in enumerate(tests, start=1):
        case_results, case_timed_out = _run_code_tests_backend(code_text, [test], mode, bundle_root=bundle_root)
        timed_out = timed_out or case_timed_out
        if case_results:
            result = case_results[0]
        else:
            result = {
                "name": test.get("name") or f"Hidden test {idx}",
                "status": "error",
                "error": "No results from worker process",
            }
        if result.get("status") == "passed":
            hidden_passed += 1
            continue
        verdict, feedback = _hidden_test_feedback_from_result(result, idx)
        summary = {
            "verdict": verdict,
            "feedback": feedback,
            "hidden_passed": hidden_passed,
            "hidden_total": hidden_total,
            "failed_test_index": idx,
            "failed_test_name": result.get("name") or f"Hidden test {idx}",
            "timed_out": timed_out or verdict == "time_limit_exceeded",
        }
        return summary
    return {
        "verdict": "accepted",
        "feedback": f"Accepted. Passed {hidden_total} hidden test{'s' if hidden_total != 1 else ''}.",
        "hidden_passed": hidden_passed,
        "hidden_total": hidden_total,
        "timed_out": False,
    }

def _grade_project_task_submission_with_hidden_tests(task, answers, bundle_root=None):
    questions = task.questions_json if isinstance(task.questions_json, list) else []
    answer_map = answers if isinstance(answers, dict) else {}
    earned = 0.0
    total = 0.0
    details = []
    question_summaries = []
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
        elif qtype == "plot":
            res["manual_review"] = True
        elif qtype == "code":
            if _code_question_has_hidden_tests(q):
                summary = _run_hidden_code_tests_for_question(raw_answer, q, bundle_root=bundle_root)
                if summary.get("verdict") == "accepted":
                    res["earned"] = points
                res["judge_verdict"] = summary.get("verdict")
                res["judge_feedback"] = summary.get("feedback")
                res["hidden_passed"] = summary.get("hidden_passed", 0)
                res["hidden_total"] = summary.get("hidden_total", 0)
                res["timed_out"] = bool(summary.get("timed_out"))
                question_summaries.append({
                    "question_id": qid,
                    "verdict": summary.get("verdict"),
                    "feedback": summary.get("feedback"),
                    "hidden_passed": summary.get("hidden_passed", 0),
                    "hidden_total": summary.get("hidden_total", 0),
                    "failed_test_index": summary.get("failed_test_index"),
                })
            else:
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

    first_failure = next((item for item in question_summaries if item.get("verdict") != "accepted"), None)
    if first_failure:
        overall_verdict = first_failure.get("verdict")
        overall_feedback = first_failure.get("feedback")
    else:
        total_hidden = sum(int(item.get("hidden_total") or 0) for item in question_summaries)
        overall_verdict = "accepted"
        if total_hidden > 0:
            overall_feedback = f"Accepted. Passed {total_hidden} hidden test{'s' if total_hidden != 1 else ''}."
        else:
            overall_feedback = "Accepted."
    judge_summary = {
        "verdict": overall_verdict,
        "feedback": overall_feedback,
        "question_summaries": question_summaries,
        "judged_at": datetime.utcnow().isoformat() + "Z",
    }
    return earned, total, details, judge_summary

def _enqueue_project_task_judge(submission, attempt):
    if not submission or not attempt:
        return None
    now = datetime.utcnow()
    submission.judge_state = "queued"
    submission.judge_verdict = None
    submission.judge_feedback = "Queued for hidden tests."
    submission.judge_summary_json = {
        "verdict": None,
        "feedback": "Queued for hidden tests.",
        "queued_at": now.isoformat() + "Z",
    }
    attempt.judge_state = "queued"
    attempt.judge_verdict = None
    attempt.judge_feedback = "Queued for hidden tests."
    attempt.judge_summary_json = {
        "verdict": None,
        "feedback": "Queued for hidden tests.",
        "queued_at": now.isoformat() + "Z",
    }
    job = JudgeJob(
        submission_id=submission.id,
        attempt_id=attempt.id,
        task_id=submission.task_id,
        student_id=submission.student_id,
        status="queued",
        payload_json={
            "attempt_number": attempt.attempt_number,
            "project_id": submission.project_id,
        },
    )
    db.session.add(job)
    return job

def _apply_project_task_judge_result(submission, attempt, task, grade_score, grade_total, grade_details, judge_summary):
    now = datetime.utcnow()
    if not submission or not attempt or not task:
        return
    has_manual_review = any(detail.get("manual_review") for detail in (grade_details or []))
    verdict = _coerce_string((judge_summary or {}).get("verdict")).strip() or None
    feedback = _coerce_string((judge_summary or {}).get("feedback")).strip() or None
    if verdict == "accepted":
        if task.requires_review or has_manual_review:
            final_status = "pending_review"
            if task.requires_review or has_manual_review:
                feedback = "Passed hidden tests. Waiting for review."
        else:
            final_status = "accepted"
    elif verdict == "judge_error":
        final_status = "rejected"
    else:
        final_status = "rejected"

    submission.score = grade_score
    submission.max_score = grade_total
    submission.status = final_status
    submission.last_activity_at = now
    submission.judge_state = "done"
    submission.judge_verdict = verdict
    submission.judge_feedback = feedback
    submission.judge_summary_json = judge_summary or None

    attempt.score = grade_score
    attempt.max_score = grade_total
    attempt.status = final_status
    attempt.grading_json = grade_details or None
    attempt.judge_state = "done"
    attempt.judge_verdict = verdict
    attempt.judge_feedback = feedback
    attempt.judge_summary_json = judge_summary or None

def _run_project_task_judge_job(job_id):
    job = JudgeJob.query.get(job_id)
    if not job:
        return False
    submission = ProjectTaskSubmission.query.get(job.submission_id)
    attempt = ProjectTaskAttempt.query.get(job.attempt_id)
    task = ProjectTask.query.get(job.task_id)
    if not submission or not attempt or not task:
        raise RuntimeError("Judge job is missing submission, attempt, or task data.")

    answers = attempt.answers_json if isinstance(attempt.answers_json, dict) else submission.answers_json
    bundle_temp = None
    bundle_root = None
    try:
        bundle_temp, bundle_root = _extract_judge_bundle_to_tempdir(task)
        grade_score, grade_total, grade_details, judge_summary = _grade_project_task_submission_with_hidden_tests(
            task,
            answers,
            bundle_root=bundle_root,
        )
    finally:
        if bundle_temp:
            bundle_temp.cleanup()

    _apply_project_task_judge_result(submission, attempt, task, grade_score, grade_total, grade_details, judge_summary)
    if submission.status == "accepted" and submission.student and submission.project:
        if _project_completed(submission.project, submission.student):
            _award_project_points_if_needed(submission.project, submission.student)
    return True

def run_next_judge_job():
    job = JudgeJob.query.filter_by(status="queued").order_by(JudgeJob.created_at.asc(), JudgeJob.id.asc()).first()
    if not job:
        return False
    job.status = "running"
    job.started_at = datetime.utcnow()
    submission = ProjectTaskSubmission.query.get(job.submission_id)
    attempt = ProjectTaskAttempt.query.get(job.attempt_id)
    if submission:
        submission.judge_state = "running"
        submission.judge_feedback = "Running hidden tests."
        submission.judge_summary_json = {
            "verdict": None,
            "feedback": "Running hidden tests.",
            "started_at": job.started_at.isoformat() + "Z",
        }
    if attempt:
        attempt.judge_state = "running"
        attempt.judge_feedback = "Running hidden tests."
        attempt.judge_summary_json = {
            "verdict": None,
            "feedback": "Running hidden tests.",
            "started_at": job.started_at.isoformat() + "Z",
        }
    db.session.commit()

    try:
        _run_project_task_judge_job(job.id)
        job.status = "done"
        job.finished_at = datetime.utcnow()
        job.error_text = None
    except Exception:
        job.status = "failed"
        job.finished_at = datetime.utcnow()
        job.error_text = traceback.format_exc()
        submission = ProjectTaskSubmission.query.get(job.submission_id)
        attempt = ProjectTaskAttempt.query.get(job.attempt_id)
        judge_summary = {
            "verdict": "judge_error",
            "feedback": "Judge failed. Try again later.",
            "judged_at": job.finished_at.isoformat() + "Z",
        }
        if submission:
            submission.status = "rejected"
            submission.judge_state = "failed"
            submission.judge_verdict = "judge_error"
            submission.judge_feedback = "Judge failed. Try again later."
            submission.judge_summary_json = judge_summary
        if attempt:
            attempt.status = "rejected"
            attempt.judge_state = "failed"
            attempt.judge_verdict = "judge_error"
            attempt.judge_feedback = "Judge failed. Try again later."
            attempt.judge_summary_json = judge_summary
    db.session.commit()
    return True

def run_judge_worker(poll_seconds=JUDGE_WORKER_POLL_SEC, once=False):
    while True:
        processed = run_next_judge_job()
        if once:
            return processed
        if not processed:
            time.sleep(max(float(poll_seconds or JUDGE_WORKER_POLL_SEC), 0.25))

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
    attempt.reviewed_at = datetime.utcnow()

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

def _complete_tutorial_task(project, task, student):
    if not project or not task or not student:
        return None
    now = datetime.utcnow()
    submission = _project_task_submission(task, student)
    if not submission:
        submission = ProjectTaskSubmission(
            task_id=task.id,
            project_id=project.id,
            student_id=student.id,
            student_name=student.name,
            answers_json={},
            run_logs=[],
            status="accepted",
            score=0.0,
            max_score=0.0,
            started_at=now,
            submitted_at=now,
            last_activity_at=now,
        )
        db.session.add(submission)
    else:
        submission.answers_json = submission.answers_json if isinstance(submission.answers_json, dict) else {}
        submission.run_logs = submission.run_logs if isinstance(submission.run_logs, list) else []
        submission.status = "accepted"
        submission.score = 0.0
        submission.max_score = 0.0
        if not submission.submitted_at:
            submission.submitted_at = now
        submission.last_activity_at = now
    return submission

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

def _mentor_group_ids(user):
    if not user or getattr(user, "role", "") != "mentor":
        return None
    return {review.group_id for review in getattr(user, "group_reviews", []) if review.group_id}

def _restricted_review_student_ids(user):
    """Return the student ids a mentor may access; None means unrestricted."""
    group_ids = _mentor_group_ids(user)
    if group_ids is None:
        return None
    if not group_ids:
        return set()
    memberships = StudentGroupMembership.query.filter(StudentGroupMembership.group_id.in_(group_ids)).all()
    return {membership.student_id for membership in memberships if membership.student_id}

def _review_scope_limited(user, allowed_student_ids=None):
    if allowed_student_ids is None:
        allowed_student_ids = _restricted_review_student_ids(user)
    return allowed_student_ids is not None

def _apply_review_scope_to_submission_query(query, user, allowed_student_ids=None):
    if allowed_student_ids is None:
        allowed_student_ids = _restricted_review_student_ids(user)
    if allowed_student_ids is None:
        return query
    if not allowed_student_ids:
        return query.filter(ProjectTaskSubmission.id == -1)
    return query.filter(ProjectTaskSubmission.student_id.in_(allowed_student_ids))

def _apply_review_scope_to_student_query(query, user, allowed_student_ids=None):
    if allowed_student_ids is None:
        allowed_student_ids = _restricted_review_student_ids(user)
    if allowed_student_ids is None:
        return query
    if not allowed_student_ids:
        return query.filter(Student.id == -1)
    return query.filter(Student.id.in_(allowed_student_ids))

def _can_user_review_student(user, student, allowed_student_ids=None):
    if allowed_student_ids is None:
        allowed_student_ids = _restricted_review_student_ids(user)
    if allowed_student_ids is None:
        return True
    if not student or not student.id:
        return False
    return student.id in allowed_student_ids

def _can_user_review_submission(user, submission, allowed_student_ids=None):
    if not submission:
        return False
    return _can_user_review_student(user, submission.student, allowed_student_ids=allowed_student_ids)

def _can_user_manage_private_note(user, note, allowed_student_ids=None):
    if not user or not note:
        return False
    if not _can_user_review_student(user, note.student, allowed_student_ids=allowed_student_ids):
        return False
    if getattr(user, "role", "") == "mentor":
        return note.author_user_id == user.id
    return True

def _visible_groups_for_student(user, student, mentor_group_ids=None):
    groups = [group for group in getattr(student, "groups", []) if group] if student else []
    if mentor_group_ids is None:
        mentor_group_ids = _mentor_group_ids(user)
    if mentor_group_ids is None:
        return sorted(groups, key=lambda group: ((group.name or "").lower(), group.id))
    return sorted(
        [group for group in groups if group.id in mentor_group_ids],
        key=lambda group: ((group.name or "").lower(), group.id),
    )

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

def _median(values):
    cleaned = sorted(
        float(value)
        for value in (values or [])
        if value is not None
    )
    if not cleaned:
        return None
    mid = len(cleaned) // 2
    if len(cleaned) % 2 == 1:
        return cleaned[mid]
    return (cleaned[mid - 1] + cleaned[mid]) / 2.0

def _review_wait_seconds(attempt):
    if not attempt or not attempt.reviewed_at:
        return None
    submitted_at = getattr(attempt, "submitted_at", None)
    if not submitted_at and getattr(attempt, "submission", None):
        submitted_at = attempt.submission.submitted_at
    if not submitted_at:
        return None
    return max(0.0, (attempt.reviewed_at - submitted_at).total_seconds())

def _pending_review_age_seconds(submission, now=None):
    if not submission:
        return None
    now = now or datetime.utcnow()
    submitted_at = submission.submitted_at or submission.last_activity_at or submission.started_at
    if not submitted_at:
        return None
    return max(0.0, (now - submitted_at).total_seconds())

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
    now = datetime.utcnow()
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
    if isinstance(config, list):
        tasks_data = config
    elif isinstance(config, dict):
        tasks_data = _first_present(config, "tasks", "project_tasks", "items")
    else:
        raise ValueError("Config must be a JSON object or an array of tasks.")
    if not isinstance(tasks_data, list) or not tasks_data:
        raise ValueError("Config must include a non-empty 'tasks' array.")
    existing = ProjectTask.query.filter_by(project_id=project.id).count() or 0
    new_tasks = []
    for offset, entry in enumerate(tasks_data, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Task #{offset} must be an object.")
        task_kind = _normalize_task_kind_name(_first_present(entry, "task_kind", "task_type", "mode", "kind"))
        if task_kind not in ("assessment", "tutorial"):
            raise ValueError(f"Task #{offset} has unsupported task_kind '{task_kind}'.")
        title = _coerce_string(_first_present(entry, "title", "name")).strip()
        if not title:
            raise ValueError(f"Task #{offset} is missing a title.")
        description = _coerce_string(_first_present(entry, "description", "summary")).strip()
        instructions = _coerce_string(
            _first_present(
                entry,
                "instructions",
                "student_instructions",
                "tutorial_markdown",
                "content_markdown",
                "content",
                "body",
            )
        ).strip()
        questions = []
        questions_payload = _first_present(entry, "questions", "items")
        requires_review = False
        auto_grade = False
        if task_kind == "tutorial":
            if isinstance(questions_payload, list) and questions_payload:
                raise ValueError(f"Task '{title}': tutorial tasks cannot define questions.")
            if not instructions:
                raise ValueError(f"Task '{title}': tutorial tasks need markdown content in 'instructions' or 'tutorial_markdown'.")
        else:
            if not isinstance(questions_payload, list) or not questions_payload:
                raise ValueError(f"Task '{title}' must include a non-empty 'questions' array.")
            try:
                questions = _normalize_exam_questions(questions_payload)
            except ValueError as exc:
                raise ValueError(f"Task '{title}': {exc}")
            except Exception:
                raise ValueError(f"Task '{title}': unable to parse questions.")
            requires_review = _coerce_bool(_first_present(entry, "requires_review", "mentor_review", "manual_review"), False)
            auto_grade = _coerce_bool(_first_present(entry, "auto_grade", "autograde", "automatic_grading"), True)
        task = ProjectTask(
            project_id=project.id,
            task_kind=task_kind,
            title=title,
            description=description or None,
            instructions=instructions or None,
            questions_json=questions,
            required=_coerce_bool(_first_present(entry, "required", "is_required"), True),
            auto_grade=auto_grade,
            requires_review=requires_review,
            order_index=existing + offset,
        )
        new_tasks.append(task)
    for task in new_tasks:
        db.session.add(task)
    return new_tasks

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
        elif qtype == "plot":
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

# Allow a small safe subset of imports used in coursework and plotting
ALLOWED_CODE_IMPORTS = {"collections", "numpy", "matplotlib", "math"}

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level and level > 0:
        raise ImportError("Relative imports are not allowed.")
    base = (name or "").split(".")[0]
    if base not in ALLOWED_CODE_IMPORTS:
        raise ImportError(f"Import of '{name}' is not allowed.")
    module = importlib.import_module(name)
    # Emulate default __import__ return behavior
    if fromlist:
        return module
    return importlib.import_module(base)

SAFE_CODE_BUILTINS["__import__"] = _safe_import

def _build_guarded_open(allowed_root):
    root = os.path.abspath(allowed_root or "")
    if not root:
        raise RuntimeError("open() is not available for this problem.")

    def _guarded_open(file, mode="r", *args, **kwargs):
        mode = _coerce_string(mode or "r")
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise PermissionError("open() is read-only in this problem.")
        path_value = _coerce_string(file).strip()
        if not path_value:
            raise FileNotFoundError("Empty file path.")
        safe_target = _safe_path_within(root, path_value)
        if not safe_target:
            raise PermissionError("File access outside the testcase workspace is not allowed.")
        return builtins.open(safe_target, mode, *args, **kwargs)

    return _guarded_open

def safe_env(allowed_open_root=None):
    """
    Return a fresh environment dict with safe builtins.
    """
    env_builtins = dict(SAFE_CODE_BUILTINS)
    if allowed_open_root:
        env_builtins["open"] = _build_guarded_open(allowed_open_root)
    return {"__builtins__": env_builtins}

def _init_plot_backend():
    try:
        import matplotlib
        matplotlib.use("Agg")
    except Exception:
        return False
    return True

def _collect_plot_images():
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return []
    images = []
    try:
        for num in plt.get_fignums():
            fig = plt.figure(num)
            buf = io.BytesIO()
            original_size = None
            try:
                width, height = fig.get_size_inches()
                if width > 0 and height > 0:
                    scale = min(
                        PLOT_EXPORT_MAX_WIDTH_IN / width,
                        PLOT_EXPORT_MAX_HEIGHT_IN / height,
                        1.0,
                    )
                    if scale < 1.0:
                        original_size = (width, height)
                        fig.set_size_inches(width * scale, height * scale, forward=False)
            except Exception:
                original_size = None
            fig.savefig(
                buf,
                format="png",
                bbox_inches="tight",
                pad_inches=0.1,
                dpi=PLOT_EXPORT_DPI,
            )
            if original_size:
                fig.set_size_inches(*original_size, forward=False)
            images.append(base64.b64encode(buf.getvalue()).decode("ascii"))
        plt.close("all")
    except Exception:
        try:
            plt.close("all")
        except Exception:
            pass
    return images

def _run_in_workspace(workdir, callback):
    if not workdir:
        return callback()
    previous_cwd = os.getcwd()
    os.chdir(workdir)
    try:
        return callback()
    finally:
        os.chdir(previous_cwd)

def _test_timeout_seconds(test):
    timeout_ms = _coerce_timeout_ms(_first_present(test, "timeout_ms", "timeout", "time_limit_ms"))
    if timeout_ms is None:
        return float(CODE_RUN_TIME_LIMIT_SEC)
    return max(float(timeout_ms) / 1000.0, 0.05)

def _test_needs_workspace(test):
    if not isinstance(test, dict):
        return False
    if _coerce_string(test.get("stdin_file")).strip():
        return True
    if _coerce_string(test.get("expected_file")).strip():
        return True
    return bool(test.get("files"))

def _read_workspace_text_file(base_root, relative_path, label):
    safe_path = _safe_path_within(base_root, relative_path)
    if not safe_path or not os.path.isfile(safe_path):
        raise FileNotFoundError(f"{label} '{relative_path}' was not found in the judge bundle.")
    try:
        with open(safe_path, "r", encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(safe_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

def _prepare_code_test_workspace(test, bundle_root=None):
    workspace = tempfile.TemporaryDirectory()
    workdir = workspace.name
    for idx, file_spec in enumerate(test.get("files") or [], start=1):
        source_rel = _coerce_string(file_spec.get("source")).strip()
        target_rel = _coerce_string(file_spec.get("target")).strip() or os.path.basename(source_rel)
        if not source_rel:
            workspace.cleanup()
            raise ValueError(f"Hidden test file #{idx} is missing a source path.")
        if not bundle_root:
            workspace.cleanup()
            raise ValueError("A judge bundle is required for hidden tests that mount files.")
        source_path = _safe_path_within(bundle_root, source_rel)
        if not source_path or not os.path.isfile(source_path):
            workspace.cleanup()
            raise FileNotFoundError(f"Judge bundle file '{source_rel}' was not found.")
        target_path = _safe_path_within(workdir, target_rel)
        if not target_path:
            workspace.cleanup()
            raise ValueError(f"Invalid hidden test target path '{target_rel}'.")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        shutil.copy2(source_path, target_path)

    sample_input = _coerce_string(test.get("input"))
    expected_output = _coerce_string(test.get("expected") or test.get("output"))
    stdin_file = _coerce_string(test.get("stdin_file")).strip()
    expected_file = _coerce_string(test.get("expected_file")).strip()
    if stdin_file:
        if not bundle_root:
            workspace.cleanup()
            raise ValueError("A judge bundle is required for hidden tests that use stdin_file.")
        sample_input = _read_workspace_text_file(bundle_root, stdin_file, "stdin_file")
    if expected_file:
        if not bundle_root:
            workspace.cleanup()
            raise ValueError("A judge bundle is required for hidden tests that use expected_file.")
        expected_output = _read_workspace_text_file(bundle_root, expected_file, "expected_file")
    return workspace, workdir, sample_input, expected_output

def _extract_judge_bundle_to_tempdir(task):
    file_info = _extract_file_info(getattr(task, "judge_bundle_file", None))
    if not file_info:
        return None, None
    bundle_path = _safe_upload_path(file_info.get("path"))
    if not bundle_path or not os.path.isfile(bundle_path):
        raise FileNotFoundError("Judge bundle file was not found on disk.")
    extracted = tempfile.TemporaryDirectory()
    total_bytes = 0
    with zipfile.ZipFile(bundle_path) as zf:
        for member in zf.infolist():
            member_name = _coerce_string(member.filename).strip()
            if not member_name:
                continue
            target_path = _safe_path_within(extracted.name, member_name)
            if not target_path:
                extracted.cleanup()
                raise ValueError(f"Judge bundle member '{member_name}' has an invalid path.")
            if member.is_dir():
                os.makedirs(target_path, exist_ok=True)
                continue
            total_bytes += int(member.file_size or 0)
            if total_bytes > JUDGE_BUNDLE_MAX_EXTRACT_BYTES:
                extracted.cleanup()
                raise ValueError(f"Judge bundle expands beyond {JUDGE_BUNDLE_MAX_EXTRACT_MB} MB.")
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return extracted, extracted.name

def _values_match(actual, expected):
    try:
        import numpy as np
    except Exception:
        np = None
    if np is not None:
        try:
            if isinstance(actual, np.ndarray) or isinstance(expected, np.ndarray):
                try:
                    return bool(np.array_equal(np.asarray(actual), np.asarray(expected), equal_nan=True))
                except TypeError:
                    return bool(np.array_equal(np.asarray(actual), np.asarray(expected)))
                except Exception:
                    return False
        except Exception:
            pass
    try:
        comparison = actual == expected
    except Exception:
        return False
    if np is not None:
        try:
            if isinstance(comparison, np.ndarray):
                return bool(comparison.all())
        except Exception:
            pass
    try:
        return bool(comparison)
    except Exception:
        return False

def _normalize_compare_text(value):
    return " ".join(_coerce_string(value).split())

def _text_matches(actual_text, expected_text, compare_mode):
    actual = _coerce_string(actual_text)
    expected = _coerce_string(expected_text)
    if compare_mode == "exact":
        return actual == expected
    if compare_mode == "normalize_whitespace":
        return _normalize_compare_text(actual) == _normalize_compare_text(expected)
    if compare_mode == "contains":
        return expected in actual
    return actual.rstrip() == expected.rstrip()

def _numeric_values_close(actual, expected, tolerance):
    if isinstance(actual, (list, tuple)) and isinstance(expected, (list, tuple)):
        if len(actual) != len(expected):
            return False
        return all(_numeric_values_close(a, b, tolerance) for a, b in zip(actual, expected))
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    if isinstance(actual, (str, bytes)) or isinstance(expected, (str, bytes)):
        return False
    try:
        left = float(actual)
        right = float(expected)
    except Exception:
        return False
    if left != left and right != right:
        return True
    return abs(left - right) <= tolerance

def _values_close(actual, expected, tolerance):
    try:
        tolerance = max(float(tolerance), 0.0)
    except Exception:
        tolerance = DEFAULT_NUMERIC_TOLERANCE
    try:
        import numpy as np
    except Exception:
        np = None
    if np is not None:
        try:
            return bool(np.allclose(np.asarray(actual), np.asarray(expected), atol=tolerance, rtol=0.0, equal_nan=True))
        except Exception:
            pass
    return _numeric_values_close(actual, expected, tolerance)

def _effective_sample_compare_mode(sample, sample_kind):
    try:
        return _normalize_sample_compare_mode(
            _first_present(sample, "compare_mode", "compare", "comparison", "match_mode", "matcher"),
            sample_kind,
        )
    except Exception:
        return DEFAULT_SCRIPT_SAMPLE_COMPARE_MODE if sample_kind == "script" else DEFAULT_CALLABLE_SAMPLE_COMPARE_MODE

def _effective_sample_tolerance(sample):
    try:
        return _coerce_sample_tolerance(
            _first_present(sample, "tolerance", "abs_tolerance", "atol", "epsilon"),
        )
    except Exception:
        return DEFAULT_NUMERIC_TOLERANCE

def _callable_result_matches(result_value, output_value, expected_text, compare_mode, expected_literal_defined, expected_literal, tolerance=None):
    if compare_mode == "contains":
        return _text_matches(output_value, expected_text, "contains"), ""
    if compare_mode == "numeric_tolerance":
        if not expected_literal_defined:
            return False, "Numeric tolerance comparison requires a literal expected value."
        return _values_close(result_value, expected_literal, tolerance), ""
    if expected_literal_defined:
        return _values_match(result_value, expected_literal), ""
    return _text_matches(output_value.strip(), expected_text.strip(), "exact"), ""

class CodeExecutionTimedOut(Exception):
    pass

def _run_with_code_timeout(seconds, callback):
    if not seconds or seconds <= 0:
        return callback()
    if not hasattr(signal, "SIGALRM") or not hasattr(signal, "setitimer"):
        return callback()

    def _handle_timeout(signum, frame):
        raise CodeExecutionTimedOut("Execution time limit exceeded.")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        return callback()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)

def _code_batch_timeout_seconds(tests, mode):
    time_limits = [_test_timeout_seconds(test) for test in (tests or [])]
    if not time_limits:
        time_limits = [max(float(CODE_RUN_TIME_LIMIT_SEC or 0), 0.1)]
    setup_budget = max(time_limits) if mode in ("function", "class") else 0.0
    per_test_factor = 2.0 if mode == "class" else 1.0
    return sum(time_limits) * per_test_factor + setup_budget + 1.0

def _run_code_tests_worker(code_text, tests, mode, bundle_root=None):
    results = []
    if not tests:
        return results
    mode = (mode or "script").strip().lower()
    if mode not in ("script", "function", "class"):
        mode = "script"
    requires_isolated_setup = mode in ("function", "class") and any(_test_needs_workspace(test) for test in tests)
    if not code_text:
        for idx, test in enumerate(tests):
            hidden = bool(test.get("hidden"))
            name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
            init_call = (test.get("init_call") or "").strip() if mode == "class" else ""
            sample_kind = "script" if mode == "script" else "callable"
            compare_mode = _effective_sample_compare_mode(test, sample_kind)
            tolerance = _effective_sample_tolerance(test) if compare_mode == "numeric_tolerance" else None
            results.append({
                "name": name,
                "status": "error",
                "input": test.get("call") or test.get("input") or "",
                "output": "",
                "expected": test.get("expected") or test.get("output") or "",
                "error": "No code submitted.",
                "mode": mode,
                "init_call": init_call,
                "compare_mode": compare_mode,
                "tolerance": tolerance,
                "hidden": hidden,
            })
        return results
    _init_plot_backend()
    env_base = None
    setup_failure_status = "error"
    setup_failure_message = ""
    setup_timeout = max((_test_timeout_seconds(test) for test in tests), default=float(CODE_RUN_TIME_LIMIT_SEC))
    if mode in ("function", "class") and not requires_isolated_setup:
        try:
            env_base = safe_env()
            env_base["__name__"] = "__main__"
            _run_with_code_timeout(
                setup_timeout,
                lambda: exec(code_text, env_base, env_base),
            )
        except CodeExecutionTimedOut:
            setup_failure_status = "timeout"
            setup_failure_message = "Setup time limit exceeded."
        except Exception:
            setup_failure_status = "error"
            setup_failure_message = traceback.format_exc()
        if setup_failure_message:
            for idx, test in enumerate(tests):
                hidden = bool(test.get("hidden"))
                name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
                init_call = (test.get("init_call") or "").strip() if mode == "class" else ""
                compare_mode = _effective_sample_compare_mode(test, "callable")
                tolerance = _effective_sample_tolerance(test) if compare_mode == "numeric_tolerance" else None
                results.append({
                    "name": name,
                    "status": setup_failure_status,
                    "input": test.get("call") or test.get("input") or "",
                    "output": "",
                    "expected": test.get("expected") or test.get("output") or "",
                    "error": setup_failure_message,
                    "mode": mode,
                    "init_call": init_call,
                    "compare_mode": compare_mode,
                    "tolerance": tolerance,
                    "hidden": hidden,
                    "plot_images": [],
                })
            return results
    for idx, test in enumerate(tests):
        hidden = bool(test.get("hidden"))
        name = test.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
        test_timeout = _test_timeout_seconds(test)
        if mode in ("function", "class"):
            call_expr = (test.get("call") or test.get("input") or "").strip()
            expected_output = _coerce_string(test.get("expected") or test.get("output"))
            expected_display = expected_output
            expected_trimmed = expected_output.strip()
            compare_mode = _effective_sample_compare_mode(test, "callable")
            tolerance = _effective_sample_tolerance(test) if compare_mode == "numeric_tolerance" else None
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
            init_call = ""
            workspace = None
            workdir = None
            if not call_expr:
                status = "error"
                error_text = "Missing call expression."
            else:
                try:
                    if _test_needs_workspace(test):
                        workspace, workdir, _, expected_output = _prepare_code_test_workspace(test, bundle_root=bundle_root)
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
                    if requires_isolated_setup:
                        env = safe_env(workdir)
                        env["__name__"] = "__main__"
                        _run_in_workspace(
                            workdir,
                            lambda: _run_with_code_timeout(
                                test_timeout,
                                lambda: exec(code_text, env, env),
                            ),
                        )
                    else:
                        env = dict(env_base or safe_env())
                    stdout = io.StringIO()
                    original_stdout = sys.stdout
                    sys.stdout = stdout
                    try:
                        if mode == "class":
                            init_call = (test.get("init_call") or "").strip()
                            if not init_call:
                                raise RuntimeError("Missing __init__ call.")
                            env["obj"] = _run_in_workspace(
                                workdir,
                                lambda: _run_with_code_timeout(
                                    test_timeout,
                                    lambda: eval(init_call, env, env),
                                ),
                            )
                        result = _run_in_workspace(
                            workdir,
                            lambda: _run_with_code_timeout(
                                test_timeout,
                                lambda: eval(call_expr, env, env),
                            ),
                        )
                        result_value = result
                        output_value = repr(result)
                    except CodeExecutionTimedOut:
                        status = "timeout"
                        error_text = "Execution time limit exceeded."
                    except Exception:
                        status = "error"
                        error_text = traceback.format_exc()
                    finally:
                        sys.stdout = original_stdout
                except CodeExecutionTimedOut:
                    status = "timeout"
                    error_text = "Execution time limit exceeded."
                except Exception:
                    status = "error"
                    error_text = traceback.format_exc()
            plot_images = _collect_plot_images()
            if workspace:
                workspace.cleanup()
            if status == "passed" and expected_trimmed:
                matched, compare_error = _callable_result_matches(
                    result_value,
                    output_value,
                    expected_trimmed,
                    compare_mode,
                    expected_literal_defined,
                    expected_literal,
                    tolerance=tolerance,
                )
                if compare_error:
                    status = "error"
                    error_text = compare_error
                elif not matched:
                    status = "mismatch"
            results.append({
                "name": name,
                "status": status,
                "input": call_expr,
                "output": output_value,
                "expected": expected_display,
                "error": error_text,
                "mode": mode,
                "init_call": init_call,
                "compare_mode": compare_mode,
                "tolerance": tolerance,
                "hidden": hidden,
                "plot_images": plot_images,
            })
        else:
            workspace = None
            workdir = None
            sample_input = _coerce_string(test.get("input"))
            expected_output = _coerce_string(test.get("expected") or test.get("output"))
            compare_mode = _effective_sample_compare_mode(test, "script")
            stdout_buffer = io.StringIO()
            status = "passed"
            error_text = ""
            try:
                if _test_needs_workspace(test):
                    workspace, workdir, sample_input, expected_output = _prepare_code_test_workspace(test, bundle_root=bundle_root)
                stdin_buffer = io.StringIO(sample_input)
                env = safe_env(workdir)
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
                    _run_in_workspace(
                        workdir,
                        lambda: _run_with_code_timeout(
                            test_timeout,
                            lambda: exec(code_text, env, env),
                        ),
                    )
                except CodeExecutionTimedOut:
                    status = "timeout"
                    error_text = "Execution time limit exceeded."
                finally:
                    sys.stdout = original_stdout
            except Exception:
                if status != "timeout":
                    status = "error"
                    error_text = traceback.format_exc()
            output_value = stdout_buffer.getvalue()
            plot_images = _collect_plot_images()
            if workspace:
                workspace.cleanup()
            if status == "passed" and expected_output.strip():
                if not _text_matches(output_value, expected_output, compare_mode):
                    status = "mismatch"
                    error_text = ""
            results.append({
                "name": name,
                "status": status,
                "input": sample_input,
                "output": output_value,
                "expected": expected_output,
                "error": error_text,
                "mode": "script",
                "init_call": "",
                "compare_mode": compare_mode,
                "tolerance": None,
                "hidden": hidden,
                "plot_images": plot_images,
            })
    return results

def _run_code_tests_backend(code_text, tests, mode, bundle_root=None):
    """
    Run code in a child process with a hard time limit.
    Returns (results, timed_out).
    """
    if not tests:
        return [], False
    mode = (mode or "script").strip().lower()
    if mode not in ("script", "function", "class"):
        mode = "script"

    try:
        ctx = multiprocessing.get_context("fork")
    except ValueError:
        ctx = multiprocessing.get_context()
    result_queue = ctx.Queue()

    def _child():
        try:
            res = _run_code_tests_worker(code_text, tests, mode, bundle_root=bundle_root)
        except Exception as e:
            res = []
            for idx, t in enumerate(tests):
                hidden = bool(t.get("hidden"))
                name = t.get("name") or ("Hidden test" if hidden else f"Test {idx+1}")
                init_call = (t.get("init_call") or "").strip() if mode == "class" else ""
                sample_kind = "script" if mode == "script" else "callable"
                compare_mode = _effective_sample_compare_mode(t, sample_kind)
                tolerance = _effective_sample_tolerance(t) if compare_mode == "numeric_tolerance" else None
                res.append({
                    "name": name,
                    "status": "error",
                    "input": t.get("call") or t.get("input") or "",
                    "output": "",
                    "expected": t.get("expected") or t.get("output") or "",
                    "error": repr(e),
                    "mode": mode,
                    "init_call": init_call,
                    "compare_mode": compare_mode,
                    "tolerance": tolerance,
                    "hidden": hidden,
                })
        result_queue.put(res)

    proc = ctx.Process(target=_child)
    proc.start()
    proc.join(_code_batch_timeout_seconds(tests, mode))

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
            init_call = (t.get("init_call") or "").strip() if mode == "class" else ""
            sample_kind = "script" if mode == "script" else "callable"
            compare_mode = _effective_sample_compare_mode(t, sample_kind)
            tolerance = _effective_sample_tolerance(t) if compare_mode == "numeric_tolerance" else None
            results.append({
                "name": name,
                "status": "timeout",
                "input": t.get("call") or t.get("input") or "",
                "output": "",
                "expected": t.get("expected") or t.get("output") or "",
                "error": "Time limit exceeded",
                "mode": mode,
                "init_call": init_call,
                "compare_mode": compare_mode,
                "tolerance": tolerance,
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
                init_call = (t.get("init_call") or "").strip() if mode == "class" else ""
                sample_kind = "script" if mode == "script" else "callable"
                compare_mode = _effective_sample_compare_mode(t, sample_kind)
                tolerance = _effective_sample_tolerance(t) if compare_mode == "numeric_tolerance" else None
                results.append({
                    "name": name,
                    "status": "error",
                    "input": t.get("call") or t.get("input") or "",
                    "output": "",
                    "expected": t.get("expected") or t.get("output") or "",
                    "error": "No results from worker process",
                    "mode": mode,
                    "init_call": init_call,
                    "compare_mode": compare_mode,
                    "tolerance": tolerance,
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
            "compare_mode": res.get("compare_mode") or "",
            "tolerance": res.get("tolerance"),
        }
        if is_hidden:
            hidden.append(base)
        else:
            base.update({
                "input": res.get("input") or "",
                "output": res.get("output") or "",
                "expected": res.get("expected") or "",
                "error": res.get("error") or "",
                "mode": res.get("mode") or "script",
                "init_call": res.get("init_call") or "",
                "compare_mode": res.get("compare_mode") or "",
                "tolerance": res.get("tolerance"),
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
    upload_error = None

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
                qtype = current_question.get("type")
                if qtype == "multi":
                    vals = request.form.getlist(field)
                    val = "||".join(vals)
                elif qtype == "plot":
                    val = _preserve_plot_answer_metadata(
                        request.form.get(field, ""),
                        previous_answers.get(qid),
                    )
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
        if action != "submit":
            combined_answers = dict(base_answers)
            combined_answers.update(draft_answers)
            plot_updates, upload_error = _collect_plot_submission_updates(
                questions,
                combined_answers,
                request.files,
                request.form,
                {
                    "kind": "exam",
                    "exam_id": exam.id,
                    "submission_id": submission.id if submission else None,
                },
                strict_code_match=False,
            )
            if upload_error:
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
                    already_submitted=already_submitted,
                    previous_answers=previous_answers,
                    time_remaining_seconds=time_remaining if time_remaining is not None else None,
                    user=user,
                    student_name=session.get("student_name"),
                    submission_id=(submission.id if submission else None),
                    upload_error=upload_error,
                ), 400
            if plot_updates:
                draft_answers.update(plot_updates)
                previous_answers.update(plot_updates)
                _save_exam_draft(exam.id, draft_answers)

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
            answers, upload_error = _prepare_plot_answers_for_submit(
                questions,
                answers,
                base_answers,
                request.files,
                request.form,
                {
                    "kind": "exam",
                    "exam_id": exam.id,
                    "submission_id": submission.id if submission else None,
                },
            )
            if upload_error:
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
                    already_submitted=already_submitted,
                    previous_answers=previous_answers,
                    time_remaining_seconds=time_remaining if time_remaining is not None else None,
                    user=user,
                    student_name=session.get("student_name"),
                    submission_id=(submission.id if submission else None),
                    upload_error=upload_error,
                ), 400
            grade_score, grade_total, grade_details = _grade_exam_submission(exam, answers)
            submission.answers_json = answers
            submission.status = "submitted"
            submission.submitted_at = datetime.utcnow()
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
        submission_id=(submission.id if submission else None),
        upload_error=upload_error,
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
                    student = Student.query.get(student_id)
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

@app.route("/announcements", methods=["GET", "POST"])
@require_user()
def announcements_admin():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    message = session.pop("announcements_status", None)
    form_data = {
        "title": request.form.get("title") or "",
        "body": request.form.get("body") or "",
        "group_id": request.form.get("group_id") or "all",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        body = form_data["body"].strip()
        group_value = (form_data["group_id"] or "all").strip()
        target_group = None
        if not title:
            error = "Announcement title is required."
        elif not body:
            error = "Announcement body is required."
        if not error and group_value != "all":
            try:
                group_id = int(group_value)
            except Exception:
                group_id = 0
            target_group = StudentGroup.query.get(group_id) if group_id else None
            if not target_group:
                error = "Selected group was not found."
        student_ids = []
        if not error:
            if target_group:
                memberships = StudentGroupMembership.query.filter_by(group_id=target_group.id).all()
                student_ids = sorted({membership.student_id for membership in memberships if membership.student_id})
            else:
                student_ids = [
                    row[0]
                    for row in db.session.query(Student.id)
                    .order_by(Student.name.asc(), Student.id.asc())
                    .all()
                ]
            if not student_ids:
                error = "No students matched the selected target."
        if not error:
            announcement = Announcement(
                title=title,
                body=body,
                created_by_user_id=user.id if user else None,
                target_group_id=(target_group.id if target_group else None),
                target_group_name=(target_group.name if target_group else None),
            )
            db.session.add(announcement)
            db.session.flush()
            for student_id in student_ids:
                db.session.add(AnnouncementDelivery(
                    announcement_id=announcement.id,
                    student_id=student_id,
                ))
            db.session.commit()
            session["announcements_status"] = f"Announcement sent to {len(student_ids)} student(s)."
            return redirect(url_for("announcements_admin"))
    announcements = (
        Announcement.query
        .options(
            subqueryload(Announcement.deliveries),
            subqueryload(Announcement.creator),
            subqueryload(Announcement.target_group),
        )
        .order_by(Announcement.created_at.desc(), Announcement.id.desc())
        .all()
    )
    announcement_rows = []
    for announcement in announcements:
        deliveries = announcement.deliveries or []
        seen_count = sum(1 for delivery in deliveries if delivery.seen_at)
        total_count = len(deliveries)
        announcement_rows.append({
            "announcement": announcement,
            "target_label": _announcement_target_label(announcement),
            "total_count": total_count,
            "seen_count": seen_count,
            "unseen_count": max(0, total_count - seen_count),
        })
    return render_template(
        "announcements_admin.html",
        groups=groups,
        announcement_rows=announcement_rows,
        form_data=form_data,
        message=message,
        error=error,
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/attendance/new", methods=["GET", "POST"])
@require_user()
def attendance_new():
    user = current_user()
    if not _is_staff(user):
        abort(403)
    groups = StudentGroup.query.order_by(StudentGroup.name.asc()).all()
    default_date = datetime.utcnow().date().isoformat()
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
        group = StudentGroup.query.get(group_id) if group_id else None
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
                    group = StudentGroup.query.get(gid)
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
        "collection": request.form.get("collection") or "comp101",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "deadline_at": request.form.get("deadline_at") or "",
        "required_task_count": request.form.get("required_task_count") or "",
        "points": request.form.get("points") or "",
        "retry_cooldown_minutes": request.form.get("retry_cooldown_minutes") or "",
    }
    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        title = form_data["title"].strip()
        collection = form_data["collection"].strip() or "comp101"
        deadline_at = None
        if not title:
            error = "Project title is required."
        deadline_raw = form_data["deadline_at"].strip()
        if deadline_raw and not error:
            deadline_at = parse_dt_local(deadline_raw)
            if not deadline_at:
                error = "Deadline must be a valid date and time."
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
        if not error:
            code = gen_code(8)
            while Project.query.filter_by(code=code).first() is not None:
                code = gen_code(8)
            project = Project(
                code=code,
                title=title,
                collection=collection,
                description=form_data["description"].strip() or None,
                instructions=form_data["instructions"].strip() or None,
                deadline_at=deadline_at,
                required_task_count=required_count,
                is_active=False,
                points=points_value,
                retry_cooldown_minutes=retry_minutes_value,
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

@app.get("/projects/<code>/export")
@require_user()
def projects_export(code):
    project = Project.query.filter_by(code=code).first_or_404()
    tasks = ProjectTask.query.filter_by(project_id=project.id).order_by(
        ProjectTask.order_index.asc(),
        ProjectTask.id.asc(),
    ).all()
    dependencies = ProjectDependency.query.filter_by(project_id=project.id).all()
    dependencies = sorted(
        dependencies,
        key=lambda dep: (
            (dep.prerequisite.title or "").lower() if dep.prerequisite else "",
            dep.prerequisite.code if dep.prerequisite else "",
        ),
    )
    group_assignments = ProjectGroupAssignment.query.filter_by(project_id=project.id).order_by(
        ProjectGroupAssignment.applies_to_all.desc(),
        ProjectGroupAssignment.created_at.asc(),
        ProjectGroupAssignment.id.asc(),
    ).all()
    payload = _serialize_project_export(
        project,
        tasks=tasks,
        dependencies=dependencies,
        group_assignments=group_assignments,
    )
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    response = make_response(json.dumps(payload, indent=2, ensure_ascii=False))
    response.mimetype = "application/json"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{project.code}_project_export_{timestamp}.json"'
    )
    return response

@app.route("/projects/<code>/edit", methods=["GET", "POST"])
@require_user()
def projects_edit(code):
    project = Project.query.filter_by(code=code).first_or_404()
    error = None
    form_data = {
        "title": request.form.get("title") if request.method == "POST" else project.title,
        "collection": request.form.get("collection") if request.method == "POST" else (project.collection or "comp101"),
        "description": request.form.get("description") if request.method == "POST" else (project.description or ""),
        "instructions": request.form.get("instructions") if request.method == "POST" else (project.instructions or ""),
        "deadline_at": request.form.get("deadline_at") if request.method == "POST" else (project.deadline_at.strftime("%Y-%m-%dT%H:%M") if project.deadline_at else ""),
        "required_task_count": request.form.get("required_task_count") if request.method == "POST" else (str(project.required_task_count) if project.required_task_count else ""),
    }
    
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        
        title = (form_data["title"] or "").strip()
        collection = (form_data["collection"] or "").strip()
        description = (form_data["description"] or "").strip()
        instructions = (form_data["instructions"] or "").strip()
        deadline_raw = (form_data["deadline_at"] or "").strip()
        required_task_count = (form_data["required_task_count"] or "").strip()
        deadline_at = None
        
        if not title:
            error = "Project title is required."
        if deadline_raw and not error:
            deadline_at = parse_dt_local(deadline_raw)
            if not deadline_at:
                error = "Deadline must be a valid date and time."
        
        if not error:
            project.title = title
            project.collection = collection or "comp101"
            project.description = description or None
            project.instructions = instructions or None
            project.deadline_at = deadline_at
            
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
    body = json.dumps(PROJECT_TASKS_SCHEMA, indent=2, ensure_ascii=False)
    if request.args.get("download") == "1":
        response = make_response(body)
        response.mimetype = "application/json"
        response.headers["Content-Disposition"] = 'attachment; filename="project_task_import_reference.json"'
        return response
    return Response(body, mimetype="application/json")

@app.route("/projects/tasks/examples/<example_name>")
@require_user()
def projects_tasks_example_download(example_name):
    schema_key = PROJECT_TASKS_EXAMPLE_DOWNLOADS.get(example_name)
    if not schema_key:
        abort(404)
    payload = PROJECT_TASKS_SCHEMA.get("example_payloads", {}).get(schema_key)
    if payload is None:
        abort(404)
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    response = make_response(body)
    response.mimetype = "application/json"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="project_task_{secure_filename(example_name) or "example"}.json"'
    )
    return response

@app.route("/projects/<code>/tasks/new", methods=["GET", "POST"])
@require_user()
def projects_task_new(code):
    project = Project.query.filter_by(code=code).first_or_404()
    req_flag = request.form.get("required")
    auto_flag_vals = request.form.getlist("auto_grade")
    review_flag = request.form.get("requires_review")
    resource_upload = request.files.get("resource_file")
    judge_bundle_upload = request.files.get("judge_bundle_file")
    form_data = {
        "title": request.form.get("title") or "",
        "description": request.form.get("description") or "",
        "instructions": request.form.get("instructions") or "",
        "task_kind": request.form.get("task_kind") or "assessment",
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
        task_kind = _normalize_task_kind_name(form_data.get("task_kind"))
        if task_kind not in ("assessment", "tutorial"):
            error = "Task kind must be assessment or tutorial."
        questions = []
        if not error and task_kind == "tutorial":
            if not form_data["instructions"].strip():
                error = "Tutorial tasks need markdown content in the task instructions."
        if not error and task_kind == "assessment":
            try:
                payload = json.loads(form_data["questions_payload"] or "[]")
                questions = _normalize_exam_questions(payload)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Unable to parse task questions."
        if task_kind == "assessment" and not questions and not error:
            error = "Add at least one question for the task."
        if not error and task_kind == "assessment":
            if _questions_require_judge_bundle(questions) and not (judge_bundle_upload and judge_bundle_upload.filename):
                error = "Hidden tests that use bundle files require a judge bundle .zip upload."
        if not error:
            order_index = (ProjectTask.query.filter_by(project_id=project.id).count() or 0) + 1
            task = ProjectTask(
                project_id=project.id,
                task_kind=task_kind,
                title=title,
                description=form_data["description"].strip() or None,
                instructions=form_data["instructions"].strip() or None,
                questions_json=questions,
                required=form_data["required"],
                auto_grade=(form_data["auto_grade"] if task_kind == "assessment" else False),
                requires_review=(form_data["requires_review"] if task_kind == "assessment" else False),
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
            if not error and judge_bundle_upload and judge_bundle_upload.filename:
                bundle_info, upload_error = _save_task_judge_bundle(task, judge_bundle_upload)
                if upload_error:
                    db.session.rollback()
                    error = upload_error
                else:
                    task.judge_bundle_file = bundle_info
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
    judge_bundle_upload = request.files.get("judge_bundle_file")
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        try:
            config = json.loads(payload or "{}")
        except ValueError as exc:
            error = f"Invalid JSON: {exc}"
        else:
            try:
                created_tasks = _import_project_tasks_from_config(project, config)
                if any(_questions_require_judge_bundle(task.questions_json) for task in created_tasks):
                    if not (judge_bundle_upload and judge_bundle_upload.filename):
                        raise ValueError("Hidden tests that use bundle files require a judge bundle .zip upload.")
                db.session.flush()
                if judge_bundle_upload and judge_bundle_upload.filename:
                    try:
                        judge_payload = judge_bundle_upload.read(JUDGE_BUNDLE_MAX_BYTES + 1)
                    except Exception:
                        raise ValueError("Unable to read the judge bundle.")
                    if len(judge_payload) > JUDGE_BUNDLE_MAX_BYTES:
                        raise ValueError(f"Judge bundle must be {JUDGE_BUNDLE_MAX_MB} MB or smaller.")
                    for task in created_tasks:
                        bundle_info, upload_error = _save_project_task_bundle_from_bytes(
                            task,
                            judge_bundle_upload.filename,
                            judge_payload,
                            content_type=(judge_bundle_upload.mimetype or ""),
                            existing_info=None,
                        )
                        if upload_error:
                            raise ValueError(upload_error)
                        task.judge_bundle_file = bundle_info
                db.session.commit()
                return redirect(url_for("projects_show", code=project.code))
            except ValueError as exc:
                db.session.rollback()
                error = str(exc)
            except Exception:
                db.session.rollback()
                error = "Unable to import tasks. Please review your JSON."
    schema_json = json.dumps(PROJECT_TASKS_SCHEMA, indent=2, ensure_ascii=False)
    starter_payloads = {
        "minimal": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["minimal_payload"], indent=2, ensure_ascii=False),
        "tutorial": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["tutorial_payload"], indent=2, ensure_ascii=False),
        "class_code": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["class_code_payload"], indent=2, ensure_ascii=False),
        "plot": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["plot_payload"], indent=2, ensure_ascii=False),
        "formatting": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["formatting_payload"], indent=2, ensure_ascii=False),
        "comparison": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["comparison_payload"], indent=2, ensure_ascii=False),
        "hidden_judge": json.dumps(PROJECT_TASKS_SCHEMA["example_payloads"]["hidden_judge_payload"], indent=2, ensure_ascii=False),
    }
    return render_template(
        "projects_task_import.html",
        project=project,
        payload=payload,
        schema_json=schema_json,
        starter_payloads=starter_payloads,
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
    judge_bundle_upload = request.files.get("judge_bundle_file")
    if request.method == "POST":
        form_data = {
            "title": request.form.get("title") or "",
            "description": request.form.get("description") or "",
            "instructions": request.form.get("instructions") or "",
            "task_kind": request.form.get("task_kind") or "assessment",
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
            "task_kind": _task_kind_value(task),
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
        task_kind = _normalize_task_kind_name(form_data.get("task_kind"))
        if task_kind not in ("assessment", "tutorial"):
            error = "Task kind must be assessment or tutorial."
        questions = []
        if not error and task_kind == "tutorial":
            if not form_data["instructions"].strip():
                error = "Tutorial tasks need markdown content in the task instructions."
        if not error and task_kind == "assessment":
            try:
                payload = json.loads(form_data["questions_payload"] or "[]")
                questions = _normalize_exam_questions(payload)
            except ValueError as exc:
                error = str(exc)
            except Exception:
                error = "Unable to parse task questions."
        if task_kind == "assessment" and not questions and not error:
            error = "Add at least one question for the task."
        if not error and task_kind == "assessment":
            existing_bundle = _extract_file_info(task.judge_bundle_file)
            has_bundle = bool(existing_bundle) or bool(judge_bundle_upload and judge_bundle_upload.filename)
            if _questions_require_judge_bundle(questions) and not has_bundle:
                error = "Hidden tests that use bundle files require a judge bundle .zip upload."
        if not error:
            task.task_kind = task_kind
            task.title = title
            task.description = form_data["description"].strip() or None
            task.instructions = form_data["instructions"].strip() or None
            task.questions_json = questions
            task.required = form_data["required"]
            task.auto_grade = form_data["auto_grade"] if task_kind == "assessment" else False
            task.requires_review = form_data["requires_review"] if task_kind == "assessment" else False
            if resource_upload and resource_upload.filename:
                existing_info = _extract_file_info(task.resource_file)
                file_info, upload_error = _save_task_resource(task, resource_upload, existing_info)
                if upload_error:
                    error = upload_error
                else:
                    task.resource_file = file_info
            if not error and judge_bundle_upload and judge_bundle_upload.filename:
                existing_info = _extract_file_info(task.judge_bundle_file)
                bundle_info, upload_error = _save_task_judge_bundle(task, judge_bundle_upload, existing_info)
                if upload_error:
                    error = upload_error
                else:
                    task.judge_bundle_file = bundle_info
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
        _remove_uploaded_file(task.judge_bundle_file)
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
            latest_attempt = _latest_task_attempt(submission) if submission else None
            judge_info = _submission_judge_snapshot(submission, latest_attempt)
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
                if judge_info["judge_verdict"] == "judge_error":
                    can_retry_now = True
                elif status in ("pending_review", "submitted", "accepted"):
                    can_retry_now = False
                elif status == "rejected":
                    retry_minutes = project.retry_cooldown_minutes or 0
                    if retry_minutes > 0 and submission.submitted_at:
                        elapsed = (datetime.utcnow() - submission.submitted_at).total_seconds()
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
                "judge_state": judge_info["judge_state"],
                "judge_verdict": judge_info["judge_verdict"],
                "judge_feedback": judge_info["judge_feedback"],
                "judge_summary": judge_info["judge_summary"],
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
    def group_rows(rows):
        groups = {}
        order = []
        for row in rows:
            name = (row["project"].collection or "comp101").strip() or "comp101"
            if name not in groups:
                groups[name] = []
                order.append(name)
            groups[name].append(row)
        return [{"name": name, "rows": groups[name]} for name in order]
    available_groups = group_rows(available_rows)
    locked_groups = group_rows(locked_rows)
    completed_groups = group_rows(completed_rows)
    tab = request.args.get("tab", "active").lower()
    if tab not in ("active", "completed"):
        tab = "active"
    return render_template(
        "projects_student.html",
        available_projects=available_rows,
        locked_projects=locked_rows,
        completed_projects=completed_rows,
        available_collections=available_groups,
        locked_collections=locked_groups,
        completed_collections=completed_groups,
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
        judge_info = _submission_judge_snapshot(submission, latest_attempt)
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
            if judge_info["judge_verdict"] == "judge_error":
                can_retry_now = True
            elif status in ("pending_review", "submitted", "accepted"):
                can_retry_now = False
            elif status == "rejected":
                retry_minutes = project.retry_cooldown_minutes or 0
                if retry_minutes > 0 and submission.submitted_at:
                    elapsed = (datetime.utcnow() - submission.submitted_at).total_seconds()
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
            "judge_state": judge_info["judge_state"],
            "judge_verdict": judge_info["judge_verdict"],
            "judge_feedback": judge_info["judge_feedback"],
            "judge_summary": judge_info["judge_summary"],
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
        "task_kind": _task_kind_value(task),
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
    if _is_tutorial_task(task):
        submission = _complete_tutorial_task(project, task, student)
        db.session.flush()
        if _project_completed(project, student):
            _award_project_points_if_needed(project, student)
        db.session.commit()
        return render_template(
            "projects_tutorial_take.html",
            project=project,
            task=task,
            submission=submission,
            user=current_user(),
            student_name=student.name,
        )
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
                elif qtype == "plot":
                    val = _preserve_plot_answer_metadata(
                        request.form.get(field, ""),
                        previous_answers.get(qid),
                    )
                else:
                    val = request.form.get(field, "")
                if upload_error:
                    return render_template(
                        "exams_take.html",
                        exam=_task_exam_view(project, task),
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
                        persisted_answers=base_answers,
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
        if action != "submit":
            combined_answers = dict(base_answers)
            combined_answers.update(draft_answers)
            plot_updates, upload_error = _collect_plot_submission_updates(
                questions,
                combined_answers,
                request.files,
                request.form,
                {
                    "kind": "project_task",
                    "project_id": project.id,
                    "task_id": task.id,
                    "submission_id": submission.id if submission else None,
                },
                strict_code_match=False,
            )
            if upload_error:
                return render_template(
                    "exams_take.html",
                    exam=_task_exam_view(project, task),
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
                    persisted_answers=base_answers,
                    upload_error=upload_error,
                ), 400
            if plot_updates:
                draft_answers.update(plot_updates)
                previous_answers.update(plot_updates)
                _save_task_draft(task.id, draft_answers)
        if action == "save":
            answers = dict(base_answers)
            answers.update(draft_answers)
            submission.answers_json = answers
            submission.last_activity_at = datetime.utcnow()
            db.session.commit()
            return redirect(url_for("student_projects"))
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
                    submission_id=submission.id,
                    persisted_answers=base_answers,
                ), 403
            answers = dict(base_answers)
            answers.update(draft_answers)
            answers, upload_error = _prepare_plot_answers_for_submit(
                questions,
                answers,
                base_answers,
                request.files,
                request.form,
                {
                    "kind": "project_task",
                    "project_id": project.id,
                    "task_id": task.id,
                    "submission_id": submission.id if submission else None,
                },
            )
            if upload_error:
                return render_template(
                    "exams_take.html",
                    exam=_task_exam_view(project, task),
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
                    persisted_answers=base_answers,
                    upload_error=upload_error,
                ), 400
            grade_score = 0
            grade_total = 0
            grade_details = []
            needs_async_judge = bool(task.auto_grade and _task_has_async_hidden_judge(questions))
            if needs_async_judge and not ENABLE_BACKEND_CODE_RUNS:
                return render_template(
                    "exams_take.html",
                    exam=_task_exam_view(project, task),
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
                    persisted_answers=base_answers,
                    upload_error="Hidden-test judging is disabled on the server.",
                ), 503
            if task.auto_grade and not needs_async_judge:
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
            submission.answers_json = answers
            submission.score = grade_score
            submission.max_score = grade_total
            submission.last_activity_at = now
            submission.submitted_at = now
            submission.judge_state = None
            submission.judge_verdict = None
            submission.judge_feedback = None
            submission.judge_summary_json = None
            if needs_async_judge:
                submission.status = "submitted"
                submission.judge_state = "queued"
                submission.judge_feedback = "Queued for hidden tests."
                submission.judge_summary_json = {
                    "verdict": None,
                    "feedback": "Queued for hidden tests.",
                    "queued_at": now.isoformat() + "Z",
                }
                grade_details_for_history = None
            else:
                has_manual_review = any(d.get("manual_review") for d in (grade_details or []))
                if task.requires_review or has_manual_review:
                    submission.status = "pending_review"
                else:
                    if task.auto_grade and grade_total > 0:
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
                judge_state=("queued" if needs_async_judge else None),
                judge_feedback=("Queued for hidden tests." if needs_async_judge else None),
                judge_summary_json=(
                    {
                        "verdict": None,
                        "feedback": "Queued for hidden tests.",
                        "queued_at": now.isoformat() + "Z",
                    }
                    if needs_async_judge else None
                ),
            )
            db.session.add(attempt)
            db.session.flush()
            if needs_async_judge:
                _enqueue_project_task_judge(submission, attempt)
            # Run cheating detection
            _run_cheating_detection(student, submission, request.remote_addr)
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
        submission_id=submission.id,
        persisted_answers=base_answers,
        upload_error=None,
    )

@app.route("/student/projects/<code>/tasks/<int:task_id>/submission")
@require_student()
def project_task_submission_self_view(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    student = current_student()
    if not _project_visible_to_student(project, student):
        abort(403)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    if _is_tutorial_task(task):
        return redirect(url_for("project_task_take", code=project.code, task_id=task.id))
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
    judge_info = _submission_judge_snapshot(submission, latest_attempt)
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
        judge_summary=judge_info["judge_summary"],
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
        user=current_user(),
        student_name=student.name,
    )

@app.route("/projects/<code>/tasks/<int:task_id>/export")
@require_user()
def projects_task_export(code, task_id):
    project = Project.query.filter_by(code=code).first_or_404()
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    payload = {
        "schema_name": "project_task_export",
        "schema_version": 1,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "project": {
            "code": project.code,
            "title": project.title,
        },
        "task": _serialize_project_task_export(task),
    }
    response = make_response(json.dumps(payload, indent=2, ensure_ascii=False))
    response.mimetype = "application/json"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_project_task_download_basename(project, task)}.json"'
    )
    return response

@app.route("/projects/tasks/<int:task_id>/tutorial.md")
def project_task_tutorial_download(task_id):
    task = ProjectTask.query.get_or_404(task_id)
    if not _is_tutorial_task(task):
        abort(404)
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
    body = _project_task_tutorial_markdown(project, task)
    response = make_response(body)
    response.mimetype = "text/markdown"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{_project_task_download_basename(project, task)}.md"'
    )
    return response

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

@app.route("/projects/tasks/<int:task_id>/judge-bundle")
@require_user()
def project_task_judge_bundle_download(task_id):
    task = ProjectTask.query.get_or_404(task_id)
    file_info = _extract_file_info(task.judge_bundle_file)
    if not file_info:
        abort(404)
    full_path = _safe_upload_path(file_info.get("path"))
    if not full_path or not os.path.isfile(full_path):
        abort(404)
    download_name = secure_filename(file_info.get("original_name") or file_info.get("stored_name") or "judge_bundle.zip") or "judge_bundle.zip"
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
    if user:
        allowed_student_ids = _restricted_review_student_ids(user)
        if not _can_user_review_submission(user, submission, allowed_student_ids=allowed_student_ids):
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

@app.route("/projects/submissions/<int:submission_id>/plots/<question_id>")
def project_task_plot_download(submission_id, question_id):
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
    if user:
        allowed_student_ids = _restricted_review_student_ids(user)
        if not _can_user_review_submission(user, submission, allowed_student_ids=allowed_student_ids):
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
    if not question or question.get("type") != "plot":
        abort(404)
    if attempt and isinstance(attempt.answers_json, dict):
        answers = attempt.answers_json
    else:
        answers = submission.answers_json if isinstance(submission.answers_json, dict) else {}
    answer = answers.get(str(question_id))
    artifact = _plot_answer_artifact(answer)
    if not artifact:
        abort(404)
    full_path = _safe_upload_path(artifact.get("path"))
    if not full_path or not os.path.isfile(full_path):
        abort(404)
    download = _coerce_bool(request.args.get("download"), False)
    download_name = secure_filename(artifact.get("original_name") or artifact.get("stored_name") or "plot.png") or "plot.png"
    return send_file(
        full_path,
        mimetype=artifact.get("content_type") or "image/png",
        as_attachment=download,
        download_name=download_name,
    )

@app.post("/projects/<code>/students/<int:student_id>/reset")
@require_user()
def project_reset_student_progress(code, student_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student.id).first_or_404()
    submission.status = "accepted"
    if not submission.submitted_at:
        submission.submitted_at = datetime.utcnow()
    submission.last_activity_at = datetime.utcnow()
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
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
    task = ProjectTask.query.filter_by(id=task_id, project_id=project.id).first_or_404()
    submission = ProjectTaskSubmission.query.filter_by(project_id=project.id, task_id=task.id, student_id=student.id).first_or_404()
    submission.status = "rejected"
    submission.last_activity_at = datetime.utcnow()
    _record_task_attempt_review(submission, status="rejected", reviewer=current_user())
    db.session.commit()
    return redirect(url_for("projects_student_submissions", code=project.code, student_id=student.id))

@app.post("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>/reset")
@require_user()
def projects_submission_task_reset(code, student_id, task_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    tasks = project.tasks or []
    submissions = _apply_review_scope_to_submission_query(
        ProjectTaskSubmission.query.filter_by(project_id=project.id),
        user,
        allowed_student_ids=allowed_student_ids,
    ).order_by(ProjectTaskSubmission.last_activity_at.desc()).all()
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
        review_scope_limited=(allowed_student_ids is not None),
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/submissions/<int:student_id>")
@require_user()
def projects_student_submissions(code, student_id):
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
    tasks = project.tasks or []
    submissions = ProjectTaskSubmission.query.filter_by(project_id=project.id, student_id=student_id).all()
    submissions_map = {sub.task_id: sub for sub in submissions}
    return render_template(
        "projects_student_submissions.html",
        project=project,
        student=student,
        tasks=tasks,
        submissions_map=submissions_map,
        review_scope_limited=(allowed_student_ids is not None),
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/projects/<code>/submissions/<int:student_id>/tasks/<int:task_id>")
@require_user()
def projects_submission_task_detail(code, student_id, task_id):
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    project = Project.query.filter_by(code=code).first_or_404()
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    judge_info = _submission_judge_snapshot(submission, latest_attempt)
    attempts = ProjectTaskAttempt.query.filter_by(submission_id=submission.id).order_by(ProjectTaskAttempt.attempt_number.desc()).all()
    attempt_rows = []
    for attempt in attempts:
        attempt_rows.append({
            "attempt": attempt,
            "answers": attempt.answers_json if isinstance(attempt.answers_json, dict) else {},
            "logs_by_question": _run_logs_by_question(attempt.run_logs if isinstance(attempt.run_logs, list) else None),
            "grading_by_question": _grading_by_question(attempt.grading_json),
            "judge_summary": _submission_judge_snapshot(submission, attempt).get("judge_summary"),
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
        judge_summary=judge_info["judge_summary"],
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews")
@require_user()
def projects_reviews():
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    mentor_group_ids = _mentor_group_ids(user)
    sort_mode = request.args.get("sort", "newest")
    collection_filter = (request.args.get("collection") or "").strip()
    project_filter = request.args.get("project_id")
    warning_filter = request.args.get("warning_filter", "all")  # all, flagged, warned, clean
    
    try:
        project_filter_id = int(project_filter) if project_filter else None
    except ValueError:
        project_filter_id = None
    
    query = _apply_review_scope_to_submission_query(
        ProjectTaskSubmission.query.filter_by(status="pending_review"),
        user,
        allowed_student_ids=allowed_student_ids,
    )

    if collection_filter:
        query = query.join(Project, ProjectTaskSubmission.project_id == Project.id).filter(
            Project.collection == collection_filter
        )
    
    if project_filter_id:
        query = query.filter(ProjectTaskSubmission.project_id == project_filter_id)
    
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
        sub.visible_groups = _visible_groups_for_student(user, sub.student, mentor_group_ids=mentor_group_ids) if sub.student else []
    
    # Get warning counts for statistics
    students_query = _apply_review_scope_to_student_query(
        Student.query,
        user,
        allowed_student_ids=allowed_student_ids,
    )
    flagged_count = students_query.filter_by(is_flagged=True).count()
    warned_students = students_query.filter(Student.warnings_json != None).all()
    warned_count = sum(1 for s in warned_students if not s.is_flagged and s.warnings_json and len(s.warnings_json) > 0)

    projects_query = _apply_review_scope_to_submission_query(
        Project.query.join(ProjectTaskSubmission, ProjectTaskSubmission.project_id == Project.id).filter(
            ProjectTaskSubmission.status == "pending_review"
        ),
        user,
        allowed_student_ids=allowed_student_ids,
    )
    collections = sorted(
        {
            (project.collection or "comp101").strip() or "comp101"
            for project in projects_query.distinct().all()
        },
        key=lambda name: name.lower(),
    )
    if collection_filter:
        projects_query = projects_query.filter(Project.collection == collection_filter)
    projects = projects_query.distinct().order_by(Project.title.asc()).all()
    return render_template(
        "projects_reviews.html",
        submissions=submissions,
        collections=collections,
        filter_collection=collection_filter,
        filter_sort=sort_mode,
        filter_project_id=project_filter_id,
        filter_warning=warning_filter,
        flagged_count=flagged_count,
        warned_count=warned_count,
        projects=projects,
        review_scope_limited=(allowed_student_ids is not None),
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews/mine")
@require_user()
def projects_reviews_mine():
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    attempts = ProjectTaskAttempt.query.filter(
        ProjectTaskAttempt.reviewed_by_user_id == user.id,
        ProjectTaskAttempt.reviewed_at != None,
    ).order_by(ProjectTaskAttempt.reviewed_at.desc()).all()
    if allowed_student_ids is not None:
        attempts = [
            attempt for attempt in attempts
            if attempt.submission and attempt.submission.student_id in allowed_student_ids
        ]
    return render_template(
        "projects_reviews_mine.html",
        attempts=attempts,
        review_scope_limited=(allowed_student_ids is not None),
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.route("/projects/reviews/<int:submission_id>")
@require_user()
def projects_review_detail(submission_id):
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    submission = ProjectTaskSubmission.query.get_or_404(submission_id)
    if not _can_user_review_submission(user, submission, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    judge_info = _submission_judge_snapshot(submission, active_attempt)
    has_code_questions = any((q.get("type") == "code") for q in questions)
    if not grading_by_question and not judge_info["judge_summary"] and task and questions and has_code_questions and ENABLE_BACKEND_CODE_RUNS:
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
        judge_summary=judge_info["judge_summary"],
        code_runs_enabled=ENABLE_BACKEND_CODE_RUNS,
        user=user,
        student_name=session.get("student_name"),
    )

@app.post("/projects/reviews/<int:submission_id>")
@require_user()
def projects_review_decision(submission_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    submission = ProjectTaskSubmission.query.get_or_404(submission_id)
    if not _can_user_review_submission(user, submission, allowed_student_ids=allowed_student_ids):
        abort(403)
    action = request.form.get("action")
    notes = (request.form.get("review_notes") or "").strip()
    attempt_id = request.form.get("attempt_id")
    reviewer = user
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
        now = datetime.utcnow()
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
    submission.last_activity_at = datetime.utcnow()
    if submission.status == "accepted" and submission.student:
        if _project_completed(submission.project, submission.student):
            _award_project_points_if_needed(submission.project, submission.student)
    db.session.commit()
    if review_attempt:
        return redirect(url_for("projects_reviews_mine"))
    return redirect(url_for("projects_reviews"))

@app.route("/mentor/dashboard")
@require_user()
def mentor_dashboard():
    user = current_user()
    if not user or getattr(user, "role", "") != "mentor":
        return redirect(url_for("dashboard_for_role"))

    group_ids = _mentor_group_ids(user) or set()
    groups = []
    memberships = []
    if group_ids:
        groups = StudentGroup.query.filter(StudentGroup.id.in_(group_ids)).order_by(StudentGroup.name.asc()).all()
        memberships = StudentGroupMembership.query.filter(
            StudentGroupMembership.group_id.in_(group_ids)
        ).options(subqueryload(StudentGroupMembership.student)).all()

    allowed_student_ids = _restricted_review_student_ids(user)
    pending_reviews = _apply_review_scope_to_submission_query(
        ProjectTaskSubmission.query.filter_by(status="pending_review"),
        user,
        allowed_student_ids=allowed_student_ids,
    ).order_by(ProjectTaskSubmission.submitted_at.asc()).all()
    for submission in pending_reviews:
        submission.has_warnings_for_this_task = _submission_has_warnings(submission.student, submission) if submission.student else False
        submission.visible_groups = _visible_groups_for_student(user, submission.student, mentor_group_ids=group_ids) if submission.student else []

    pending_by_student = defaultdict(list)
    pending_count_by_student = defaultdict(int)
    for submission in pending_reviews:
        if submission.student_id:
            pending_by_student[submission.student_id].append(submission)
            pending_count_by_student[submission.student_id] += 1

    notes = []
    if allowed_student_ids:
        notes = StudentPrivateNote.query.filter(
            StudentPrivateNote.student_id.in_(allowed_student_ids)
        ).order_by(StudentPrivateNote.created_at.desc()).all()
    note_count_by_student = defaultdict(int)
    latest_note_by_student = {}
    for note in notes:
        if note.student_id:
            note_count_by_student[note.student_id] += 1
            latest_note_by_student.setdefault(note.student_id, note)

    students_by_group = defaultdict(list)
    distinct_student_ids = set()
    for membership in memberships:
        if not membership.student or not membership.student_id:
            continue
        students_by_group[membership.group_id].append(membership.student)
        distinct_student_ids.add(membership.student_id)

    group_rows = []
    for group in groups:
        student_rows = []
        for student in sorted(students_by_group.get(group.id, []), key=lambda s: ((s.name or "").lower(), s.id)):
            student_rows.append({
                "student": student,
                "pending_count": pending_count_by_student.get(student.id, 0),
                "note_count": note_count_by_student.get(student.id, 0),
                "latest_note": latest_note_by_student.get(student.id),
                "latest_pending": pending_by_student.get(student.id, [None])[0],
            })
        group_rows.append({
            "group": group,
            "student_rows": student_rows,
            "student_count": len(student_rows),
            "pending_count": sum(row["pending_count"] for row in student_rows),
            "notes_count": sum(row["note_count"] for row in student_rows),
        })

    return render_template(
        "mentor_dashboard.html",
        group_rows=group_rows,
        pending_reviews=pending_reviews[:12],
        recent_notes=notes[:8],
        total_group_count=len(group_rows),
        total_student_count=len(distinct_student_ids),
        total_pending_count=len(pending_reviews),
        total_note_count=len(notes),
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/admin/reviews/dashboard")
@require_user()
def admin_review_dashboard():
    user = current_user()
    if not user or getattr(user, "role", "") == "mentor":
        abort(403)

    allowed_student_ids = _restricted_review_student_ids(user)
    now = datetime.utcnow()
    last_7_days = now - timedelta(days=7)
    last_30_days = now - timedelta(days=30)

    pending_query = _apply_review_scope_to_submission_query(
        ProjectTaskSubmission.query.filter_by(status="pending_review").options(
            subqueryload(ProjectTaskSubmission.project),
            subqueryload(ProjectTaskSubmission.task),
            subqueryload(ProjectTaskSubmission.student)
                .subqueryload(Student.group_memberships)
                .subqueryload(StudentGroupMembership.group),
        ),
        user,
        allowed_student_ids=allowed_student_ids,
    )
    pending_submissions = pending_query.order_by(ProjectTaskSubmission.submitted_at.asc()).all()

    reviewed_attempts = []
    reviewed_query = ProjectTaskAttempt.query.filter(
        ProjectTaskAttempt.reviewed_at != None
    ).join(
        ProjectTaskSubmission,
        ProjectTaskAttempt.submission_id == ProjectTaskSubmission.id,
    )
    if allowed_student_ids is not None:
        if allowed_student_ids:
            reviewed_query = reviewed_query.filter(ProjectTaskSubmission.student_id.in_(allowed_student_ids))
        else:
            reviewed_query = None
    if reviewed_query is not None:
        reviewed_attempts = reviewed_query.options(
            subqueryload(ProjectTaskAttempt.reviewer),
            subqueryload(ProjectTaskAttempt.submission).subqueryload(ProjectTaskSubmission.project),
            subqueryload(ProjectTaskAttempt.submission).subqueryload(ProjectTaskSubmission.task),
            subqueryload(ProjectTaskAttempt.submission).subqueryload(ProjectTaskSubmission.student)
                .subqueryload(Student.group_memberships)
                .subqueryload(StudentGroupMembership.group),
        ).order_by(ProjectTaskAttempt.reviewed_at.desc()).all()

    student_groups_cache = {}

    def student_groups_label(student):
        if not student or not student.id:
            return "—"
        cached = student_groups_cache.get(student.id)
        if cached is not None:
            return cached
        groups = _visible_groups_for_student(user, student)
        label = ", ".join(group.name for group in groups) if groups else "—"
        student_groups_cache[student.id] = label
        return label

    reviewer_stats = {}
    project_stats = {}
    student_stats = {}
    reviewed_waits = []
    reviewed_student_ids = set()
    reviewed_project_ids = set()
    accepted_review_count = 0
    rejected_review_count = 0
    reviews_last_7_days = 0
    reviews_last_30_days = 0
    recent_review_rows = []

    for attempt in reviewed_attempts:
        submission = attempt.submission
        student = submission.student if submission else None
        project = submission.project if submission else None
        task = submission.task if submission else None
        reviewer = attempt.reviewer
        wait_seconds = _review_wait_seconds(attempt)
        if wait_seconds is not None:
            reviewed_waits.append(wait_seconds)
        if student and student.id:
            reviewed_student_ids.add(student.id)
        if project and project.id:
            reviewed_project_ids.add(project.id)
        if attempt.status == "accepted":
            accepted_review_count += 1
        elif attempt.status == "rejected":
            rejected_review_count += 1
        if attempt.reviewed_at and attempt.reviewed_at >= last_7_days:
            reviews_last_7_days += 1
        if attempt.reviewed_at and attempt.reviewed_at >= last_30_days:
            reviews_last_30_days += 1

        reviewer_key = reviewer.id if reviewer and reviewer.id else 0
        reviewer_row = reviewer_stats.setdefault(reviewer_key, {
            "reviewer_name": reviewer.name if reviewer else "Unknown reviewer",
            "role_label": (getattr(reviewer, "role", "") or "staff").replace("_", " ").title() if reviewer else "Unknown",
            "total_reviews": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "wait_values": [],
            "recent_7d": 0,
            "last_reviewed_at": None,
            "student_ids": set(),
            "project_ids": set(),
        })
        reviewer_row["total_reviews"] += 1
        if attempt.status == "accepted":
            reviewer_row["accepted_count"] += 1
        elif attempt.status == "rejected":
            reviewer_row["rejected_count"] += 1
        if wait_seconds is not None:
            reviewer_row["wait_values"].append(wait_seconds)
        if attempt.reviewed_at and attempt.reviewed_at >= last_7_days:
            reviewer_row["recent_7d"] += 1
        if attempt.reviewed_at and (
            reviewer_row["last_reviewed_at"] is None or attempt.reviewed_at > reviewer_row["last_reviewed_at"]
        ):
            reviewer_row["last_reviewed_at"] = attempt.reviewed_at
        if student and student.id:
            reviewer_row["student_ids"].add(student.id)
        if project and project.id:
            reviewer_row["project_ids"].add(project.id)

        project_key = project.id if project and project.id else 0
        project_row = project_stats.setdefault(project_key, {
            "project_title": project.title if project else "Unknown project",
            "pending_count": 0,
            "reviewed_count": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "wait_values": [],
            "student_ids": set(),
            "last_reviewed_at": None,
            "oldest_pending_seconds": None,
        })
        project_row["reviewed_count"] += 1
        if attempt.status == "accepted":
            project_row["accepted_count"] += 1
        elif attempt.status == "rejected":
            project_row["rejected_count"] += 1
        if wait_seconds is not None:
            project_row["wait_values"].append(wait_seconds)
        if student and student.id:
            project_row["student_ids"].add(student.id)
        if attempt.reviewed_at and (
            project_row["last_reviewed_at"] is None or attempt.reviewed_at > project_row["last_reviewed_at"]
        ):
            project_row["last_reviewed_at"] = attempt.reviewed_at

        if student and student.id:
            student_row = student_stats.setdefault(student.id, {
                "student_name": student.name,
                "student_email": student.email,
                "groups_label": student_groups_label(student),
                "pending_count": 0,
                "reviewed_count": 0,
                "accepted_count": 0,
                "rejected_count": 0,
                "wait_values": [],
                "last_reviewed_at": None,
                "last_status": None,
            })
            student_row["reviewed_count"] += 1
            if attempt.status == "accepted":
                student_row["accepted_count"] += 1
            elif attempt.status == "rejected":
                student_row["rejected_count"] += 1
            if wait_seconds is not None:
                student_row["wait_values"].append(wait_seconds)
            if attempt.reviewed_at and (
                student_row["last_reviewed_at"] is None or attempt.reviewed_at > student_row["last_reviewed_at"]
            ):
                student_row["last_reviewed_at"] = attempt.reviewed_at
                student_row["last_status"] = attempt.status

        if len(recent_review_rows) < 24:
            review_notes = (attempt.review_notes or (submission.review_notes if submission else "") or "").strip()
            if len(review_notes) > 140:
                review_notes = review_notes[:137].rstrip() + "..."
            recent_review_rows.append({
                "reviewed_at": attempt.reviewed_at,
                "reviewer_name": reviewer.name if reviewer else "Unknown reviewer",
                "student_name": submission.student_name if submission and submission.student_name else "Unknown",
                "student_groups": student_groups_label(student),
                "project_title": project.title if project else "—",
                "task_title": task.title if task else "—",
                "attempt_number": attempt.attempt_number,
                "status": attempt.status or "reviewed",
                "wait_display": _format_duration(wait_seconds) if wait_seconds is not None else "—",
                "review_notes": review_notes,
                "submission_id": submission.id if submission else None,
            })

    pending_queue_rows = []
    queue_waits = []
    pending_student_ids = set()
    pending_project_ids = set()
    pending_24h_count = 0
    pending_72h_count = 0
    oldest_pending_seconds = None

    for submission in pending_submissions:
        student = submission.student
        project = submission.project
        task = submission.task
        wait_seconds = _pending_review_age_seconds(submission, now=now)
        if wait_seconds is not None:
            queue_waits.append(wait_seconds)
            if wait_seconds >= 24 * 3600:
                pending_24h_count += 1
            if wait_seconds >= 72 * 3600:
                pending_72h_count += 1
            oldest_pending_seconds = max(oldest_pending_seconds or 0, wait_seconds)
        if student and student.id:
            pending_student_ids.add(student.id)
        if project and project.id:
            pending_project_ids.add(project.id)

        project_key = project.id if project and project.id else 0
        project_row = project_stats.setdefault(project_key, {
            "project_title": project.title if project else "Unknown project",
            "pending_count": 0,
            "reviewed_count": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "wait_values": [],
            "student_ids": set(),
            "last_reviewed_at": None,
            "oldest_pending_seconds": None,
        })
        project_row["pending_count"] += 1
        if student and student.id:
            project_row["student_ids"].add(student.id)
        if wait_seconds is not None:
            project_row["oldest_pending_seconds"] = max(project_row["oldest_pending_seconds"] or 0, wait_seconds)

        if student and student.id:
            student_row = student_stats.setdefault(student.id, {
                "student_name": student.name,
                "student_email": student.email,
                "groups_label": student_groups_label(student),
                "pending_count": 0,
                "reviewed_count": 0,
                "accepted_count": 0,
                "rejected_count": 0,
                "wait_values": [],
                "last_reviewed_at": None,
                "last_status": None,
            })
            student_row["pending_count"] += 1

        if len(pending_queue_rows) < 18:
            pending_queue_rows.append({
                "submitted_at": submission.submitted_at,
                "student_name": submission.student_name or "Unknown",
                "student_groups": student_groups_label(student),
                "project_title": project.title if project else "—",
                "task_title": task.title if task else "—",
                "waiting_display": _format_duration(wait_seconds) if wait_seconds is not None else "—",
                "submission_id": submission.id,
            })

    total_reviews = len(reviewed_attempts)
    avg_wait_seconds = (sum(reviewed_waits) / len(reviewed_waits)) if reviewed_waits else None
    median_wait_seconds = _median(reviewed_waits)
    avg_pending_seconds = (sum(queue_waits) / len(queue_waits)) if queue_waits else None
    daily_review_rate = reviews_last_7_days / 7.0 if reviews_last_7_days else 0.0
    backlog_days = (len(pending_submissions) / daily_review_rate) if daily_review_rate > 0 else None

    reviewer_rows = []
    max_reviewer_total = max((row["total_reviews"] for row in reviewer_stats.values()), default=0)
    for row in reviewer_stats.values():
        wait_values = row.pop("wait_values")
        avg_row_wait = (sum(wait_values) / len(wait_values)) if wait_values else None
        row["avg_wait_display"] = _format_duration(avg_row_wait) if avg_row_wait is not None else "—"
        row["median_wait_display"] = _format_duration(_median(wait_values)) if wait_values else "—"
        row["student_count"] = len(row.pop("student_ids"))
        row["project_count"] = len(row.pop("project_ids"))
        row["acceptance_rate"] = (row["accepted_count"] / row["total_reviews"] * 100.0) if row["total_reviews"] else 0.0
        row["share_pct"] = (row["total_reviews"] / max_reviewer_total * 100.0) if max_reviewer_total else 0.0
        reviewer_rows.append(row)
    reviewer_rows.sort(
        key=lambda row: (
            -row["total_reviews"],
            -row["recent_7d"],
            (row["reviewer_name"] or "").lower(),
        )
    )

    project_rows = []
    max_project_load = max(
        (row["pending_count"] + row["reviewed_count"] for row in project_stats.values()),
        default=0,
    )
    for row in project_stats.values():
        wait_values = row.pop("wait_values")
        total_project_activity = row["pending_count"] + row["reviewed_count"]
        avg_row_wait = (sum(wait_values) / len(wait_values)) if wait_values else None
        row["avg_wait_display"] = _format_duration(avg_row_wait) if avg_row_wait is not None else "—"
        row["student_count"] = len(row.pop("student_ids"))
        row["acceptance_rate"] = (row["accepted_count"] / row["reviewed_count"] * 100.0) if row["reviewed_count"] else 0.0
        row["share_pct"] = (total_project_activity / max_project_load * 100.0) if max_project_load else 0.0
        row["oldest_pending_display"] = _format_duration(row["oldest_pending_seconds"]) if row["oldest_pending_seconds"] is not None else "—"
        row["activity_total"] = total_project_activity
        project_rows.append(row)
    project_rows.sort(
        key=lambda row: (
            -row["pending_count"],
            -row["reviewed_count"],
            (row["project_title"] or "").lower(),
        )
    )

    student_rows = []
    max_student_load = max(
        (row["pending_count"] + row["reviewed_count"] for row in student_stats.values()),
        default=0,
    )
    for row in student_stats.values():
        wait_values = row.pop("wait_values")
        total_student_activity = row["pending_count"] + row["reviewed_count"]
        avg_row_wait = (sum(wait_values) / len(wait_values)) if wait_values else None
        row["avg_wait_display"] = _format_duration(avg_row_wait) if avg_row_wait is not None else "—"
        row["share_pct"] = (total_student_activity / max_student_load * 100.0) if max_student_load else 0.0
        row["activity_total"] = total_student_activity
        student_rows.append(row)
    student_rows.sort(
        key=lambda row: (
            -row["pending_count"],
            -row["reviewed_count"],
            (row["student_name"] or "").lower(),
        )
    )

    return render_template(
        "admin_review_dashboard.html",
        total_pending_count=len(pending_submissions),
        total_reviewed_count=total_reviews,
        unique_reviewer_count=sum(1 for row in reviewer_rows if row["reviewer_name"] != "Unknown reviewer"),
        unique_student_count=len(reviewed_student_ids),
        reviewed_project_count=len(reviewed_project_ids),
        queue_student_count=len(pending_student_ids),
        queue_project_count=len(pending_project_ids),
        accepted_review_count=accepted_review_count,
        rejected_review_count=rejected_review_count,
        acceptance_rate=((accepted_review_count / total_reviews) * 100.0) if total_reviews else 0.0,
        avg_wait_display=_format_duration(avg_wait_seconds) if avg_wait_seconds is not None else "—",
        median_wait_display=_format_duration(median_wait_seconds) if median_wait_seconds is not None else "—",
        avg_pending_display=_format_duration(avg_pending_seconds) if avg_pending_seconds is not None else "—",
        oldest_pending_display=_format_duration(oldest_pending_seconds) if oldest_pending_seconds is not None else "—",
        pending_24h_count=pending_24h_count,
        pending_72h_count=pending_72h_count,
        reviews_last_7_days=reviews_last_7_days,
        reviews_last_30_days=reviews_last_30_days,
        backlog_days=backlog_days,
        reviewer_rows=reviewer_rows[:10],
        project_rows=project_rows[:10],
        student_rows=student_rows[:12],
        pending_queue_rows=pending_queue_rows,
        recent_review_rows=recent_review_rows,
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/students/<int:student_id>/notes", methods=["GET", "POST"])
@require_user()
def student_private_notes(student_id):
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    mentor_group_ids = _mentor_group_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)

    error = None
    if request.method == "POST":
        if not verify_csrf():
            abort(400, "bad csrf")
        body = (request.form.get("body") or "").strip()
        if not body:
            error = "Note text is required."
        else:
            db.session.add(StudentPrivateNote(
                student_id=student.id,
                author_user_id=(user.id if user else None),
                body=body,
            ))
            db.session.commit()
            return redirect(url_for("student_private_notes", student_id=student.id))

    notes = StudentPrivateNote.query.filter_by(student_id=student.id).order_by(StudentPrivateNote.created_at.desc()).all()
    pending_reviews = ProjectTaskSubmission.query.filter_by(
        student_id=student.id,
        status="pending_review",
    ).order_by(ProjectTaskSubmission.submitted_at.desc()).all()
    groups = _visible_groups_for_student(user, student, mentor_group_ids=mentor_group_ids)

    return render_template(
        "student_private_notes.html",
        student=student,
        notes=notes,
        pending_reviews=pending_reviews,
        groups=groups,
        error=error,
        current_user_id=(user.id if user else None),
        unrestricted_note_delete=(getattr(user, "role", "") != "mentor"),
        user=user,
        student_name=session.get("student_name"),
    )

@app.post("/students/<int:student_id>/notes/<int:note_id>/delete")
@require_user()
def student_private_note_delete(student_id, note_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
    note = StudentPrivateNote.query.filter_by(id=note_id, student_id=student.id).first_or_404()
    if not _can_user_manage_private_note(user, note, allowed_student_ids=allowed_student_ids):
        abort(403)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("student_private_notes", student_id=student.id))

# --------------------------------------------------------------------
# Gradebook
# --------------------------------------------------------------------

@app.route("/grades", methods=["GET", "POST"])
@require_user()
def grades_admin():
    message = session.pop("grades_status", None)
    error = session.pop("grades_error", None)
    search_filters = _grades_search_filters_from_request(request.values)
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
            return redirect(_grades_admin_url(search_filters))
        if not assignment:
            session["grades_error"] = "Assignment/test name is required."
            return redirect(_grades_admin_url(search_filters))
        try:
            score = float(score_raw)
            max_score = float(max_raw)
        except Exception:
            session["grades_error"] = "Score and maximum score must be numbers."
            return redirect(_grades_admin_url(search_filters))
        _create_grade_entry(student, assignment, score, max_score, remarks)
        db.session.commit()
        session["grades_status"] = f"Recorded grade for {student.name}."
        return redirect(_grades_admin_url(search_filters))

    has_filters = bool(search_filters["student_query"] or search_filters["assignment_query"])
    query = _grades_query(search_filters)
    grades = query.all() if has_filters else query.limit(200).all()
    return render_template(
        "grades_admin.html",
        grades=grades,
        has_filters=has_filters,
        message=message,
        error=error,
        search_filters=search_filters,
        user=current_user(),
        student_name=session.get("student_name"),
    )

@app.post("/grades/<int:grade_id>/update")
@require_user()
def grades_update(grade_id):
    if not verify_csrf():
        abort(400, "bad csrf")
    search_filters = _grades_search_filters_from_request(request.form)
    grade = Grade.query.get_or_404(grade_id)
    score_raw = request.form.get("score") or ""
    max_raw = request.form.get("max_score") or ""
    remarks = (request.form.get("remarks") or "").strip()
    try:
        grade.score = float(score_raw)
        grade.max_score = float(max_raw)
    except Exception:
        session["grades_error"] = "Score and maximum score must be numbers."
        return redirect(_grades_admin_url(search_filters))
    grade.remarks = remarks or None
    db.session.commit()
    session["grades_status"] = f"Updated grade for {grade.student_name}."
    return redirect(_grades_admin_url(search_filters))

@app.post("/grades/import")
@require_user()
def grades_import():
    if not verify_csrf():
        abort(400, "bad csrf")
    search_filters = _grades_search_filters_from_request(request.form)
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
            return redirect(_grades_admin_url(search_filters))
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
            return redirect(_grades_admin_url(search_filters))

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
    return redirect(_grades_admin_url(search_filters))

@app.get("/grades/export")
@require_user()
def grades_export():
    search_filters = _grades_search_filters_from_request(request.args)
    fmt = (request.args.get("format") or "csv").strip().lower()
    has_filters = bool(search_filters["student_query"] or search_filters["assignment_query"])
    query = _grades_query(search_filters)
    grades = query.all() if has_filters else query.limit(200).all()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        response = make_response(
            json.dumps([_serialize_grade_export_row(grade) for grade in grades], indent=2, ensure_ascii=False)
        )
        response.mimetype = "application/json"
        response.headers["Content-Disposition"] = f'attachment; filename="grades_{timestamp}.json"'
        return response

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id",
            "student_name",
            "student_email",
            "assignment",
            "score",
            "max_score",
            "remarks",
            "created_at",
            "updated_at",
        ])
        for grade in grades:
            row = _serialize_grade_export_row(grade)
            writer.writerow([
                row["id"],
                row["student_name"],
                row["student_email"],
                row["assignment"],
                row["score"],
                row["max_score"],
                row["remarks"],
                row["created_at"],
                row["updated_at"],
            ])
        response = make_response(output.getvalue())
        response.mimetype = "text/csv"
        response.headers["Content-Disposition"] = f'attachment; filename="grades_{timestamp}.csv"'
        return response

    abort(400, "unsupported export format")

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
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    students_query = _apply_review_scope_to_student_query(
        Student.query,
        user,
        allowed_student_ids=allowed_student_ids,
    )
    # Get all flagged students
    flagged = students_query.filter_by(is_flagged=True).order_by(Student.name.asc()).all()
    
    # Get students with warnings but not flagged
    all_students = students_query.filter(Student.warnings_json != None).order_by(Student.name.asc()).all()
    warned = [s for s in all_students if not s.is_flagged and s.warnings_json and len(s.warnings_json) > 0]
    
    return render_template(
        "warnings_list.html",
        flagged_students=flagged,
        warned_students=warned,
        review_scope_limited=_review_scope_limited(user, allowed_student_ids=allowed_student_ids),
        user=user,
        student_name=session.get("student_name"),
    )

@app.route("/warnings/student/<int:student_id>")
@require_user()
def warnings_student_detail(student_id):
    """View detailed warnings for a specific student."""
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
        user=user,
        student_name=session.get("student_name"),
    )

@app.post("/warnings/student/<int:student_id>/flag")
@require_user()
def warnings_flag_student(student_id):
    """Manually flag a student."""
    if not verify_csrf():
        abort(400, "bad csrf")
    
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    
    user = current_user()
    allowed_student_ids = _restricted_review_student_ids(user)
    student = Student.query.get_or_404(student_id)
    if not _can_user_review_student(user, student, allowed_student_ids=allowed_student_ids):
        abort(403)
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
    user = current_user()
    if user and getattr(user, "role", "") == "mentor":
        return redirect(url_for("mentor_dashboard"))
    if user and getattr(user, "role", "") == "admin":
        return redirect(url_for("admin_review_dashboard"))
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
