
import json
from datetime import datetime, timedelta, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy import UniqueConstraint, func
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()

class JSONText(TypeDecorator):
    impl = TEXT
    cache_ok = True
    def process_bind_param(self, value, dialect):
        if value is None: return None
        return json.dumps(value, ensure_ascii=False)
    def process_result_value(self, value, dialect):
        if value is None: return None
        return json.loads(value)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="instructor")
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    first_login = db.Column(db.Boolean, nullable=False, default=True)
    last_login  = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    first_login = db.Column(db.Boolean, nullable=False, default=True)
    last_login  = db.Column(db.DateTime, nullable=True)
    # Last activity timestamp (updated on each student request)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    # Warning system fields
    warnings_json = db.Column(JSONText, nullable=True, default=list)  # List of warning records
    is_flagged = db.Column(db.Boolean, nullable=False, default=False)  # Quick flag for cheater tag
    flag_notes = db.Column(db.Text, nullable=True)  # Admin notes about the flag

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

    @property
    def groups(self):
        return [m.group for m in getattr(self, "group_memberships", []) if m.group]


class StudentGroup(db.Model):
    __tablename__ = "student_groups"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class StudentGroupMembership(db.Model):
    __tablename__ = "student_group_memberships"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('student_groups.id', ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    student = db.relationship('Student', backref=db.backref('group_memberships', cascade="all,delete-orphan"))
    group = db.relationship('StudentGroup', backref=db.backref('memberships', cascade="all,delete-orphan"))

    __table_args__ = (
        UniqueConstraint('student_id', 'group_id', name='uq_student_group_membership'),
    )

class StudentGroupReviewer(db.Model):
    __tablename__ = "student_group_reviewers"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('student_groups.id', ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref=db.backref('group_reviews', cascade="all,delete-orphan"))
    group = db.relationship('StudentGroup', backref=db.backref('reviewers', cascade="all,delete-orphan"))

    __table_args__ = (
        UniqueConstraint('user_id', 'group_id', name='uq_group_reviewer'),
    )

class AttendanceSheet(db.Model):
    __tablename__ = "attendance_sheets"
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('student_groups.id', ondelete="SET NULL"), nullable=True)
    group_name = db.Column(db.String(120), nullable=True)
    title = db.Column(db.String(120), nullable=False, default="Session")
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True)

    group = db.relationship('StudentGroup')
    creator = db.relationship('User')

class AttendanceEntry(db.Model):
    __tablename__ = "attendance_entries"
    id = db.Column(db.Integer, primary_key=True)
    sheet_id = db.Column(db.Integer, db.ForeignKey('attendance_sheets.id', ondelete="CASCADE"), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(16), nullable=False, default="present")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    sheet = db.relationship('AttendanceSheet', backref=db.backref('entries', cascade="all,delete-orphan"))
    student = db.relationship('Student')

    __table_args__ = (
        UniqueConstraint('sheet_id', 'student_id', name='uq_attendance_sheet_student'),
    )

class Leaderboard(db.Model):
    __tablename__ = "leaderboards"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    metric = db.Column(db.String(64), nullable=False)  # total_points | projects_done | logtime
    group_id = db.Column(db.Integer, db.ForeignKey('student_groups.id', ondelete="SET NULL"), nullable=True)
    params_json = db.Column(JSONText, nullable=True)
    is_published = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    group = db.relationship('StudentGroup')

class Form(db.Model):
    __tablename__ = "forms"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    schema_json = db.Column(JSONText, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')
    # NEW:
    closes_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_open(self):
        return (self.closes_at is None) or (datetime.now(timezone.utc).replace(tzinfo=None) < self.closes_at)

class FormResponse(db.Model):
    __tablename__ = "form_responses"
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('forms.id', ondelete="CASCADE"), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), index=True, nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    payload_json = db.Column(JSONText, nullable=False)  # submitted answers
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    form = db.relationship('Form', backref=db.backref('responses', cascade="all,delete-orphan"))
    student = db.relationship('Student')

class Exam(db.Model):
    __tablename__ = "exams"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    instructions = db.Column(db.Text, nullable=True)
    questions_json = db.Column(JSONText, nullable=False)
    settings_json = db.Column(JSONText, nullable=True)
    starts_at = db.Column(db.DateTime, nullable=True)
    ends_at = db.Column(db.DateTime, nullable=True)
    duration_minutes = db.Column(db.Integer, nullable=True)
    is_open = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')
    access_password_hash = db.Column(db.String(255), nullable=True)

    @property
    def is_available(self):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if not self.is_open:
            return False
        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now > self.ends_at:
            return False
        return True

    def set_access_password(self, password):
        password = (password or "").strip()
        if not password:
            self.access_password_hash = None
        else:
            self.access_password_hash = generate_password_hash(password)

    def check_access_password(self, password):
        if not self.access_password_hash:
            return True
        return check_password_hash(self.access_password_hash, password or "")

class ExamSubmission(db.Model):
    __tablename__ = "exam_submissions"
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exams.id', ondelete="CASCADE"), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), index=True, nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    answers_json = db.Column(JSONText, nullable=False, default=dict)
    run_logs = db.Column(JSONText, nullable=False, default=list)
    status = db.Column(db.String(32), nullable=False, default="in_progress")  # in_progress|submitted
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    score = db.Column(db.Float, default=0.0, nullable=False)
    max_score = db.Column(db.Float, default=0.0, nullable=False)
    grading_json = db.Column(JSONText, nullable=True)

    exam = db.relationship('Exam', backref=db.backref('submissions', cascade="all,delete-orphan"))
    student = db.relationship('Student')

    __table_args__ = (
        UniqueConstraint('exam_id', 'student_id', name='uq_exam_submission_student'),
    )

class StudentStats(db.Model):
    __tablename__ = "student_stats"
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), primary_key=True)
    times_spoken = db.Column(db.Integer, default=0, nullable=False)
    last_spoken_at = db.Column(db.DateTime)
    current_round_done = db.Column(db.Boolean, default=False, nullable=False)

class StudentLogSession(db.Model):
    __tablename__ = "student_log_sessions"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ended_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    student = db.relationship('Student')

class Intervention(db.Model):
    __tablename__ = "interventions"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    section = db.Column(db.String(120))
    duration_sec = db.Column(db.Integer, default=120, nullable=False)
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="picked", nullable=False)  # picked|running|completed|skipped
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Grade(db.Model):
    __tablename__ = "grades"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    student_name = db.Column(db.String(120), nullable=False)
    assignment = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Float, nullable=False, default=0.0)
    max_score = db.Column(db.Float, nullable=False, default=0.0)
    remarks = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    student = db.relationship('Student')

class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    instructions = db.Column(db.Text, nullable=True)
    required_task_count = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Points awarded once upon first project completion; retry cooldown (minutes) applies after rejected submissions.
    points = db.Column(db.Integer, nullable=False, default=0)
    retry_cooldown_minutes = db.Column(db.Integer, nullable=False, default=0)
    # Proficiency gating: if set, student must have this tag to access project
    required_proficiency_tag = db.Column(db.String(64), nullable=True)
    # Deadline fields
    starts_at = db.Column(db.DateTime, nullable=True)  # When project becomes available
    due_at = db.Column(db.DateTime, nullable=True)  # Soft deadline - late penalty applies after
    hard_deadline_at = db.Column(db.DateTime, nullable=True)  # Hard cutoff - no submissions after
    late_penalty_percent = db.Column(db.Float, nullable=False, default=0.0)  # Percentage deduction for late work
    # Time window availability (recurring weekly schedule)
    availability_enabled = db.Column(db.Boolean, nullable=False, default=False)  # Whether to enforce time windows
    availability_rules = db.Column(db.Text, nullable=True)  # JSON: weekly schedule {day: [{start, end}]}

# --------------------------
# Blog
# --------------------------
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    is_published = db.Column(db.Boolean, nullable=False, default=True)

    author = db.relationship("User", backref="blog_posts")
    comments = db.relationship("BlogComment", back_populates="post", cascade="all,delete-orphan")

class BlogComment(db.Model):
    __tablename__ = "blog_comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id', ondelete="CASCADE"), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=True)
    author_name = db.Column(db.String(120), nullable=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    post = db.relationship("BlogPost", back_populates="comments")
    author = db.relationship("User", backref="blog_comments")


class ProjectGroupAssignment(db.Model):
    __tablename__ = "project_group_assignments"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete="CASCADE"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('student_groups.id', ondelete="CASCADE"), nullable=True)
    applies_to_all = db.Column(db.Boolean, nullable=False, default=False)
    is_required = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    project = db.relationship('Project', backref=db.backref('group_assignments', cascade="all,delete-orphan"))
    group = db.relationship('StudentGroup')

class ProjectDependency(db.Model):
    __tablename__ = "project_dependencies"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete="CASCADE"), nullable=False)
    prerequisite_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete="CASCADE"), nullable=False)

    project = db.relationship('Project', foreign_keys=[project_id], backref=db.backref('dependencies', cascade="all,delete-orphan"))
    prerequisite = db.relationship('Project', foreign_keys=[prerequisite_id])

class ProjectTask(db.Model):
    __tablename__ = "project_tasks"
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    instructions = db.Column(db.Text, nullable=True)
    questions_json = db.Column(JSONText, nullable=False)
    resource_file = db.Column(JSONText, nullable=True)
    required = db.Column(db.Boolean, nullable=False, default=True)
    auto_grade = db.Column(db.Boolean, nullable=False, default=True)
    requires_review = db.Column(db.Boolean, nullable=False, default=False)
    order_index = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    project = db.relationship('Project', backref=db.backref('tasks', cascade="all,delete-orphan", order_by="ProjectTask.order_index"))

class ProjectTaskSubmission(db.Model):
    __tablename__ = "project_task_submissions"
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('project_tasks.id', ondelete="CASCADE"), index=True, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete="CASCADE"), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), index=True, nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    answers_json = db.Column(JSONText, nullable=False, default=dict)
    run_logs = db.Column(JSONText, nullable=False, default=list)
    status = db.Column(db.String(32), nullable=False, default="in_progress")  # in_progress|submitted|pending_review|accepted|rejected
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    score = db.Column(db.Float, default=0.0, nullable=False)
    max_score = db.Column(db.Float, default=0.0, nullable=False)
    review_notes = db.Column(db.Text, nullable=True)

    task = db.relationship('ProjectTask', backref=db.backref('submissions', cascade="all,delete-orphan"))
    project = db.relationship('Project')
    student = db.relationship('Student')

    __table_args__ = (
        UniqueConstraint('task_id', 'student_id', name='uq_project_task_student'),
    )

class ProjectTaskAttempt(db.Model):
    __tablename__ = "project_task_attempts"
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('project_task_submissions.id', ondelete="CASCADE"), index=True, nullable=False)
    attempt_number = db.Column(db.Integer, nullable=False, default=1)
    answers_json = db.Column(JSONText, nullable=False, default=dict)
    run_logs = db.Column(JSONText, nullable=False, default=list)
    status = db.Column(db.String(32), nullable=False, default="submitted")
    score = db.Column(db.Float, default=0.0, nullable=False)
    max_score = db.Column(db.Float, default=0.0, nullable=False)
    grading_json = db.Column(JSONText, nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True)
    review_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    submission = db.relationship(
        'ProjectTaskSubmission',
        backref=db.backref('attempts', cascade="all,delete-orphan", order_by="ProjectTaskAttempt.attempt_number"),
    )
    reviewer = db.relationship('User')

    __table_args__ = (
        UniqueConstraint('submission_id', 'attempt_number', name='uq_project_task_attempt_number'),
    )

# --------------------------
# Proficiency Test System
# --------------------------

class ProficiencyExercise(db.Model):
    """Pool of exercises for proficiency tests."""
    __tablename__ = "proficiency_exercises"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)  # Problem statement
    instructions = db.Column(db.Text, nullable=True)  # Additional instructions
    starter_code = db.Column(db.Text, nullable=True)  # Initial code template
    # Test cases: {"visible": [...], "hidden": [...]}
    # Each test case: {"input": "...", "expected_output": "...", "description": "..."}
    test_cases_json = db.Column(JSONText, nullable=False, default=dict)
    time_limit_sec = db.Column(db.Float, nullable=False, default=3.0)  # Per test case
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Link to learning outcome
    outcome_tag = db.Column(db.String(64), db.ForeignKey('learning_outcomes.tag_name', onupdate="CASCADE"), nullable=True, index=True)
    difficulty_level = db.Column(db.Integer, nullable=False, default=1)  # 1=basic, 2=intermediate, 3=advanced
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True)

    creator = db.relationship('User')

    @property
    def visible_test_cases(self):
        tc = self.test_cases_json or {}
        return tc.get("visible", [])

    @property
    def hidden_test_cases(self):
        tc = self.test_cases_json or {}
        return tc.get("hidden", [])


class ProficiencyTestConfig(db.Model):
    """Global configuration for proficiency tests."""
    __tablename__ = "proficiency_test_config"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False, default="Python Proficiency Test")
    description = db.Column(db.Text, nullable=True)
    exercise_count = db.Column(db.Integer, nullable=False, default=3)  # Number of exercises per test
    duration_minutes = db.Column(db.Integer, nullable=False, default=60)  # Test duration
    cooldown_hours = db.Column(db.Integer, nullable=False, default=48)  # Hours before retry
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class ProficiencyTestAttempt(db.Model):
    """A student's test attempt with randomly selected exercises."""
    __tablename__ = "proficiency_test_attempts"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    
    # Link to specific learning outcome (if outcome-based test)
    outcome_tag = db.Column(db.String(64), db.ForeignKey('learning_outcomes.tag_name', onupdate="CASCADE"), nullable=True, index=True)
    
    # Snapshot of config at time of test
    duration_minutes = db.Column(db.Integer, nullable=False, default=60)
    # Status: in_progress | submitted | passed | failed
    status = db.Column(db.String(32), nullable=False, default="in_progress")
    
    # Score tracking
    final_score = db.Column(db.Float, nullable=True)  # 0.0-1.0 percentage
    
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    student = db.relationship('Student', backref=db.backref('proficiency_attempts', cascade="all,delete-orphan"))
    reviewer = db.relationship('User')

    @property
    def is_expired(self):
        if self.status != "in_progress":
            return False
        deadline = self.started_at + timedelta(minutes=self.duration_minutes)
        return datetime.now(timezone.utc).replace(tzinfo=None) > deadline

    @property
    def time_remaining_sec(self):
        if self.status != "in_progress":
            return 0
        deadline = self.started_at + timedelta(minutes=self.duration_minutes)
        remaining = (deadline - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()
        return max(0, remaining)


class ProficiencyExerciseSubmission(db.Model):
    """Student's submission for one exercise within a test attempt."""
    __tablename__ = "proficiency_exercise_submissions"
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('proficiency_test_attempts.id', ondelete="CASCADE"), index=True, nullable=False)
    exercise_id = db.Column(db.Integer, db.ForeignKey('proficiency_exercises.id', ondelete="SET NULL"), nullable=True)
    # Snapshot of exercise at submission time
    exercise_title = db.Column(db.String(255), nullable=False)
    exercise_description = db.Column(db.Text, nullable=True)
    exercise_instructions = db.Column(db.Text, nullable=True)
    exercise_starter_code = db.Column(db.Text, nullable=True)
    exercise_test_cases_json = db.Column(JSONText, nullable=True)  # Full snapshot
    # Student's work
    code = db.Column(db.Text, nullable=True)  # Student's submitted code
    run_logs = db.Column(JSONText, nullable=False, default=list)  # Test run history
    # Grading results after submission
    visible_results_json = db.Column(JSONText, nullable=True)  # Results of visible tests
    hidden_results_json = db.Column(JSONText, nullable=True)   # Results of hidden tests
    visible_passed = db.Column(db.Integer, default=0, nullable=False)
    visible_total = db.Column(db.Integer, default=0, nullable=False)
    hidden_passed = db.Column(db.Integer, default=0, nullable=False)
    hidden_total = db.Column(db.Integer, default=0, nullable=False)
    order_index = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    attempt = db.relationship('ProficiencyTestAttempt', backref=db.backref('submissions', cascade="all,delete-orphan", order_by="ProficiencyExerciseSubmission.order_index"))
    exercise = db.relationship('ProficiencyExercise')


class StudentProficiencyTag(db.Model):
    """Proficiency tags earned by students upon passing tests."""
    __tablename__ = "student_proficiency_tags"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    tag_name = db.Column(db.String(64), nullable=False, default="python")  # e.g., "python", "advanced_python"
    attempt_id = db.Column(db.Integer, db.ForeignKey('proficiency_test_attempts.id', ondelete="SET NULL"), nullable=True)
    awarded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    awarded_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), nullable=True)

    student = db.relationship('Student', backref=db.backref('proficiency_tags', cascade="all,delete-orphan"))
    attempt = db.relationship('ProficiencyTestAttempt')
    awarded_by = db.relationship('User')

    __table_args__ = (
        UniqueConstraint('student_id', 'tag_name', name='uq_student_proficiency_tag'),
    )


class LearningOutcome(db.Model):
    """Defines a learning outcome/competency area (e.g., 'recursion_basic', 'algorithms_sorting')."""
    __tablename__ = "learning_outcomes"
    id = db.Column(db.Integer, primary_key=True)
    
    # Unique identifier (e.g., "recursion_basic", "algorithms_sorting")
    tag_name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    # Display information
    display_name = db.Column(db.String(120), nullable=False)  # "Recursion (Basic)"
    description = db.Column(db.Text, nullable=True)
    icon_emoji = db.Column(db.String(10), nullable=True, default="📚")  # "🔁" for recursion
    
    # Domain categorization
    domain = db.Column(db.String(64), nullable=False, index=True)  # "fundamentals", "data_structures", "recursion", etc.
    domain_display = db.Column(db.String(120), nullable=False)  # "Programming Fundamentals & Python Proficiency"
    
    # Difficulty & progression (1=basic, 2=intermediate, 3=advanced)
    difficulty_level = db.Column(db.Integer, nullable=False, default=1)
    
    # Week in curriculum (for ordering)
    week_number = db.Column(db.Integer, nullable=True)
    
    # Prerequisites (JSON array of tag_names that must be passed first)
    prerequisites_json = db.Column(JSONText, nullable=True, default=list)
    
    # Test configuration for this specific outcome
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    exercise_count = db.Column(db.Integer, nullable=False, default=2)  # Micro-tests
    duration_minutes = db.Column(db.Integer, nullable=False, default=15)
    cooldown_hours = db.Column(db.Integer, nullable=False, default=24)
    passing_threshold = db.Column(db.Float, nullable=False, default=0.75)  # 75% to pass
    
    # Ordering/display priority
    display_order = db.Column(db.Integer, nullable=False, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    @property
    def prerequisites(self):
        """Get list of prerequisite tag names."""
        return self.prerequisites_json if isinstance(self.prerequisites_json, list) else []


class StudentOutcomeProgress(db.Model):
    """Track student progress per learning outcome (including failed attempts)."""
    __tablename__ = "student_outcome_progress"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    outcome_tag = db.Column(db.String(64), db.ForeignKey('learning_outcomes.tag_name', onupdate="CASCADE"), nullable=False, index=True)
    
    # Progress tracking
    attempts = db.Column(db.Integer, nullable=False, default=0)
    best_score = db.Column(db.Float, nullable=True)  # Best % across attempts (0.0-1.0)
    is_unlocked = db.Column(db.Boolean, nullable=False, default=False)  # Prerequisites met
    is_passed = db.Column(db.Boolean, nullable=False, default=False)
    
    # Timestamps
    first_attempt_at = db.Column(db.DateTime, nullable=True)
    last_attempt_at = db.Column(db.DateTime, nullable=True)
    passed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    student = db.relationship('Student', backref=db.backref('outcome_progress', cascade="all,delete-orphan"))
    outcome = db.relationship('LearningOutcome', backref='student_progress')
    
    __table_args__ = (
        UniqueConstraint('student_id', 'outcome_tag', name='uq_student_outcome_progress'),
    )
