
import json
from datetime import datetime
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
        return (self.closes_at is None) or (datetime.utcnow() < self.closes_at)

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
        now = datetime.utcnow()
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
    # Deadline fields
    starts_at = db.Column(db.DateTime, nullable=True)  # When project becomes available
    due_at = db.Column(db.DateTime, nullable=True)  # Soft deadline - late penalty applies after
    hard_deadline_at = db.Column(db.DateTime, nullable=True)  # Hard cutoff - no submissions after
    late_penalty_percent = db.Column(db.Float, nullable=False, default=0.0)  # Percentage deduction for late work

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
    score = db.Column(db.Float, default=0.0, nullable=False)
    max_score = db.Column(db.Float, default=0.0, nullable=False)
    review_notes = db.Column(db.Text, nullable=True)

    task = db.relationship('ProjectTask', backref=db.backref('submissions', cascade="all,delete-orphan"))
    project = db.relationship('Project')
    student = db.relationship('Student')

    __table_args__ = (
        UniqueConstraint('task_id', 'student_id', name='uq_project_task_student'),
    )
