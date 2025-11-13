
import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()

def _as_naive_utc(dt):
    """Return dt as naive UTC (or None). Handles aware/naive inputs safely."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt 

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
    role = db.Column(db.String(32), nullable=False, default="instructor")  # instructor, admin, mentor
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    first_login = db.Column(db.Boolean, nullable=False, default=True)
    last_login  = db.Column(db.DateTime, nullable=True)
    # Link to mentor table if role is 'mentor'
    mentor_id = db.Column(db.Integer, db.ForeignKey('mentors.id', ondelete="SET NULL"), nullable=True)
    
    mentor = db.relationship('Mentor', foreign_keys=[mentor_id])

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    first_login = db.Column(db.Boolean, nullable=False, default=True)
    last_login  = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    question = db.Column(db.Text, nullable=False)
    options = db.Column(JSONText, nullable=False)
    correct_index = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')
    # NEW: gate voting without deleting the poll
    is_open = db.Column(db.Boolean, nullable=False, default=True)

class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id', ondelete="CASCADE"), index=True, nullable=False)
    choice = db.Column(db.Integer, nullable=False)
    voter_token_hash = db.Column(db.String(64), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), index=True, nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    poll = db.relationship('Poll', backref=db.backref('votes', cascade="all,delete-orphan"))
    student = db.relationship('Student')

    # NEW: one vote per (poll, student) at the DB layer
    __table_args__ = (
        UniqueConstraint('poll_id', 'student_id', name='uq_vote_poll_student'),
    )

class Form(db.Model):
    __tablename__ = "forms"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    schema_json = db.Column(JSONText, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')
    # NEW:
    closes_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_open(self):
        return (self.closes_at is None) or (datetime.now() < self.closes_at)

class FormResponse(db.Model):
    __tablename__ = "form_responses"
    id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('forms.id', ondelete="CASCADE"), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"), index=True, nullable=True)
    student_name = db.Column(db.String(120), nullable=True)
    payload_json = db.Column(JSONText, nullable=False)  # submitted answers
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    form = db.relationship('Form', backref=db.backref('responses', cascade="all,delete-orphan"))
    student = db.relationship('Student')

class LectureSignal(db.Model):
    __tablename__ = "lecture_signals"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    kind = db.Column(db.String(16), nullable=False)  # "ok" | "confused"
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

class LectureQuestion(db.Model):
    __tablename__ = "lecture_questions"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    text = db.Column(db.Text, nullable=False)
    handled = db.Column(db.Boolean, default=False, nullable=False)  # NEW
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


class StudentStats(db.Model):
    __tablename__ = "student_stats"
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), primary_key=True)
    times_spoken = db.Column(db.Integer, default=0, nullable=False)
    last_spoken_at = db.Column(db.DateTime)
    current_round_done = db.Column(db.Boolean, default=False, nullable=False)

class Intervention(db.Model):
    __tablename__ = "interventions"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    section = db.Column(db.String(120))
    duration_sec = db.Column(db.Integer, default=120, nullable=False)
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id', ondelete="SET NULL"))
    status = db.Column(db.String(20), default="picked", nullable=False)  # picked|running|completed|skipped
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

class Notebook(db.Model):
    __tablename__ = "notebooks"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="CASCADE"), index=True, nullable=False)
    content_json = db.Column(JSONText, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)

class Mentor(db.Model):
    __tablename__ = "mentors"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False, default="")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    first_login = db.Column(db.Boolean, nullable=False, default=True)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Homework(db.Model):
    __tablename__ = "homeworks"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, index=True, nullable=False)  # share code
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    template_json = db.Column(JSONText, nullable=False)  # nbformat JSON
    open_at = db.Column(db.DateTime, nullable=True)
    due_at = db.Column(db.DateTime, nullable=True)
    creator_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    @property
    def is_open(self) -> bool:
        now = datetime.now()
        open_at = _as_naive_utc(self.open_at)
        due_at = _as_naive_utc(self.due_at)
        if open_at and now < open_at:
            return False
        if due_at and now > due_at:
            return False
        return True

class StudentHomework(db.Model):
    __tablename__ = "student_homeworks"
    id = db.Column(db.Integer, primary_key=True)
    homework_id = db.Column(db.Integer, db.ForeignKey("homeworks.id"), index=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("students.id"), index=True, nullable=False)
    notebook_id = db.Column(db.Integer, db.ForeignKey("notebooks.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    submitted_at = db.Column(db.DateTime, nullable=True)
    # Mentor assignment (assigned on first submission, persists through reopens)
    assigned_mentor_id = db.Column(db.Integer, db.ForeignKey("mentors.id", ondelete="SET NULL"), index=True, nullable=True)
    assigned_at = db.Column(db.DateTime, nullable=True)  # When mentor was assigned
    # Acceptance/Rejection by mentor
    acceptance_status = db.Column(db.String(20), nullable=True)  # "accepted", "rejected", or None (pending)
    acceptance_comment = db.Column(db.Text, nullable=True)  # Optional comment on acceptance/rejection
    reviewed_at = db.Column(db.DateTime, nullable=True)  # When mentor reviewed
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    # Feedback fields (legacy - kept for backward compatibility)
    feedback = db.Column(db.Text, nullable=True)
    feedback_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    feedback_at = db.Column(db.DateTime, nullable=True)
    # Re-open capability
    reopened_at = db.Column(db.DateTime, nullable=True)
    reopened_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    
    assigned_mentor = db.relationship('Mentor')

    __table_args__ = (
        db.UniqueConstraint("homework_id", "student_id", name="uq_homework_student"),
    )

class HomeworkMessage(db.Model):
    __tablename__ = "homework_messages"
    id = db.Column(db.Integer, primary_key=True)
    student_homework_id = db.Column(db.Integer, db.ForeignKey("student_homeworks.id", ondelete="CASCADE"), index=True, nullable=False)
    sender_type = db.Column(db.String(20), nullable=False)  # "student" or "instructor"
    sender_user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    sender_student_id = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="SET NULL"), nullable=True)
    sender_name = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    student_read_at = db.Column(db.DateTime, nullable=True)  # When student last saw messages
    instructor_read_at = db.Column(db.DateTime, nullable=True)  # When instructor last saw messages
    
    student_homework = db.relationship('StudentHomework', backref=db.backref('messages', cascade="all,delete-orphan", order_by='HomeworkMessage.created_at'))
    sender_user = db.relationship('User')
    sender_student = db.relationship('Student')