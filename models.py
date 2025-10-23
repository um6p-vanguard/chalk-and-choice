
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy import UniqueConstraint
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

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(12), unique=True, index=True, nullable=False)
    question = db.Column(db.Text, nullable=False)
    options = db.Column(JSONText, nullable=False)
    correct_index = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

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

class LectureSignal(db.Model):
    __tablename__ = "lecture_signals"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    kind = db.Column(db.String(16), nullable=False)  # "ok" | "confused"
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class LectureQuestion(db.Model):
    __tablename__ = "lecture_questions"
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id', ondelete="SET NULL"))
    student_name = db.Column(db.String(120))
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
