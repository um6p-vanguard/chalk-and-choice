
import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy import UniqueConstraint, CheckConstraint
from sqlalchemy.ext.mutable import MutableDict
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
    __table_args__ = (
        CheckConstraint("xp >= 0",     name="ck_students_xp_nonneg"),
        CheckConstraint("stars >= 0",  name="ck_students_stars_nonneg"),
        CheckConstraint("(handle IS NULL) OR (length(trim(handle)) > 0)",
                        name="ck_students_handle_not_blank"),
        CheckConstraint("toxicity_points >= 0", name="ck_students_toxicity_nonneg"),
        db.Index("ix_students_xp", "xp"),
        db.Index("ix_students_stars", "stars"),
        db.Index("ix_students_toxicity", "toxicity_points"),
    )

    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(120), nullable=False)
    email         = db.Column(db.String(255, collation="NOCASE"), unique=True, index=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False, default="")
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    first_login   = db.Column(db.Boolean, nullable=False, default=True)
    last_login    = db.Column(db.DateTime)


    xp            = db.Column(db.Integer, nullable=False, default=0)
    stars         = db.Column(db.Integer, nullable=False, default=0)
    toxicity_points = db.Column(db.Integer, nullable=False, default=0)


    handle        = db.Column(db.String(32,  collation="NOCASE"), unique=True, index=True)  
    bio           = db.Column(db.Text)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

    def __repr__(self):
        return f"<Student id={self.id} email={self.email!r} xp={self.xp} stars={self.stars}>"

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
    handled = db.Column(db.Boolean, default=False, nullable=False)  # NEW
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# ---------------- Learning Outcome ----------------
class LearningOutcome(db.Model):
    __tablename__ = "learning_outcomes"
    __table_args__ = (
        CheckConstraint("length(trim(code))  > 0", name="ck_lo_code_not_blank"),
        CheckConstraint("length(trim(title)) > 0", name="ck_lo_title_not_blank"),
    )
    id          = db.Column(db.Integer, primary_key=True)
    code        = db.Column(db.String(32,collation="NOCASE"), unique=True, nullable=False)
    title       = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow,
                            onupdate=datetime.utcnow, nullable=False)

    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')

    def __repr__(self):
        return f"<LearningOutcome id={self.id} code={self.code!r}>"

# ---------------- Quest ----------------
class Quest(db.Model):
    __tablename__ = "quests"
    __table_args__ = (
        CheckConstraint("xp >= 0", name="ck_quests_xp_nonneg"),
        CheckConstraint("(difficulty IS NULL) OR (difficulty BETWEEN 1 AND 5)",
                        name="ck_quests_difficulty_1_5"),
        db.Index("ix_quests_published", "published", "is_optional"),
    )

    id          = db.Column(db.Integer, primary_key=True)
    code        = db.Column(db.String(64), unique=True, index=True, nullable=False)
    title       = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)

    xp          = db.Column(db.Integer, nullable=False, default=10)
    stars       = db.Column(db.Integer, nullable=False, default=10)
    difficulty  = db.Column(db.Integer)  # 1..5 (nullable)
    is_optional = db.Column(db.Boolean, nullable=False, default=False)
    published   = db.Column(db.Boolean, nullable=False, default=False)

    starts_at   = db.Column(db.DateTime)   # store UTC
    due_at      = db.Column(db.DateTime)   # store UTC
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow,
                            onupdate=datetime.utcnow, nullable=False)
    
    completion = db.Column(
        MutableDict.as_mutable(db.JSON),
        nullable=False,
        default=dict
    )

    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')

    def __repr__(self):
        return f"<Quest id={self.id} code={self.code!r}>"

# ---------------- Task ----------------
class Task(db.Model):
    __tablename__ = "tasks"
    __table_args__ = (
        db.UniqueConstraint("quest_id", "slug", name="uq_tasks_quest_slug"),
        db.Index("ix_tasks_quest_order", "quest_id", "order_in_quest"),
        CheckConstraint("xp >= 0", name="ck_tasks_xp_nonneg"),
        CheckConstraint("stars >= 0", name="ck_tasks_stars_nonneg"),
        CheckConstraint("(difficulty IS NULL) OR (difficulty BETWEEN 1 AND 5)",
                        name="ck_tasks_difficulty_1_5"),
        CheckConstraint("(min_score_to_pass >= 0.0) AND (min_score_to_pass <= 1.0)",
                name="ck_tasks_min_score_0_1"),
        db.Index("ix_tasks_required", "quest_id", "must_pass"),
    )

    id          = db.Column(db.Integer, primary_key=True)
    quest_id    = db.Column(db.Integer, index=True)  # FK later

    slug        = db.Column(db.String(64), nullable=False)  # unique per quest
    title       = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)

    type = db.Column(db.Enum(
        "CODE", "MCQ", "TEXT", "REFLECTION", "VISIT", "FILE_UPLOAD",
        name="task_type", native_enum=False  # SQLite-friendly
    ), nullable=False)

    # Rewards / gating
    xp                 = db.Column(db.Integer, nullable=False, default=10)
    stars              = db.Column(db.Integer, nullable=False, default=10)
    difficulty         = db.Column(db.Integer)  # 1..5 (nullable)
    must_pass          = db.Column(db.Boolean, nullable=False, default=True)
    min_score_to_pass  = db.Column(db.Numeric(3, 2), nullable=False, default=1.00)
    order_in_quest     = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    creator_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="SET NULL"), index=True, nullable=True)
    creator = db.relationship('User')

    config = db.Column(
        MutableDict.as_mutable(db.JSON),         # tracks in-place changes
        nullable=False,
        default=dict                              # NEVER default="{}" or default={}
    )

    def __repr__(self):
        return f"<Task id={self.id} slug={self.slug!r} quest_id={self.quest_id}>"
    


# Quest ↔ LearningOutcome mapping
class QuestOutcome(db.Model):
    __tablename__ = "quest_outcomes"
    __table_args__ = (
        db.PrimaryKeyConstraint("quest_id", "lo_id", name="pk_quest_outcomes"),
        db.Index("ix_quest_outcomes_lo", "lo_id"),
        CheckConstraint("weight >= 0", name="ck_qo_weight_nonneg"),
    )

    quest_id = db.Column(
        db.Integer,
        db.ForeignKey("quests.id", ondelete="CASCADE"),
        nullable=False
    )
    lo_id = db.Column(
        db.Integer,
        db.ForeignKey("learning_outcomes.id", ondelete="CASCADE"),
        nullable=False
    )
    weight = db.Column(db.Integer, nullable=False, default=1)  # contribution strength


# Task ↔ LearningOutcome mapping
class TaskOutcome(db.Model):
    __tablename__ = "task_outcomes"
    __table_args__ = (
        db.PrimaryKeyConstraint("task_id", "lo_id", name="pk_task_outcomes"),
        db.Index("ix_task_outcomes_lo", "lo_id"),
        CheckConstraint("weight >= 0", name="ck_to_weight_nonneg"),
    )

    task_id = db.Column(
        db.Integer,
        db.ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False
    )
    lo_id = db.Column(
        db.Integer,
        db.ForeignKey("learning_outcomes.id", ondelete="CASCADE"),
        nullable=False
    )
    weight = db.Column(db.Integer, nullable=False, default=1)
    
    
# ===== Quest prerequisites =====
class QuestPrereq(db.Model):
    __tablename__ = "quest_prereqs"
    __table_args__ = (
        db.PrimaryKeyConstraint("quest_id", "prereq_quest_id", name="pk_quest_prereqs"),
        CheckConstraint("quest_id <> prereq_quest_id", name="ck_quest_prereq_no_self"),
        CheckConstraint("min_required >= 1", name="ck_quest_prereq_min_required_ge1"),
        CheckConstraint("(group_id IS NOT NULL) OR (min_required = 1)",
                name="ck_quest_prereq_null_group_means_one"),
        db.Index("ix_quest_prereqs_quest", "quest_id"),
        db.Index("ix_quest_prereqs_prereq", "prereq_quest_id"),
        db.Index("ix_quest_prereqs_quest_group", "quest_id", "group_id"),
    )

    quest_id = db.Column(
        db.Integer,
        db.ForeignKey("quests.id", ondelete="CASCADE"),
        nullable=False
    )
    prereq_quest_id = db.Column(
        db.Integer,
        db.ForeignKey("quests.id", ondelete="CASCADE"),
        nullable=False
    )

    group_id    = db.Column(db.Integer)
    min_required= db.Column(db.Integer, default=1)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<QuestPrereq quest={self.quest_id} requires={self.prereq_quest_id}>"

# ===== Task prerequisites =====
class TaskPrereq(db.Model):
    __tablename__ = "task_prereqs"
    __table_args__ = (
        db.PrimaryKeyConstraint("task_id", "prereq_task_id", name="pk_task_prereqs"),
        CheckConstraint("task_id <> prereq_task_id", name="ck_task_prereq_no_self"),
        CheckConstraint("min_required >= 1", name="ck_task_prereq_min_required_ge1"),
        CheckConstraint("(group_id IS NOT NULL) OR (min_required = 1)",
                name="ck_task_prereq_null_group_means_one"),
        db.Index("ix_task_prereqs_task", "task_id"),
        db.Index("ix_task_prereqs_prereq", "prereq_task_id"),
        db.Index("ix_task_prereqs_task_group", "task_id", "group_id"),
    )

    task_id = db.Column(
        db.Integer,
        db.ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False
    )
    prereq_task_id = db.Column(
        db.Integer,
        db.ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False
    )

    group_id    = db.Column(db.Integer)
    min_required= db.Column(db.Integer, default=1)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<TaskPrereq task={self.task_id} requires={self.prereq_task_id}>"

class Badge(db.Model):
    __tablename__ = "badges"
    __table_args__ = (
        CheckConstraint("length(trim(code))  > 0", name="ck_badge_code_not_blank"),
        CheckConstraint("length(trim(name))  > 0", name="ck_badge_name_not_blank"),
        db.Index("ix_badges_code", "code"),
    )

    id          = db.Column(db.Integer, primary_key=True)
    code        = db.Column(db.String(64,  collation="NOCASE"), unique=True, nullable=False)
    name        = db.Column(db.String(120), nullable=False)
    short_desc  = db.Column(db.String(255))
    image_url   = db.Column(db.String(1024))

    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by  = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)

    def __repr__(self):
        return f"<Badge id={self.id} code={self.code!r}>"

class QuestBadge(db.Model):
    __tablename__ = "quest_badges"
    __table_args__ = (
        db.PrimaryKeyConstraint("quest_id", "badge_id", name="pk_quest_badges"),
        db.Index("ix_quest_badges_badge", "badge_id"),
    )
    quest_id = db.Column(db.Integer, db.ForeignKey("quests.id", ondelete="CASCADE"), nullable=False)
    badge_id = db.Column(db.Integer, db.ForeignKey("badges.id", ondelete="CASCADE"), nullable=False)

class TaskBadge(db.Model):
    __tablename__ = "task_badges"
    __table_args__ = (
        db.PrimaryKeyConstraint("task_id", "badge_id", name="pk_task_badges"),
        db.Index("ix_task_badges_badge", "badge_id"),
    )
    task_id  = db.Column(db.Integer, db.ForeignKey("tasks.id",  ondelete="CASCADE"), nullable=False)
    badge_id = db.Column(db.Integer, db.ForeignKey("badges.id", ondelete="CASCADE"), nullable=False)


class StudentBadge(db.Model):
    __tablename__ = "student_badges"
    __table_args__ = (
        db.PrimaryKeyConstraint("student_id", "badge_id", name="pk_student_badges"),
        db.Index("ix_student_badges_badge", "badge_id"),
        db.Index("ix_student_badges_student", "student_id"),
    )

    student_id  = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)
    badge_id    = db.Column(db.Integer, db.ForeignKey("badges.id",   ondelete="CASCADE"), nullable=False)

    awarded_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    source_type = db.Column(db.Enum("QUEST", "TASK", "ADMIN", name="badge_source_type", native_enum=False),
                            nullable=False, default="ADMIN")
    source_id   = db.Column(db.Integer)
    note        = db.Column(db.String(255))


class Submission(db.Model):
    __tablename__ = "submissions"
    __table_args__ = (
        CheckConstraint("(score >= 0.0) AND (score <= 1.0)", name="ck_submissions_score_0_1"),
        db.Index("ix_submissions_task_user_time", "task_id", "student_id", "created_at"),
    )

    id          = db.Column(db.Integer, primary_key=True)
    task_id     = db.Column(db.Integer, db.ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    student_id  = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False, index=True)

    status      = db.Column(db.Enum("PENDING","PASSED","FAILED","PARTIAL","ERROR",
                                    name="submission_status", native_enum=False),
                            nullable=False, default="PENDING")

    score       = db.Column(db.Numeric(4, 3), nullable=False, default=0.000)
    feedback    = db.Column(db.Text)
    runtime_ms  = db.Column(db.Integer)
    memory_kb   = db.Column(db.Integer)
    language    = db.Column(db.String(32))

    payload     = db.Column(JSONText)

    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class StudentTaskGrade(db.Model):
    __tablename__ = "student_task_grades"
    __table_args__ = (
        db.UniqueConstraint("task_id", "student_id", name="uq_task_grade_task_student"),
        CheckConstraint("(best_score >= 0.0) AND (best_score <= 1.0)", name="ck_task_grade_best_0_1"),
        db.Index("ix_task_grades_task", "task_id"),
        db.Index("ix_task_grades_student", "student_id"),
    )
    id                 = db.Column(db.Integer, primary_key=True)
    task_id            = db.Column(db.Integer, db.ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False)
    student_id         = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)
    attempts_count     = db.Column(db.Integer, nullable=False, default=0)
    best_score         = db.Column(db.Numeric(4, 3), nullable=False, default=0.000)
    passed             = db.Column(db.Boolean, nullable=False, default=False)
    last_submission_id = db.Column(db.Integer, db.ForeignKey("submissions.id", ondelete="SET NULL"))
    last_updated       = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class StudentQuestGrade(db.Model):
    __tablename__ = "student_quest_grades"
    __table_args__ = (
        db.UniqueConstraint("quest_id", "student_id", name="uq_quest_grade_quest_student"),
        db.Index("ix_quest_grades_quest", "quest_id"),
        db.Index("ix_quest_grades_student", "student_id"),
    )

    id           = db.Column(db.Integer, primary_key=True)
    quest_id     = db.Column(db.Integer, db.ForeignKey("quests.id", ondelete="CASCADE"), nullable=False)
    student_id   = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)

    passed       = db.Column(db.Boolean, nullable=False, default=False)
    best_score   = db.Column(db.Numeric(4, 3), nullable=False, default=0.000)  # optional aggregate
    completed_at = db.Column(db.DateTime)

    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class TaskTestcase(db.Model):
    __tablename__ = "task_testcases"
    __table_args__ = (
        db.Index("ix_testcases_task_order", "task_id", "order_in_task"),
        CheckConstraint("(weight >= 0.0)", name="ck_testcases_weight_nonneg"),
    )
    id            = db.Column(db.Integer, primary_key=True)
    task_id       = db.Column(db.Integer, db.ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    name          = db.Column(db.String(120))
    input_text    = db.Column(db.Text)      # for IO judge
    expected_text = db.Column(db.Text)
    visibility    = db.Column(db.Enum("SAMPLE","HIDDEN", name="testcase_visibility", native_enum=False),
                              nullable=False, default="HIDDEN")
    weight        = db.Column(db.Numeric(4, 2), nullable=False, default=1.00)
    order_in_task = db.Column(db.Integer, nullable=False, default=1)

class TaskResource(db.Model):
    __tablename__ = "task_resources"
    id        = db.Column(db.Integer, primary_key=True)
    task_id   = db.Column(db.Integer, db.ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    label     = db.Column(db.String(120))
    url       = db.Column(db.String(1024))
    kind      = db.Column(db.String(32))

class StudentRewardEvent(db.Model):
    __tablename__ = "student_reward_events"
    __table_args__ = (db.Index("ix_reward_events_student_time", "student_id", "created_at"),)

    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)
    delta_xp    = db.Column(db.Integer, nullable=False, default=0)
    delta_stars = db.Column(db.Integer, nullable=False, default=0)
    source_type = db.Column(db.Enum("QUEST","TASK","ADMIN", name="reward_source_type", native_enum=False),
                            nullable=False, default="ADMIN")
    source_id   = db.Column(db.Integer)
    note        = db.Column(db.String(255))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class StudentToxicityEvent(db.Model):
    __tablename__ = "student_toxicity_events"
    __table_args__ = (db.Index("ix_toxicity_events_student_time", "student_id", "created_at"),)

    id          = db.Column(db.Integer, primary_key=True)
    student_id  = db.Column(db.Integer, db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)
    delta_points= db.Column(db.Integer, nullable=False)
    reason      = db.Column(db.String(255))
    given_by    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
