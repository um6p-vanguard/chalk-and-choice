# scripts/dev_seed.py
from datetime import datetime
from werkzeug.security import generate_password_hash

from app import create_app
from models import db, User, Student

def _set_pw(obj, plain):
    if hasattr(obj, "set_password"):
        obj.set_password(plain)
    elif hasattr(obj, "password_hash"):
        obj.password_hash = generate_password_hash(plain)
    else:
        raise RuntimeError(f"{obj.__class__.__name__} has no password field")

def upsert_user(name, email, role, password):
    u = User.query.filter_by(email=email).one_or_none()
    if u is None:
        u = User(name=name, email=email, role=role, created_at=datetime.utcnow())
        _set_pw(u, password)
        db.session.add(u)
        print(f"[seed] created {role} user: {email}")
    else:
        print(f"[seed] {role} user already exists: {email}")
    return u

def upsert_student(name, email, password):
    s = Student.query.filter_by(email=email).one_or_none()
    if s is None:
        s = Student(
            name=name, email=email,
            created_at=datetime.utcnow(), first_login=False
        )
        _set_pw(s, password)
        db.session.add(s)
        print(f"[seed] created student: {email}")
    else:
        print(f"[seed] student already exists: {email}")
    return s

def main():
    app = create_app()
    with app.app_context():
        db.create_all()   # safe if tables already exist

        admin  = upsert_user("Alice Admin",  "admin@example.com",  "ADMIN",  "admin123")
        mentor = upsert_user("Mark Mentor",  "mentor@example.com", "MENTOR", "mentor123")
        student= upsert_student("Stu Dent",  "student@example.com","student123")

        db.session.commit()
        print("[seed] done.")

if __name__ == "__main__":
    main()
