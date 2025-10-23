import argparse, json, secrets, string
from app import create_app
from models import db, User, Student

def rand_password(n=10):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

def seed_students(app, json_path):
    with app.app_context():
        items = json.load(open(json_path, "r"))
        out = []
        for it in items:
            name = it["name"].strip()
            email = it["email"].strip().lower()
            pw = it.get("password") or rand_password()
            s = Student.query.filter_by(email=email).first()
            if not s:
                s = Student(name=name, email=email, first_login=True)
                s.set_password(pw)
                db.session.add(s)
                action = "created"
            else:
                s.name = name
                s.set_password(pw)
                s.first_login = True
                action = "updated"
            out.append({"email": email, "password": pw, "action": action})
        db.session.commit()
        print("Seeded/updated:", len(out))
        for r in out:
            print(f"{r['email']}: {r['password']} ({r['action']})")

def seed_users(app, json_path):
    """
    JSON: [{"name":"Prof X","email":"x@school.edu","role":"instructor|admin","password":"..."}]
    If password omitted, one is generated; first_login=True forces password change.
    """
    with app.app_context():
        items = json.load(open(json_path, "r"))
        out = []
        for it in items:
            name = it["name"].strip()
            email = it["email"].strip().lower()
            role = (it.get("role") or "instructor").strip().lower()
            pw = it.get("password") or rand_password()
            u = User.query.filter_by(email=email).first()
            if not u:
                u = User(name=name, email=email, role=role, first_login=True)
                u.set_password(pw)
                db.session.add(u)
                action = "created"
            else:
                u.name = name
                u.role = role
                u.set_password(pw)
                u.first_login = True
                action = "updated"
            out.append({"email": email, "password": pw, "role": role, "action": action})
        db.session.commit()
        print("Seeded/updated:", len(out))
        for r in out:
            print(f"{r['email']} ({r['role']}): {r['password']} ({r['action']})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["seed-students","seed-users"])
    parser.add_argument("json_path")
    args = parser.parse_args()

    app = create_app()
    if args.cmd == "seed-students":
        seed_students(app, args.json_path)
    else:
        seed_users(app, args.json_path)
