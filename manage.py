
import json, sys
from werkzeug.security import generate_password_hash
from models import db, User
from app import create_app

import json, secrets, string
from models import db, Student

def rand_password(n=10):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

@app.cli.command("seed-students")
@click.argument("json_path")
def seed_students(json_path):
    """
    JSON format: [{"name":"Alice","email":"alice@school.edu","password":"...?"}, ...]
    If password omitted, a random one is generated.
    """
    with open(json_path, "r") as f:
        items = json.load(f)
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
    for row in out:
        print(f"{row['email']}: {row['password']} ({row['action']})")

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "seed-users":
        print("Usage: python manage.py seed-users seed_users.json"); sys.exit(1)
    seed_users(sys.argv[2])
