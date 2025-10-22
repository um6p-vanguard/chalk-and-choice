
import json, sys
from werkzeug.security import generate_password_hash
from models import db, User
from app import create_app

def seed_users(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    app = create_app()
    with app.app_context():
        for row in data:
            email = row.get("email","").strip().lower()
            name  = row.get("name","").strip()
            pw    = row.get("password","")
            role  = row.get("role","instructor")
            if not email or not name or not pw: continue
            u = User.query.filter_by(email=email).first()
            if u:
                u.name = name
                u.role = role if role in ("admin","instructor") else "instructor"
                u.password_hash = generate_password_hash(pw)
            else:
                u = User(email=email, name=name, role=role if role in ("admin","instructor") else "instructor",
                         password_hash=generate_password_hash(pw))
                db.session.add(u)
        db.session.commit()
    print("Seeding done.")

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "seed-users":
        print("Usage: python manage.py seed-users seed_users.json"); sys.exit(1)
    seed_users(sys.argv[2])
