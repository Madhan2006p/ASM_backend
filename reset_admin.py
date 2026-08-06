import os
import sys
import sqlite3
import base64
import hashlib

salt = "asm_admin_salt_2026"
iterations = 260000
raw_pwd = b"admin123"
pwd_hash = base64.b64encode(hashlib.pbkdf2_hmac("sha256", raw_pwd, salt.encode("utf-8"), iterations)).decode("ascii")
formatted_hash = f"pbkdf2_sha256${iterations}${salt}${pwd_hash}"

db_path = os.path.join(os.path.dirname(__file__), "db.sqlite3")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

admin_users = ["admin", "madhan", "admin@localhost", "dharsika", "Dharsika"]
for user in admin_users:
    cur.execute(
        "UPDATE auth_user SET password=?, is_superuser=1, is_staff=1 WHERE username=?",
        (formatted_hash, user)
    )

conn.commit()

cur.execute("SELECT username, password FROM auth_user WHERE is_superuser=1")
rows = cur.fetchall()
print("Superusers updated in db.sqlite3:")
for r in rows:
    print(f"Username: {r[0]} | Password Hash: {r[1][:30]}...")

conn.close()
