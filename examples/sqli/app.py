"""Run: python3 examples/sqli/app.py  (local demo only, in-memory DB)."""
import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (name TEXT, secret TEXT)")
db.executemany("INSERT INTO users VALUES (?, ?)", [("alice", "a-secret"), ("bob", "b-secret")])

def vulnerable(name):
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()

def fixed(name):
    return db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()

payload = "x' OR '1'='1"
print("vulnerable:", vulnerable(payload))  # leaks every row
print("fixed:     ", fixed(payload))       # []
