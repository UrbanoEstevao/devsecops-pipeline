"""
Deliberately vulnerable demo API.

This exists ONLY so the pipeline has real findings to show. Every bug below is
intentional and labelled. Never deploy this anywhere reachable.
"""
import os
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__)

# [VULN] Hardcoded secret -> Gitleaks / Semgrep
API_SECRET_TOKEN = "Zr8v1Qm4Tq7XwL2pK9sN3bH6yF0cJ5dGx4Wq"  # fake, high-entropy
app.config["SECRET_KEY"] = API_SECRET_TOKEN
DB_PATH = os.environ.get("DB_PATH", "/tmp/demo.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        [("alice", "alice@example.com"), ("bob", "bob@example.com")],
    )
    conn.commit()
    conn.close()


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/openapi.json")
def openapi():
    return send_from_directory(os.path.dirname(__file__), "openapi.json")


@app.get("/api/users")
def users():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    # [VULN] SQL injection -> Semgrep (SAST) + ZAP (DAST)
    rows = conn.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.get("/api/greet")
def greet():
    name = request.args.get("name", "world")
    # [VULN] Reflected XSS -> Semgrep + ZAP
    return f"<html><body><h1>Hello {name}</h1></body></html>"


@app.get("/api/lookup")
def lookup():
    host = request.args.get("host", "localhost")
    # [VULN] OS command injection -> Semgrep + ZAP
    out = subprocess.run(f"getent hosts {host}", shell=True, capture_output=True, text=True)
    return jsonify(output=out.stdout)


@app.post("/api/import")
def import_config():
    # [VULN] Unsafe YAML deserialization -> Semgrep; PyYAML 5.3.1 -> Trivy (SCA)
    data = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(imported=str(data))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
