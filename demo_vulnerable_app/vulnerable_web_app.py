"""
Vulnerable Web Application for Security Demo
Contains multiple intentional security vulnerabilities for testing citations.
"""

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import subprocess
import pickle
import hashlib
import os
import yaml
import requests

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"  # VULNERABILITY: Hardcoded secret


@app.route("/")
def home():
    return "<h1>Vulnerable Demo App</h1><p>Multiple security issues for testing</p>"


@app.route("/sql_injection")
def sql_injection():
    """SQL Injection vulnerability"""
    user_id = request.args.get("id", "1")
    
    # VULNERABILITY: SQL Injection via string formatting
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    
    return f"User data: {result}"


@app.route("/xss")
def xss_vulnerability():
    """Cross-Site Scripting vulnerability"""
    user_input = request.args.get("name", "Guest")
    
    # VULNERABILITY: Reflected XSS - direct insertion of user input
    template = f"<h2>Hello {user_input}!</h2>"
    return render_template_string(template)


@app.route("/command_injection")
def command_injection():
    """Command Injection vulnerability"""
    filename = request.args.get("file", "test.txt")
    
    # VULNERABILITY: Command injection via subprocess
    try:
        result = subprocess.run(f"cat {filename}", shell=True, capture_output=True, text=True)
        return f"File contents: {result.stdout}"
    except Exception as e:
        return f"Error: {e}"


@app.route("/pickle_deserialize")  
def pickle_vulnerability():
    """Unsafe deserialization vulnerability"""
    data = request.args.get("data")
    
    if data:
        # VULNERABILITY: Unsafe pickle deserialization
        try:
            import base64
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f"Deserialized: {obj}"
        except Exception as e:
            return f"Error: {e}"
    
    return "Provide data parameter"


@app.route("/weak_crypto")
def weak_crypto():
    """Weak cryptography vulnerability"""
    password = request.args.get("password", "test123")
    
    # VULNERABILITY: Using weak MD5 hash
    weak_hash = hashlib.md5(password.encode()).hexdigest()
    
    return f"Password hash (MD5): {weak_hash}"


@app.route("/path_traversal")
def path_traversal():
    """Path traversal vulnerability"""
    file_path = request.args.get("path", "index.html")
    
    # VULNERABILITY: Path traversal - no input validation
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {e}"


@app.route("/yaml_load")
def yaml_vulnerability():
    """YAML deserialization vulnerability"""
    yaml_data = request.args.get("yaml", "test: value")
    
    # VULNERABILITY: Unsafe YAML loading
    try:
        parsed = yaml.load(yaml_data)  # Should use yaml.safe_load()
        return f"Parsed YAML: {parsed}"
    except Exception as e:
        return f"Error: {e}"


@app.route("/ssrf")
def ssrf_vulnerability():
    """Server-Side Request Forgery vulnerability"""
    url = request.args.get("url", "http://httpbin.org/ip")
    
    # VULNERABILITY: SSRF - no URL validation
    try:
        # Disabled SSL verification (another vulnerability)
        response = requests.get(url, verify=False, timeout=5)
        return f"Response: {response.text}"
    except Exception as e:
        return f"Error: {e}"


@app.route("/session_fixation")
def session_fixation():
    """Session management vulnerability"""
    # VULNERABILITY: Session fixation - accepts session ID from user
    if "session_id" in request.args:
        session_id = request.args.get("session_id")
        session["id"] = session_id
    
    return f"Session ID: {session.get('id', 'Not set')}"


def setup_database():
    """Setup demo database with test data"""
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, email TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@example.com')")
    
    conn.commit()
    conn.close()


if __name__ == "__main__":
    setup_database()
    
    # VULNERABILITY: Debug mode enabled in production
    app.run(debug=True, host="0.0.0.0", port=5000)