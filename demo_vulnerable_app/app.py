#!/usr/bin/env python3
"""
Demo Vulnerable Flask Application
This app contains intentional security vulnerabilities for testing Impact Scan.
"""

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, redirect, session
import pickle
import yaml

app = Flask(__name__)
app.secret_key = "hardcoded-secret-key-bad"  # VULNERABILITY: Hardcoded secret

# VULNERABILITY: SQL Injection
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # VULNERABLE: SQL injection possible
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        conn = sqlite3.connect('users.db')
        result = conn.execute(query).fetchone()
        conn.close()
        
        if result:
            session['user'] = username
            return redirect('/dashboard')
        else:
            return "Login failed"
    
    return '''
    <form method="post">
        Username: <input name="username"><br>
        Password: <input name="password" type="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

# VULNERABILITY: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form['host']
        # VULNERABLE: Command injection possible
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
        return f"<pre>{result.decode()}</pre>"
    
    return '''
    <form method="post">
        Host to ping: <input name="host">
        <input type="submit" value="Ping">
    </form>
    '''

# VULNERABILITY: Server-Side Template Injection (SSTI)
@app.route('/template')
def template():
    name = request.args.get('name', 'World')
    # VULNERABLE: Template injection possible
    template = f"Hello {name}!"
    return render_template_string(template)

# VULNERABILITY: Insecure Deserialization
@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.files['data'].read()
    # VULNERABLE: Pickle deserialization
    obj = pickle.loads(data)
    return f"Loaded: {obj}"

# VULNERABILITY: YAML Deserialization
@app.route('/config', methods=['POST'])
def config():
    config_data = request.form['config']
    # VULNERABLE: YAML load without safe_load
    config = yaml.load(config_data, Loader=yaml.Loader)
    return f"Config loaded: {config}"

# VULNERABILITY: Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', 'default.txt')
    # VULNERABLE: Path traversal possible
    with open(filename, 'r') as f:
        content = f.read()
    return f"<pre>{content}</pre>"

# VULNERABILITY: Weak Cryptography
@app.route('/encrypt')
def encrypt():
    import hashlib
    data = request.args.get('data', '')
    # VULNERABLE: MD5 is cryptographically broken
    hash_value = hashlib.md5(data.encode()).hexdigest()
    return f"MD5 Hash: {hash_value}"

# VULNERABILITY: Debug mode enabled
if __name__ == '__main__':
    # VULNERABLE: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)