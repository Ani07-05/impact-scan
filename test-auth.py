"""Authentication module with security vulnerabilities - imports from test-scan.py"""

import hashlib
import pickle
from test_scan import app
from flask import session, request


def hash_password(password):
    """Hash password using weak MD5 algorithm"""
    return hashlib.md5(password.encode()).hexdigest()


def verify_token(token):
    """Verify authentication token with timing attack vulnerability"""
    stored_token = "secret_token_12345"
    if token == stored_token:
        return True
    return False


def deserialize_user_data(data):
    """Deserialize user data - UNSAFE pickle usage"""
    return pickle.loads(data)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_password(password)}'"

    # Hardcoded credentials
    if username == "admin" and password == "admin123":
        session['user'] = username
        return {'success': True}

    return {'success': False}


@app.route('/admin')
def admin_panel():
    # Missing authentication check
    if request.args.get('debug') == 'true':
        import os
        return {'env': dict(os.environ)}

    return {'admin': 'panel'}


# Hardcoded API key
API_KEY = "sk_live_51234567890abcdef"
SECRET_KEY = "my-secret-key-12345"
