"""
Simple vulnerable Flask app for testing web intelligence capabilities.
Contains various security issues that should be detected.
"""
import hashlib
import sqlite3
from flask import Flask, request, render_template_string
import requests
import yaml

app = Flask(__name__)

# Vulnerability 1: Hardcoded secrets
SECRET_KEY = "hardcoded-secret-key-123"
API_KEY = "sk-1234567890abcdef"

# Vulnerability 2: SQL Injection
@app.route('/users/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Direct string concatenation - SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    result = cursor.fetchone()
    return str(result)

# Vulnerability 3: XSS via template injection
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {name}!</h1>'
    return render_template_string(template)

# Vulnerability 4: Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 5: Unsafe YAML loading
@app.route('/config', methods=['POST'])
def load_config():
    config_data = request.data
    config = yaml.load(config_data)  # Unsafe YAML loading
    return str(config)

# Vulnerability 6: SSL verification disabled
def fetch_data(url):
    response = requests.get(url, verify=False)
    return response.text

# Vulnerability 7: Missing request timeout
def slow_request(url):
    response = requests.get(url)  # No timeout specified
    return response.text

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')