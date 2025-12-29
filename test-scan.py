"""Test file for Impact Scan GitHub App - Python Flask API with security vulnerabilities"""

import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    return {'user': user}


@app.route('/search')
def search_users():
    search_term = request.args.get('q')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
    result = cursor.execute(query).fetchall()
    conn.close()

    return {'results': result}


@app.route('/template')
def render_template():
    template_str = request.args.get('template')
    return render_template_string(template_str)


@app.route('/command')
def execute_command():
    cmd = request.args.get('cmd')
    result = os.system(cmd)
    return {'output': result}


@app.route('/eval')
def eval_code():
    code = request.args.get('code')
    result = eval(code)
    return {'result': result}


@app.route('/file')
def read_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()


if __name__ == '__main__':
    # Insecure SSL context
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_NONE

    app.run(debug=True, host='0.0.0.0', ssl_context=context)
