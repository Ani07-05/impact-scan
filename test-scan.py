"""Test file for Impact Scan GitHub App - Python API with security issues"""

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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
