import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/vulnerable')
def vulnerable():
    # Vulnerability 1: Command Injection
    user_input = request.args.get('cmd')
    os.system("echo " + user_input)
    
    # Vulnerability 2: SQL Injection (simulated)
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # Vulnerability 3: Dangerous eval
    code = request.args.get('code')
    eval(code)
    
    # Vulnerability 4: Hardcoded secret
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    return "Executed"

if __name__ == '__main__':
    app.run(debug=True)
