from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello World!"

@app.route('/vulnerable')
def vulnerable():
    # This should be detected as a Flask entry point
    user_input = request.args.get('input', '')
    # Vulnerable code for testing
    result = eval(user_input)
    return str(result)

if __name__ == '__main__':
    app.run(debug=True)