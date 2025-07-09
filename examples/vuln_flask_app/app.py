from flask import Flask, request
import sqlite3

app = Flask(__name__)
db_path = "app.db"


def get_user(user_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # VULNERABILITY: Direct f-string formatting leads to SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

@app.route("/user")
def show_user():
    user_id = request.args.get("id")
    user_data = get_user(user_id)
    if user_data:
        return str(user_data)
    return "User not found", 404

if __name__ == "__main__":
    # Setup a dummy database for the example
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, name TEXT)")
    conn.execute("INSERT OR IGNORE INTO users (id, name) VALUES ('1', 'admin')")
    conn.commit()
    conn.close()
    
    app.run(debug=False)
