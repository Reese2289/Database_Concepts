from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bcrypt
from datetime import date
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'mydatabase.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (Username, PasswordHash, JoinDate) VALUES (?, ?, ?)',
            (username, hashed_password, date.today())
        )
        conn.commit()
        conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE Username = ?', (username,)
        ).fetchone()
        conn.close()

        print("Query executed for:", username)
        print("Result:", dict(user) if user else "No user found")

        if user and bcrypt.checkpw(password.encode('utf-8'), user['PasswordHash']):
            session['user_id'] = user['ID']
            session['username'] = user['Username']
            print("Credentials verified for user:", username)
            return redirect(url_for('home'))
        else:
            return "Invalid username or password"

    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
