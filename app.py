from flask import Flask, render_template, request, redirect
import sqlite3
import bcrypt
from datetime import date
import os

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True)
