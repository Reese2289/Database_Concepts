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

# Load database records for logged in user
@app.route('/records')
def records():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    records = conn.execute(
        'SELECT * FROM monsterData WHERE UserID = ?', (session['user_id'],)
    ).fetchall()
    conn.close()

    return render_template('records.html', records=records)

# Add new record for logged in user
@app.route('/add_record', methods=['GET', 'POST'])
def add_record():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        monsterName = request.form.get('monsterName')
        largestSize = request.form.get('largestSize')
        smallestSize = request.form.get('smallestSize')
        largeGoldCrown = 'largeGoldCrown' in request.form
        smallGoldCrown = 'smallGoldCrown' in request.form
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO monsterData (UserID, MonsterName, LargestSize, SmallestSize, LargeGoldCrown, SmallGoldCrown) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], monsterName, largestSize, smallestSize, largeGoldCrown, smallGoldCrown)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('records'))
    return render_template('records.html')

@app.context_processor
def inject_user():
    return dict(username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
