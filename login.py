import sqlite3
import bcrypt
import random
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'HEMUCHOMU'
app.run
 
@app.route('/new.html')
def home():
    role = request.args.get('role')
    print(role)
    return render_template('landing.html',role_value=role)

@app.route('/')
def home2():
    return render_template('landing.html')


@app.route('/signup', methods=['POST'])
def Signup():
    username = request.form.get('signup-username')
    password = request.form.get('signup-password')
    if not username or not password:
        flash('Please fill in all fields.')
        return redirect(url_for('home'))
    if check_username_exists(username,role):
        flash('Username already exists.')
        username = request.form.get('signup-username')
        return redirect(url_for('home'))
    create_table(role)
    insert_user(role,username,password)     
    flash('Signup successful! Please log in.')
    return redirect(url_for('home'))

@app.route("/db", methods=['GET'])
def db():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM client")
    print(cursor.fetchall())
    


@app.route('/login', methods=['POST'])
def login():
    print(role)
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    u = request.form['username']
    p = request.form['password']
    cursor = conn.cursor()
    cursor.execute(f'SELECT password FROM {role} WHERE username = ?', (u))
    stored_password = cursor.fetchone()
    conn.commit()
    conn.close()

    if stored_password and bcrypt.checkpw(p.encode('utf-8'), stored_password[0]):
        session['username'] = u
        session['role'] = role
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username, password, or role.')
        return redirect(url_for('home'))
    
    """if check_user(u,p):
        session['username'] = u
        session['role'] = role
        return redirect(url_for('dashboard'))
    else :
        flash('Invalid username, password, or role.')
        return redirect(url_for('home'))"""
    
    
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f'Welcome {session["username"]} to the dashboard!'
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))

def create_table(role):
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {role}(
                     id INTEGER,
                     username TEXT NOT NULL,
                     password TEXT NOT NULL,
                     PRIMARY KEY(id,username))''')
    conn.commit()
    conn.close()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def insert_user(role,username, password):
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()

    hashed_password = hash_password(password)
    cursor.execute(f'''INSERT INTO {role} (id,
                   username, password) VALUES ( ?, ?, ?)''', (unique_id(role),username,hashed_password))

    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()

    cursor.execute('''SELECT password FROM users WHERE username = ?''', (username,))
    stored_password = cursor.fetchone()

    conn.close()

    if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password[0]):
        return True
    else:
        return False

def unique_id(role):
    uid=random.randint(100000, 999999)
    if check_unique_id_exists(uid,role):
        unique_id(role)
    return uid  


def check_unique_id_exists(unique_id,role):
    conn = sqlite3.connect('user_credentials.db') 
    cursor = conn.cursor()
    cursor.execute(f'SELECT 1 FROM {role} WHERE id = ?',(unique_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def check_username_exists(username,role):
    conn = sqlite3.connect('user_credentials.db') 
    cursor = conn.cursor()
    cursor.execute(f'SELECT 1 FROM {role} WHERE id = ?',(username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None
    
if __name__ == '__main__':
    app.run(debug=True)
