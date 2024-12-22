import sqlite3
import bcrypt
import random
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'HEMUCHOMU'
app.run
role=""


@app.route('/ultimatefinal.html')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))   
    global role
    role = request.args.get('role')
    session['role']=role
    print(role,"login 1")
    return render_template('ultimatefinal.html')

@app.route('/landingmain.html')
def home1():
    return render_template('landingmain.html')


@app.route('/')
def home2():
    return render_template('landingmain.html')

@app.route('/about.html')
def home3():
    return render_template('about.html')


@app.route('/signup', methods=['POST'])
def Signup():
    print("sad 2",role )
    create_table(role)
    username = request.form.get('signup-username')
    password = request.form.get('signup-password')
    if not username or not password:
        flash('Please fill in all fields.')
        return redirect(url_for('signup'))
    if check_username_exists(username,role):
        flash('Username already exists.')
        username = request.form.get('signup-username')
        return redirect(url_for('signup'))
    print("5",role)
    insert_user(role,username,password)     
    flash('Signup successful! Please log in.')
    return redirect(url_for('login'))

@app.route("/db", methods=['GET'])
def db():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM client")
    print(cursor.fetchall())
    


@app.route('/login', methods=['POST'])
def login():
    print(role,"login 8")
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    u = request.form['username']
    p = request.form['password']
    cursor = conn.cursor()
    cursor.execute(f'SELECT password FROM {role} WHERE username = ?', (u,))
    stored_password = cursor.fetchone()
    conn.commit()
    conn.close()

    """if stored_password and bcrypt.checkpw(p.encode('utf-8'), stored_password[0]):
        session['username'] = u
        session['role'] = role
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username, password, or role.')
        return redirect(url_for('login'))"""
    
    if check_user(u,p):
        session['username'] = u
        session['role'] = role
        print("working")
        return render_template('ultimatefinal.html')
    else :
        print("not working")
        flash('Invalid username, password, or role.')
        return redirect(url_for('login'))
    
    
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('ultimatefinal.html')
    

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

def create_table(role):
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    print(role,"create table 3")
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
    print(role,"6")
    hashed_password = hash_password(password)
    cursor.execute(f'''INSERT INTO {role} (id,
                   username, password) VALUES ( ?, ?, ?)''', (unique_id(role),username,hashed_password))
    print(role,"7")
    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()

    cursor.execute(f'''SELECT password FROM {role} WHERE username = ?''', (username,))
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
    print(role,"checkuser 4 ")
    cursor.execute(f'SELECT 1 FROM {role} WHERE username = ?',(username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None
    
if __name__ == '__main__':
    app.run(debug=True)
