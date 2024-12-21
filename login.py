import sqlite3
import bcrypt
import random
from flask import Flask, render_template, request, redirect, url_for, flash, session


app = Flask(__name__)
app.secret_key = 'HEMUCHOMU'

conn = sqlite3.connect('user_credentials.db')
cursor = conn.cursor()


@app.route('/')
def home():
    return render_template('FINAL.html')


@app.route('/signup', methods=['POST'])
def Signup():
    print(request.form,"sad")
    username = request.form['signup-username']
    password = request.form['signup-password']
    role = request.form['signup-role']
    if not username or not password or not role:
        flash('Please fill in all fields.')
        return redirect(url_for('home'))
    create_table(role)
    insert_user(role,username,password)

    flash('Signup successful! Please log in.')
    return redirect(url_for('home'))
    


"""@app.route('/login', methods=['POST'])
def login():
    u = request.form['username']
    p = request.form['password']
    role = request.form['role']
    cursor = conn.cursor()
    cursor.execute(f'SELECT password FROM {role} WHERE username = ? AND role = ?', (u, role))
    stored_password = cursor.fetchone()
    conn.close()

    if stored_password and bcrypt.checkpw(p.encode('utf-8'), stored_password[0]):
        session['username'] = u
        session['role'] = role
        return redirect(url_for('dashboard'))
    else:
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
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {role}(
                     id INTEGER,
                     username TEXT NOT NULL,
                     password TEXT NOT NULL,
                     PRIMARY KEY(id,username))''')

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

# Function to print all users from the database
def print_all_users():
    conn = sqlite3.connect('user_credentials.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    print("Users in the database:")
    for row in rows:
        print(f"ID: {row[0]}, Username: {row[1]}, Password: {row[2]}")

    conn.close()

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

def get_role():
    role = (input("Enter Role : ")).strip()
    return role
    

"""def main():
    u=input("Enter username : ")
    p=input("Enter password : ")
    role=get_role()"""
    

"""def main():
    print_all_users()"""
"""def main():
    while True:
        u = input("Username : ")
        p = input("Password : ")
        if check_user(u,p):
            print("Login Successfull")
        else :
            print("Invalid username or password")"""


if __name__ == '__main__':
    app.run(debug=True)

conn.commit()
conn.close()
