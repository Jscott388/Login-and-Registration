from flask import Flask, render_template, redirect, request, flash, session
import datetime
import re
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

app = Flask(__name__)
app.secret_key = 'thissecret'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'login')

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')


queries = {
    'create' : 'INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())',
    'get_user' : "SELECT first_name, last_name, email FROM users WHERE id = :id",
    'login' : "SELECT id, password FROM users WHERE email = :email",
}

def get_user_id(email):
    email_query = "SELECT id FROM users WHERE email = :email"
    email_data = {'email' : email}
    user_email = mysql.query_db(email_query, email_data)
    return user_email

def get_user_id(id):
    query = queries['get_user']
    data = {'id': id}
    user = mysql.query_db(query, data)
    session['user'] = user
    return redirect('/welcome')

@app.route('/')
def index():
    if 'user' not in session:
        return render_template('index.html')

    return redirect ('/welcome')


@app.route('/login', methods=['POST'])
def login():
    login_error = False
    email = request.form['login_email']
    password = request.form['login_password']

    user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    query_data = {'email': email}
    user_login = mysql.query_db(user_query, query_data)
    print user_login

    if len(user_login) < 1:
        flash("Email not registered", 'error')
        login_error = True

    if not bcrypt.check_password_hash(user_login[0]['password'], password):
        flash("Email/password does not match", 'error')
        login_error = True

    if login_error == True:
        return redirect ('/')

    else:
        print 'Session Log'
        session['user'] = mysql.query_db(user_query, query_data)[0]
        return redirect('/welcome')

@app.route('/register', methods=['POST'])
def register_user():
    error = False

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm']

    query = "SELECT email FROM users"
    emails = mysql.query_db(query)

    if len(first_name) < 2 or len(last_name) < 2:
        flash("First and Last name must be at least 2 characters", 'error')
        error = True

    if not EMAIL_REGEX.match(email) or len(email) < 1:
        flash("Valid email required.", 'error')
        error = True

    elif {'email' : email} in emails:
        flash("Email already registered", 'error')
        error = True

    if len(password) < 8:
        flash("Password must be at least 8 characters", 'error')
        error = True

    elif confirm != password:
        flash("Password must match!", 'error')
        error = True

    if error == False:

        pw_hash = bcrypt.generate_password_hash(password)

        query = queries['create']
        data = {
                'first_name' : first_name,
                'last_name' : last_name,
                'email' : email,
                'password' : pw_hash
        }
        new_user = mysql.query_db(query, data)

        return get_user_id(new_user)

    else:
        return redirect('/')

    return redirect('/')

@app.route('/welcome')
def welcome():
    if not 'user' in session:
        return redirect('/')

    return render_template('welcome.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user')
    return redirect('/')

app.run(debug=True)
