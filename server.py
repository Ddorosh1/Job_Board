from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app=Flask(__name__)
app.secret_key = "wow"
bcrypt = Bcrypt(app)
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add_user', methods=['POST'])
def add_user():
    if request.form['password'] != '':
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        is_valid = True
        if not email_regex.match(request.form['email']):
            is_valid = False
            flash('Invalid Email')
        if len(request.form['first_name']) < 2:
            is_valid = False
            flash('Please enter a valid first name')
        if len(request.form['last_name']) < 2:
            is_valid = False
            flash('Please enter a valid last name')
        if len(request.form['password']) < 6:
            is_valid = False
            flash('Password needs to be at least 6 characters')
        if request.form['password'] != request.form['cpassword']:
            is_valid = False
            flash('Passwords do not match')
        if is_valid:
            session['email'] = request.form['email']
            session['first_name'] = request.form['first_name']
            mysql = connectToMySQL('manage_jobs')
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW())"
            data = {
                'fn': request.form['first_name'],
                'ln': request.form['last_name'],
                'em': request.form['email'],
                'pw': pw_hash
            }
            result = mysql.query_db(query, data)
            print(result)
            session['logged_in_id'] = result
            return redirect('/dashboard')
    flash('You must fill out the registration')
    return redirect('/')

@app.route('/log_in', methods=['POST'])
def login():
    is_valid = True
    if request.form['password'] == '':
        flash('You must enter a password')
        return redirect('/')
    if request.form['email'] == "":
        flash('You must enter a valid email')
        return redirect('/')
    else:
        if not email_regex.match(request.form['email']):
            is_valid = False
            flash('Invalid Email')
            return redirect('/')
        if is_valid:
            mysql = connectToMySQL('manage_jobs')
            query = "SELECT id, email, password FROM users WHERE email = %(em)s"
            data = {
                'em': request.form['email']
            }
            result = mysql.query_db(query, data)
            if result:
                if bcrypt.check_password_hash(result[0]['password'], request.form['password'] ):
                    session['logged_in_id'] = result[0]['id']
                    return redirect('/dashboard')
            else:
                flash("You could not be logged in")
                return redirect('/')
            flash('You could not be logged in')
            return redirect('/')

@app.route('/log_out')
def logout():
    session.pop('logged_in_id')
    return redirect('/')

@app.route('/dashboard')
def dash():
    if not 'logged_in_id' in session:
        return redirect('/')
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT id, title, location from jobs WHERE NOT users_id = %(id)s ORDER BY updated_at desc"
    data = {
        'id': session['logged_in_id']
    }
    data1 = mysql.query_db(query, data)
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT first_name FROM users WHERE id = %(id)s"
    data = {
        'id': session['logged_in_id']
    }
    result = mysql.query_db(query, data)
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT id, title, location, users_id from jobs WHERE users_id = %(id)s"
    data = {
        'id': session['logged_in_id']
    }
    jobs = mysql.query_db(query, data)
    print(jobs)
    return render_template('dashboard.html', user = result, data = data1, jobs_data = jobs)

@app.route('/new')
def new():
    if not 'logged_in_id' in session:
        return redirect('/')
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT first_name FROM users WHERE id = %(id)s"
    data = {
        'id': session['logged_in_id']
    }
    data = mysql.query_db(query, data)
    return render_template('new.html', data = data)

@app.route('/cancel')
def cancel():
    return redirect('/dashboard')

@app.route('/create_job', methods=['POST'])
def create():
    if not 'logged_in_id' in session:
        return redirect('/')
    is_valid = True
    if len(request.form['title']) < 3:
        is_valid = False
        flash("The job title must consist of at least 3 characters")
    if len(request.form['desc']) < 3:
        is_valid = False
        flash("Description must consist of at least 3 characters")
    if len(request.form['location']) < 3:
        is_valid = False
        flash("A location must be provided")
    if is_valid:
        mysql = connectToMySQL('manage_jobs')
        query = "INSERT INTO jobs (title, description, location, created_at, updated_at, users_id) VALUES (%(title)s, %(desc)s, %(location)s, NOW(), NOW(), %(id)s)"
        data = {
            'title': request.form['title'],
            'desc': request.form['desc'],
            'location': request.form['location'],
            'id': session['logged_in_id']
        }
        data = mysql.query_db(query, data)        
        return redirect('/dashboard')
    else:
        return redirect('/new')

@app.route('/edit_page/<id>')
def edit(id):
    if not 'logged_in_id' in session:
        return redirect('/')
    session['job_id'] = id
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT title, description, location FROM jobs WHERE id = %(id)s "
    data = {
        'id': id
    }
    results = mysql.query_db(query, data)
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT first_name FROM users WHERE id = %(id)s"
    data = {
        'id': session['logged_in_id']
    }
    user = mysql.query_db(query, data)
    return render_template('edit.html', data = results, user = user)

@app.route('/jobs/<id>')
def details(id):
    if not 'logged_in_id' in session:
        return redirect('/')
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT jobs.id, users.first_name, title, description, location, jobs.created_at FROM jobs JOIN users on users.id = users_id WHERE jobs.id = %(id)s"
    data = {
        'id': id
    }
    result = mysql.query_db(query, data)
    mysql = connectToMySQL('manage_jobs')
    query = "SELECT first_name FROM users WHERE id = %(uid)s"
    data = {
        'uid': session['logged_in_id']
    }
    user = mysql.query_db(query, data)
    return render_template('details.html', user = user, data = result)

@app.route('/edit_job', methods=["POST"])
def edit_trip():
    is_valid = True
    if len(request.form['title']) < 3:
        is_valid = False
        flash("The job title must consist of at least 3 characters")
    if len(request.form['description']) < 3:
        is_valid = False
        flash("Description must consist of at least 3 characters")
    if len(request.form['location']) < 3:
        is_valid = False
        flash("A location must be provided")
    if is_valid:
        mysql = connectToMySQL('manage_jobs')
        query = "UPDATE jobs SET title = %(title)s, description = %(desc)s, location = %(location)s, updated_at = NOW() WHERE id = %(id)s"
        data = {
            'title': request.form['title'],
            'desc': request.form['description'],
            'location': request.form['location'],
            'id': request.form['job_id']
        }
        mysql.query_db(query, data)
        return redirect('/dashboard')
    else:
        return redirect('/edit_page/<id>')

@app.route('/delete/<id>')
def delete_trip(id):
    mysql = connectToMySQL('manage_jobs')
    query = "DELETE FROM jobs WHERE id = %(id)s "
    data = {
        'id': id
    }
    mysql.query_db(query, data)
    return redirect('/dashboard')

app.run(debug=True)