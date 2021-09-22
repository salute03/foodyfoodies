import os
from flask import (
    Flask, flash, render_template,
    redirect, request, session, url_for)
from form import RegisterForm, LoginForm
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
if os.path.exists("env.py"):
    import env


app = Flask(__name__)

app.config["MONGO_DBNAME"] = os.environ.get("MONGO_DBNAME")
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")
app.secret_key = os.environ.get("SECRET_KEY")

mongo = PyMongo(app)


@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/login",  methods=['GET', 'POST'])
def login():
    '''
    The login function calls LoginForm class from forms.py,
    It checks if the entered username and passwords are valid
    and then add user to session.
    '''
    # Check if the user is already logged in
    if 'username' in session:
        flash('You are already logged in!')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        # Variable for users collection
       
        registered_user = mongo.db.users.find_one({'username': request.form.get('username')})

        if registered_user:
            # Check if password in the form is equal to the password in the DB
            if check_password_hash(registered_user['password'],
                                   request.form['password']):
                # Add user to session if passwords match
                session['username'] = request.form['username']
                flash('You have been successfully logged in!')
                return redirect(url_for('home'))
            else:
                # if user entered incorrect password
                flash("Incorrect username or password. Please try again")
                return redirect(url_for('login'))
        else:
            # if user entered incorrect username
            flash("Username does not exist! Please try again")
            return redirect(url_for('login'))
    return render_template('login.html',  form=form, title='Login')


@app.route("/register", methods=['GET', 'POST'])
def register():
    '''
    CREATE.
    Creates a new account; it calls the RegisterForm class from forms.py.
    Checks if the username is not already excist in database,
    hashes the entered password and add a new user to session.
    '''
    # checks if user is not already logged in
    if 'username' in session:
        flash('You are already registered!')
        return redirect(url_for('home'))

    form = RegisterForm()
    if form.validate_on_submit():
        # variable for users collection
       
        # checks if the username is unique
        registered_user = mongo.db.users.find_one({'username': request.form.get('username')})
        if registered_user:
            flash("Sorry, this username is already taken!")
            return redirect(url_for('register'))
        else:
            # hashes the entered password
            hashed_password = generate_password_hash(
                                request.form.get('password'))
            new_user = {
                "username": request.form.get('username'),
                "password": hashed_password,
                "user_recipes": [],
            }
            mongo.db.users.insert_one(new_user)
            # add new user to the session
            session["username"] = request.form.get('username')
            flash('Your account has been successfully created.')
            return redirect(url_for('home'))
    return render_template('register.html', form=form,  title='Register')


if __name__ == "__main__":
    app.run(host=os.environ.get("IP"),
            port=int(os.environ.get("PORT")),
            debug=True)