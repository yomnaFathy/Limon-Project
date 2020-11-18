import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from models import db, bcrypt, User
from utils.auth import generate_token

app = Flask(__name__)
app.secret_key = os.urandom(24)
db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))

POSTGRES = {
    'user': 'postgres',
    'pw': '12345',
    'host': 'localhost',
    'port': '5432',
    'db': 'test2'
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.email)

@app.route('/login', methods=['GET', 'POST'])
def login_post():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.get_user_by_email_and_password(email, password)

        if not user:
            flash('Please check your login details and try again.')
            return redirect(url_for('login_post'))
            
        login_user(user, remember=remember)
        return redirect(url_for('profile'))
    else:
        return render_template('login.html')


@app.route('/signup', methods=['GET','POST'])
def signup_post():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.get_user_by_email_and_password(email, password)
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))   

        new_user = User.create_user(email, password) ## NEEDS MODIFICATION

        # return redirect(url_for('login'))
        return jsonify(
            id=new_user.id,
            token=generate_token(user=new_user,SECRET_KEY=app.secret_key)
        )
    else:
        return render_template('signup.html')

@app.route('/get_token', methods=['POST'])
def get_token():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.get_user_by_email_and_password(email, password)
    if user:
        return jsonify(token=generate_token(user))

    return jsonify(error=True), 403

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)