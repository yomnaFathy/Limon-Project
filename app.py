import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_httpauth import HTTPBasicAuth
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from models import db, bcrypt, User
# from utils.auth import generate_token, verify_token

app = Flask(__name__)
app.secret_key = os.urandom(24)
db.init_app(app)
bcrypt.init_app(app)
auth = HTTPBasicAuth()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# @login_manager.user_loader
# def load_user(user_id):

#     return User.query.get(int(user_id))

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

@app.route('/signup', methods=['POST'])
def signup():
    
    email = request.json.get('email')
    password = request.json.get('password')
    if email is None or password is None:
        abort(400) # missing arguments
    user = User.get_user_by_email_and_password(email, password)
    if user:
        flash('Email address already exists')
        return jsonify({'data': 'Email address already exists'})

    new_user = User.create_user(email, password) ## NEEDS MODIFICATION
    
    return jsonify(
        id=new_user.id,
        token=User.generate_token(user=new_user,SECRET_KEY=app.secret_key)
    )


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = User.get_user_by_email_and_password(email, password)
    if user:
        token=User.generate_token(user, SECRET_KEY=app.secret_key)
        g.token = token
        return jsonify(token=token)

    return jsonify(error=True), 403


@app.route("/api/is_token_valid", methods=["POST"])
def is_token_valid():
    incoming = request.get_json()
    is_valid = User.verify_token(incoming["token"], SECRET_KEY=app.secret_key)

    if is_valid:
        return jsonify(token_is_valid=True)
    else:
        return jsonify(token_is_valid=False), 403


@app.route("/api/user", methods=["GET"])
@auth.login_required
def get_user():
    return jsonify({ 'data': 'Hello,'})

@auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    user = User.verify_token(email_or_token, SECRET_KEY=app.secret_key)
    if not user:
        # try to authenticate with username/password
        user = User.get_user_by_email_and_password(email_or_token, password)
        if not user:
            return False
    g.user = user
    return True

@app.route('/logout')
@auth.login_required
def logout():
    ()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)