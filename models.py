from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
# from app import db, bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):

    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(225), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    def __init__(self, email, password):
        # self.id = id
        self.email = email
        self.password = User.hashed_password(password) 

    @staticmethod
    def create_user(email, password):
        user = User(
            # id = self.id,
            email = email,
            password = password
        )

        try:
            db.session.add(user)
            db.session.commit()
            return True
        except IntegrityError:
            return False
    
    @staticmethod
    def hashed_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    @staticmethod
    def get_user_by_id(user_id):
        user = User.query.filter_by(id=user_id)
        return user
    
    @staticmethod
    def get_user_by_email_and_password(email, password):
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return False
            