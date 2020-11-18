from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired, BadSignature

db = SQLAlchemy()
bcrypt = Bcrypt()
TWO_WEEKS = 1209600

class User(UserMixin, db.Model):

    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(225), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = User.hashed_password(password) 

    @staticmethod
    def create_user(email, password):
        user = User(
            email = email,
            password = password
        )

        try:
            db.session.add(user)
            db.session.commit()
            return user
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
      
    def generate_token(user, SECRET_KEY, expiration=TWO_WEEKS):
        s = Serializer(SECRET_KEY, expires_in=expiration)
        token = s.dumps({
            'id': user.id,
            'email': user.email,
        }).decode('utf-8')
        return token

    @staticmethod 
    def verify_token(token, SECRET_KEY):
        s = Serializer(SECRET_KEY)
        try:
            data = s.loads(token)
        except (BadSignature, SignatureExpired):
            return None
        return data