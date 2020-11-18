import os


class BaseConfig(object):
    DEBUG = False
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class TestingConfig(BaseConfig):
    
    POSTGRES = {
    'user': 'postgres',
    'pw': '12345',
    'host': 'localhost',
    'port': '5432',
    'db': 'test2'
    }
    SQLALCHEMY_DATABASE_URI = 'postgresql://%(user)s:\
        %(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
    DEBUG = True
    SECRET_KEY = os.urandom(24)