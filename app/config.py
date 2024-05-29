import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql://root:06122001@localhost:3306/book_data'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
