from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


    
    
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(200), nullable=False)
    published_date = db.Column(db.Date)
    isbn = db.Column(db.String(13), unique=True, nullable=False)
    public = db.Column(db.Boolean(), default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    author_name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f"<Book {self.title}>"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    salt = db.Column(db.String(100))
    pic = db.Column(db.String(100))
    
    books = db.relationship('Book', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"
