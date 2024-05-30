from flask import request, jsonify, abort, session, redirect, url_for,make_response
from .services.book_service import *
from .models import *
import hashlib
import secrets

import jwt
from datetime import datetime, timedelta

# Secret key for encoding JWTs
SECRET_KEY = 'your_secret_key_here'  # Replace with your actual secret key



def generate_jwt(username):
    expiration = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({'username': username, 'exp': expiration}, SECRET_KEY, algorithm='HS256')
    print("token",token)
    return token

# Function to generate a salted and hashed password
def hash_password(password, salt):
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed_password

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    wrapper.__name__ = f'login_required_{func.__name__}'
    return wrapper


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        stored_salt = user.salt
        stored_hashed_password = user.password
        hashed_password = hash_password(password, stored_salt)
        if hashed_password == stored_hashed_password:
            return True
    return False

def register_routes(app):
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if authenticate(username, password):
            token = generate_jwt(username)
            print("token",token)
            response_data = {
                'message': 'Login successful',
                'token': token  # Include the token in the response data
            }
            return jsonify(response_data)

        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        print(username)
        print(password)
        if not username or not password:
            print('1')
            return jsonify({'message': 'Username and password are required'}), 400
            
        if User.query.filter_by(username=username).first():
            print('2')
            return jsonify({'message': 'Username already exists'}), 400
        # Generate a random salt
        salt = secrets.token_hex(16)

        # Hash the password with the salt
        hashed_password = hash_password(password, salt)
        print(hashed_password)

        # Create a new user with the hashed password and salt
        new_user = User(username=username, password=hashed_password, salt=salt)
        
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201

    @app.route('/books', methods=['GET', 'POST'])
    @login_required
    def manage_books():
        if request.method == 'GET':
            books = BookService.get_books()
            books_list = [{'id': book.id, 'title': book.title, 'author': book.author.name,
                           'published_date': book.published_date, 'isbn': book.isbn} for book in books]
            return jsonify(books_list)
        elif request.method == 'POST':
            data = request.get_json()
            book = BookService.add_book(data)
            return jsonify({'id': book.id, 'title': book.title, 'author': book.author.name, 'published_date': book.published_date, 'isbn': book.isbn}), 201

    @app.route('/books/<int:book_id>', methods=['GET', 'PUT', 'DELETE'])
    @login_required
    def manage_book(book_id):
        if request.method == 'GET':
            book = BookService.get_book(book_id)
            if book is None:
                abort(404)
            return jsonify({'id': book.id, 'title': book.title, 'author': book.author.name, 'published_date': book.published_date, 'isbn': book.isbn})
        elif request.method == 'PUT':
            data = request.get_json()
            book = BookService.update_book(book_id, data)
            if book is None:
                abort(404)
            return jsonify({'id': book.id, 'title': book.title, 'author': book.author.name, 'published_date': book.published_date, 'isbn': book.isbn})
        elif request.method == 'DELETE':
            book = BookService.delete_book(book_id)
            if book is None:
                abort(404)
            return '', 204
        
        
    @app.route('/logout', methods=['POST'])
    def logout():
        response = make_response(jsonify({'message': 'Logout successful'}))
        response.set_cookie('session_token', '', expires=0)
        return response