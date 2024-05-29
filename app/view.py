from flask import request, jsonify, abort, session, redirect, url_for
from .services.book_service import *
from .models import *

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    wrapper.__name__ = f'login_required_{func.__name__}'
    return wrapper

def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password==password:
        session['user_id'] = user.id
        return True
    return False

def register_routes(app):
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if authenticate(username, password):
            return jsonify({'message': 'Login successful'})
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists'}), 400
        new_user = User(username=username,password=password)
        db.session.add(new_user)  # Add the new user to the session
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
        session.pop('user_id', None)  # Remove the 'user_id' from the session
        return jsonify({'message': 'Logout successful'})