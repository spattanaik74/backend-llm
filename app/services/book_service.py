from app.models import *
from app.repositories.book_repository import *
from app.models import db

class BookService:
    @staticmethod
    def add_book(data):
        author_name = data.get('author')
        author = Author.query.filter_by(name=author_name).first()
        if not author:
            author = Author(name=author_name)
            db.session.add(author)
            db.session.commit()
        
        book = Book(title=data.get('title'), author=author, published_date=data.get('published_date'), isbn=data.get('isbn'))
        BookRepository.add(book)
        return book

    @staticmethod
    def update_book(book_id, data):
        book = BookRepository.get_by_id(book_id)
        if book:
            book.title = data.get('title')
            author_name = data.get('author')
            author = Author.query.filter_by(name=author_name).first()
            if not author:
                author = Author(name=author_name)
                db.session.add(author)
                db.session.commit()
            book.author = author
            book.published_date = data.get('published_date')
            book.isbn = data.get('isbn')
            db.session.commit()
        return book

    @staticmethod
    def delete_book(book_id):
        book = BookRepository.get_by_id(book_id)
        if book:
            BookRepository.delete(book)
        return book

    @staticmethod
    def get_books():
        return BookRepository.get_all()

    @staticmethod
    def get_book(book_id):
        return BookRepository.get_by_id(book_id)


