from app.models import *

class BookRepository:
    @staticmethod
    def add(book):
        db.session.add(book)
        db.session.commit()

    @staticmethod
    def delete(book):
        db.session.delete(book)
        db.session.commit()

    @staticmethod
    def get_all():
        return Book.query.all()

    @staticmethod
    def get_by_id(book_id):
        return Book.query.get(book_id)
