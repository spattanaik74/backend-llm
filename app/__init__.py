from flask import Flask
from .config import *
from .view import register_routes
from .models import db
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = 'your_secret_key_here'

    db.init_app(app)
    CORS(app)
    register_routes(app)

    with app.app_context():
        db.create_all()

    return app
