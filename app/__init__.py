from flask import Flask
from .config import *
from .view import *
from .models import db
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    

    db.init_app(app)
    CORS(app,supports_credentials=True)
    register_routes(app)

    with app.app_context():
        db.create_all()

    return app
