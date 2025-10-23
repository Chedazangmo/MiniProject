# __init__.py - CORRECT CONFIG (allow sessions for CSRF)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import datetime

db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__, template_folder='app/templates')
    
    # Basic config
    app.config['SECRET_KEY'] = 'dev-secret-key'  # IMPORTANT: Same for sessions and JWT
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = 'super-secret-key-12345'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False

    db.init_app(app)
    jwt.init_app(app)

    # Register blueprints
    from app.routes import task_bp, auth_bp
    app.register_blueprint(task_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app