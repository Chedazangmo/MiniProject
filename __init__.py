# __init__.py - FIXED VERSION
from flask import Flask, request  # ADD 'request' HERE
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import datetime

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__, template_folder='app/templates')
    
    # Basic config
    app.config['SECRET_KEY'] = 'dev-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # DISABLE SESSIONS AND CSRF
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF protection
    app.config['SESSION_TYPE'] = 'null'     # Disable server-side sessions
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = 'super-secret-key-12345'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_SESSION_COOKIE'] = False

    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)

    # Add middleware to prevent session creation
    @app.before_request
    def prevent_session_creation():
        from flask import session
        # Prevent session from being saved or modified
        session.modified = False
    
    @app.after_request
    def remove_session_cookie(response):
        """Ensure session cookie is not set"""
        # FIXED: 'request' is now imported at the top
        if 'session' in request.cookies:
            response.set_cookie('session', '', expires=0, max_age=0)
        return response

    # Register blueprints
    from app.routes import task_bp, auth_bp
    app.register_blueprint(task_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Create tables
    with app.app_context():
        db.create_all()

    return app
# Make sure these are available for import
__all__ = ['create_app', 'db', 'jwt']