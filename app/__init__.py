from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
import datetime
from flask.sessions import SessionInterface, SessionMixin

# ==========================
# 🔒 Custom Null Session Setup
# ==========================
class NullSession(dict, SessionMixin):
    """A session object that does nothing."""
    def __setitem__(self, *args, **kwargs): pass
    def __getitem__(self, *args, **kwargs): return None
    def get(self, *args, **kwargs): return None

class NullSessionInterface(SessionInterface):
    """Completely disable Flask session cookies."""
    def open_session(self, app, request):
        return NullSession()

    def save_session(self, app, session, response):
        # Prevent Flask from setting any session cookie
        return


# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()


def create_app():
    app = Flask(__name__, template_folder='templates')
    
    # Basic config
    app.config['SECRET_KEY'] = 'dev-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # DISABLE SESSIONS AND CSRF
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_TYPE'] = 'null'
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = 'super-secret-key-12345'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config['JWT_COOKIE_SECURE'] = False
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_SESSION_COOKIE'] = False
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
    app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
    app.config['JWT_COOKIE_DOMAIN'] = None
    app.config['JWT_COOKIE_SAMESITE'] = None

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)

    # Remove session cookie if found
    @app.after_request
    def remove_session_cookie(response):
        for cookie_name in ['session', '_csrf_token', 'rz']:
            if cookie_name in request.cookies:
                response.set_cookie(cookie_name, '', expires=0, max_age=0)
        return response

    # Register blueprints
    from app.routes import task_bp, auth_bp
    app.register_blueprint(task_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Create tables
    with app.app_context():
        db.create_all()

    # 🚀 DEBUG ROUTE INFO
    with app.app_context():
        print("🚀 === REGISTERED ROUTES ===")
        for rule in app.url_map.iter_rules():
            if 'static' not in str(rule):
                print(f"  {rule.endpoint}: {rule.rule} -> {list(rule.methods)}")
        print("🎯 === END ROUTES ===")

    # 🧠 THIS IS THE KEY — disable sessions entirely
    app.session_interface = NullSessionInterface()

    return app


__all__ = ['create_app', 'db', 'jwt']
