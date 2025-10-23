# test_jwt.py
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'test-secret-key'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)

@app.route('/test-jwt')
@jwt_required(optional=True)
def test_jwt():
    current_user = get_jwt_identity()
    return f"JWT Test - User: {current_user}"

@app.route('/test-simple')
def test_simple():
    return "Simple route works!"

@app.route('/')
def home():
    return "Home page - <a href='/test-simple'>Test Simple</a> | <a href='/test-jwt'>Test JWT</a>"

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Use different port to avoid conflict