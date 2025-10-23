# working_jwt_test.py
from flask import Flask, make_response
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)
import datetime

app = Flask(__name__)

# SIMPLE JWT CONFIG
app.config['JWT_SECRET_KEY'] = 'super-secret-key-12345'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)

@app.route('/')
def home():
    return """
    <h1>JWT Working Test - Port 5000</h1>
    <p><strong>TEST IN THIS ORDER:</strong></p>
    <ol>
        <li><a href='/login'>LOGIN (Create Token)</a></li>
        <li><a href='/check-token'>CHECK TOKEN STATUS</a></li>
        <li><a href='/test-jwt'>TEST JWT (Protected Route)</a></li>
        <li><a href='/logout'>LOGOUT (Clear Token)</a></li>
    </ol>
    <hr>
    <p><a href='/debug-cookies'>DEBUG: View Cookies</a></p>
    """

@app.route('/login')
def login():
    # Create a simple token
    access_token = create_access_token(identity='test_user_123')
    
    response = make_response("""
    <h2 style="color: green;">✅ TOKEN CREATED!</h2>
    <p>JWT Token has been set in your cookies.</p>
    <p><strong>Next:</strong> <a href='/check-token'>Check if token is valid</a></p>
    <p><a href='/test-jwt'>Then test protected route</a></p>
    """)
    
    set_access_cookies(response, access_token)
    return response

@app.route('/test-jwt')
@jwt_required()
def test_jwt():
    current_user = get_jwt_identity()
    return f"""
    <h2 style="color: green;">✅ JWT SUCCESS!</h2>
    <p>Protected route accessed successfully.</p>
    <p><strong>Current User:</strong> {current_user}</p>
    <p><a href='/'>Back to Home</a></p>
    """

@app.route('/check-token')
@jwt_required(optional=True)
def check_token():
    current_user = get_jwt_identity()
    if current_user:
        return f"""
        <h2 style="color: green;">✅ TOKEN VALID</h2>
        <p><strong>Current User:</strong> {current_user}</p>
        <p><a href='/test-jwt'>Test Protected Route</a></p>
        """
    else:
        return """
        <h2 style="color: red;">❌ NO VALID TOKEN</h2>
        <p>No valid JWT token found in cookies.</p>
        <p><a href='/login'>Login to create token</a></p>
        """

@app.route('/logout')
def logout():
    response = make_response("""
    <h2 style="color: blue;">✅ LOGGED OUT</h2>
    <p>JWT token cleared from cookies.</p>
    <p><a href='/'>Back to Home</a></p>
    """)
    unset_jwt_cookies(response)
    return response

@app.route('/debug-cookies')
def debug_cookies():
    from flask import request
    cookies = request.cookies
    cookie_info = "<br>".join([f"{k}: {v}" for k, v in cookies.items()])
    
    return f"""
    <h2>Cookie Debug Info</h2>
    <p><strong>Found {len(cookies)} cookies:</strong></p>
    <pre>{cookie_info}</pre>
    <p><a href='/'>Back to Home</a></p>
    """

if __name__ == '__main__':
    print("🚀 Starting JWT test server on http://127.0.0.1:5000")
    print("📝 Visit http://127.0.0.1:5000 to test")
    print("🔧 Using safe port 5000")
    app.run(debug=True, port=5000)  # CHANGED TO PORT 5000