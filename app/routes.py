# app/routes.py - FIXED IMPORTS FOR ROOT __init__.py
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, make_response, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies
)
from flask_sqlalchemy import SQLAlchemy

# Import models and forms
from app.models import Task, User
from app.forms import TaskForm, RegistrationForm, LoginForm

task_bp = Blueprint('task', __name__)
auth_bp = Blueprint('auth', __name__)

# Helper function to get db instance


def get_db():
    return current_app.extensions['sqlalchemy']

# Helper function to get database session


def get_db_session():
    db = get_db()
    return db.session


# Simple message storage
messages = []


def add_message(text, category='info'):
    messages.append({'text': text, 'category': category})


def get_messages():
    global messages
    msgs = messages.copy()
    messages.clear()
    return msgs

# Context processor


@task_bp.app_context_processor
@auth_bp.app_context_processor
def inject_user():
    try:
        current_user = get_jwt_identity()
        if current_user:
            db_session = get_db_session()
            user = db_session.query(User).filter_by(
                username=current_user).first()
            return dict(
                current_user_id=user.id if user else None,
                messages=get_messages())
    except BaseException:
        pass
    return dict(current_user_id=None, messages=get_messages())

# HTML Routes


@task_bp.route('/')
@jwt_required(optional=True)
def index():
    current_user = get_jwt_identity()
    db_session = get_db_session()

    if current_user:
        user = db_session.query(User).filter_by(username=current_user).first()
        if user:
            tasks = db_session.query(Task).filter_by(user_id=user.id).all()
        else:
            tasks = []
    else:
        tasks = []

    return render_template('index.html', tasks=tasks)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    db_session = get_db_session()

    if form.validate_on_submit():
        # Check if username already exists
        existing_user = db_session.query(User).filter_by(
            username=form.username.data).first()
        if existing_user:
            add_message('Username already exists!', 'error')
            return render_template('register.html', form=form)

        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db_session.add(user)
        db_session.commit()

        add_message('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)

@auth_bp.route('/api/register', methods=['POST'])
def api_register():
    """JSON API endpoint for user registration"""
    print("=== API REGISTER CALLED ===")  # Debug line
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    print(f"Received data: {data}")  # Debug line
    db_session = get_db_session()
    
    # Validate required fields
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # Check if username already exists
    existing_user = db_session.query(User).filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    
    # Create new user (only username and password)
    user = User(username=username)
    user.set_password(password)
    
    db_session.add(user)
    db_session.commit()
    
    print(f"User created: {username}")  # Debug line
    return jsonify({
        "message": "User registered successfully",
        "user_id": user.id,
        "username": user.username
    }), 201


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    db_session = get_db_session()

    if form.validate_on_submit():
        user = db_session.query(User).filter_by(
            username=form.username.data).first()

        if user and user.check_password(form.password.data):
            # Create both access and refresh tokens
            access_token = create_access_token(identity=user.username)
            refresh_token = create_refresh_token(identity=user.username)

            response = make_response(redirect(url_for('task.index')))
            # Set both tokens as cookies
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            add_message('Login successful!', 'success')
            return response
        else:
            add_message('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@auth_bp.route('/api/login', methods=['POST'])
def api_login():
    """JSON API endpoint for user login"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    db_session = get_db_session()
    
    # Validate required fields
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # Find user and verify password
    user = db_session.query(User).filter_by(username=username).first()
    
    if user and user.check_password(password):
        # Create JWT tokens
        access_token = create_access_token(identity=user.username)
        refresh_token = create_refresh_token(identity=user.username)
        
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user.id,
            "username": user.username
        }), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        response = jsonify({'msg': 'Token refreshed successfully'})
        set_access_cookies(response, new_access_token)
        return response, 200
    except Exception as e:
        return jsonify({'msg': 'Token refresh failed', 'error': str(e)}), 401


@auth_bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    # Unset both access and refresh cookies
    unset_jwt_cookies(response)
    add_message('You have been logged out.', 'info')
    return response

# Add these routes after your existing logout route


@auth_bp.route('/clean-all', methods=['POST', 'GET'])
def clean_all():
    """
    Clear all JWT cookies from the client.
    """
    response = jsonify({"msg": "All JWT cookies cleared successfully."})
    unset_jwt_cookies(response)  # Removes both access and refresh cookies
    return response


@task_bp.route('/debug/auth-check')
@jwt_required(optional=True)
def debug_auth_check():
    """Check authentication status"""
    current_user = get_jwt_identity()

    return jsonify({
        'jwt_identity': current_user,
        'cookies_present': {
            'access_token': 'access_token_cookie' in request.cookies,
            'refresh_token': 'refresh_token_cookie' in request.cookies
        },
        'authentication_method': 'JWT Only' if current_user else 'None'
    })


@task_bp.route('/add', methods=['GET', 'POST'])
@jwt_required()
def add_task():
    current_user = get_jwt_identity()
    db_session = get_db_session()
    user = db_session.query(User).filter_by(username=current_user).first()

    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=form.title.data,
            description=form.description.data,
            status=form.status.data,
            user_id=user.id
        )
        db_session.add(task)
        db_session.commit()
        add_message('Task added successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('add_task.html', form=form)


@task_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@jwt_required()
def edit_task(id):
    current_user = get_jwt_identity()
    db_session = get_db_session()
    user = db_session.query(User).filter_by(username=current_user).first()

    task = db_session.query(Task).filter_by(
        id=id, user_id=user.id).first_or_404()
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.status = form.status.data
        db_session.commit()
        add_message('Task updated successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('edit_task.html', form=form, task=task)


@task_bp.route('/delete/<int:id>')
@jwt_required()
def delete_task_html(id):
    current_user = get_jwt_identity()
    db_session = get_db_session()
    user = db_session.query(User).filter_by(username=current_user).first()

    task = db_session.query(Task).filter_by(
        id=id, user_id=user.id).first_or_404()
    db_session.delete(task)
    db_session.commit()
    add_message('Task deleted successfully!', 'info')
    return redirect(url_for('task.index'))

# Debug routes


@auth_bp.route('/debug-form', methods=['GET', 'POST'])
def debug_form():
    """Test form validation"""
    form = LoginForm()
    if request.method == 'POST':
        return f"""
        <h2>Form Debug</h2>
        <p>Form validated: {form.validate_on_submit()}</p>
        <p>Form errors: {form.errors}</p>
        <p>Username: {request.form.get('username')}</p>
        <p>Password: {request.form.get('password')}</p>
        """

    return """
    <h2>Test Form</h2>
    <form method="POST">
        <input type="text" name="username" required><br>
        <input type="password" name="password" required><br>
        <button type="submit">Test</button>
    </form>
    """


@task_bp.route('/jwt-info')
@jwt_required()
def jwt_info():
    current_user = get_jwt_identity()
    return f"""
    <h2>JWT Verification</h2>
    <p><strong>Current User:</strong> {current_user}</p>
    <p><strong>JWT Status:</strong> ✅ VALID AND WORKING</p>
    <p><strong>Authentication Method:</strong> JWT Tokens (Access + Refresh)</p>
    <p><strong>Tokens:</strong> Both access and refresh tokens implemented</p>
    """
@auth_bp.route('/debug-users')
def debug_users():
    from app.models import User
    users = User.query.all()
    return f"<h2>Total Users: {len(users)}</h2>" + "<br>".join([u.username for u in users])

@task_bp.route('/debug/routes')
def debug_routes():
    """Show all available routes"""
    from flask import current_app
    routes = []
    for rule in current_app.url_map.iter_rules():
        if 'static' not in str(rule):
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'path': str(rule)
            })
    return jsonify(routes)

@task_bp.route('/health')
def health_check():
    """Health check endpoint"""
    from datetime import datetime
    try:
        return jsonify({
            'status': 'healthy',
            'service': 'task-manager',
            'authentication': 'jwt_with_refresh_tokens'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503
@task_bp.route('/api/tasks', methods=['GET'])
@jwt_required()
def api_get_tasks():
    """JSON API endpoint to get all tasks for current user"""
    current_user = get_jwt_identity()
    db_session = get_db_session()
    
    user = db_session.query(User).filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    tasks = db_session.query(Task).filter_by(user_id=user.id).all()
    
    tasks_data = []
    for task in tasks:
        tasks_data.append({
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "status": task.status,
        })
    
    return jsonify({
        "tasks": tasks_data,
        "count": len(tasks_data)
    }), 200
@task_bp.route('/api/tasks', methods=['POST'])
@jwt_required()
def api_add_task():
    """JSON API endpoint to add a new task"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    current_user = get_jwt_identity()
    db_session = get_db_session()
    
    user = db_session.query(User).filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    data = request.get_json()
    
    if not data or not data.get('title'):
        return jsonify({"error": "Title is required"}), 400
    
    task = Task(
        title=data.get('title'),
        description=data.get('description', ''),
        status=data.get('status', 'pending'),
        user_id=user.id
    )
    
    db_session.add(task)
    db_session.commit()
    
    return jsonify({
        "message": "Task created successfully",
        "task": {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "status": task.status
        }
    }), 201

@task_bp.route('/api/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def api_update_task(task_id):
    """JSON API endpoint to update a task"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    current_user = get_jwt_identity()
    db_session = get_db_session()
    
    user = db_session.query(User).filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    task = db_session.query(Task).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    data = request.get_json()
    
    # Update task fields if provided
    if 'title' in data:
        task.title = data['title']
    if 'description' in data:
        task.description = data['description']
    if 'status' in data:
        task.status = data['status']
    
    db_session.commit()
    
    return jsonify({
        "message": "Task updated successfully",
        "task": {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "status": task.status
        }
    }), 200
@task_bp.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def api_delete_task(task_id):
    """JSON API endpoint to delete a task"""
    current_user = get_jwt_identity()
    db_session = get_db_session()
    
    user = db_session.query(User).filter_by(username=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    task = db_session.query(Task).filter_by(id=task_id, user_id=user.id).first()
    if not task:
        return jsonify({"error": "Task not found"}), 404
    
    db_session.delete(task)
    db_session.commit()
    
    return jsonify({
        "message": "Task deleted successfully",
        "deleted_task_id": task_id
    }), 200