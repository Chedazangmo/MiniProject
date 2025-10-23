# app/routes.py - UPDATED VERSION WITHOUT FLASH
from flask import Blueprint, render_template, redirect, url_for, request, jsonify, make_response
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from __init__ import db
from app.models import Task, User
from app.forms import TaskForm, RegistrationForm, LoginForm

task_bp = Blueprint('task', __name__)
auth_bp = Blueprint('auth', __name__)

# Simple message storage (alternative to flash)
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
            user = User.query.filter_by(username=current_user).first()
            return dict(current_user_id=user.id if user else None, messages=get_messages())
    except:
        pass
    return dict(current_user_id=None, messages=get_messages())

# HTML Routes
@task_bp.route('/')
@jwt_required(optional=True)
def index():
    current_user = get_jwt_identity()
    
    if current_user:
        user = User.query.filter_by(username=current_user).first()
        if user:
            tasks = Task.query.filter_by(user_id=user.id).all()
        else:
            tasks = []
    else:
        tasks = []
    
    return render_template('index.html', tasks=tasks)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    print(f"DEBUG: Register - Method: {request.method}, Validate: {form.validate_on_submit()}")
    
    if form.validate_on_submit():
        print("DEBUG: Form is valid, creating user...")
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print(f"DEBUG: User created: {user.username}")
        
        add_message('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    else:
        print(f"DEBUG: Form errors: {form.errors}")
    
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print(f"DEBUG: Login - Method: {request.method}, Validate: {form.validate_on_submit()}")
    
    if form.validate_on_submit():
        print("DEBUG: Form is valid, checking credentials...")
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            print(f"DEBUG: Login successful for user: {user.username}")
            access_token = create_access_token(identity=user.username)
            response = make_response(redirect(url_for('task.index')))
            set_access_cookies(response, access_token)
            add_message('Login successful!', 'success')
            return response
        else:
            print("DEBUG: Invalid credentials")
            add_message('Invalid username or password', 'error')
    else:
        print(f"DEBUG: Form errors: {form.errors}")
    
    return render_template('login.html', form=form)




@auth_bp.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    unset_jwt_cookies(response)
    add_message('You have been logged out.', 'info')
    return response

# ... keep the rest of your routes the same
@task_bp.route('/add', methods=['GET','POST'])
@jwt_required()
def add_task():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=form.title.data,
            description=form.description.data,
            status=form.status.data,
            user_id=user.id
        )
        db.session.add(task)
        db.session.commit()
        add_message('Task added successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('add_task.html', form=form)

@task_bp.route('/edit/<int:id>', methods=['GET','POST'])
@jwt_required()
def edit_task(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    task = Task.query.filter_by(id=id, user_id=user.id).first_or_404()
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.status = form.status.data
        db.session.commit()
        add_message('Task updated successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('edit_task.html', form=form, task=task)

@task_bp.route('/delete/<int:id>')
@jwt_required()
def delete_task_html(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    task = Task.query.filter_by(id=id, user_id=user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    add_message('Task deleted successfully!', 'info')
    return redirect(url_for('task.index'))

# Add these debug routes to app/routes.py

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
    <p><strong>Authentication Method:</strong> JWT Tokens</p>
    """