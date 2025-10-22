# app/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, session
from __init__ import db
from app.models import Task, User
from app.forms import TaskForm, RegistrationForm, LoginForm

task_bp = Blueprint('task', __name__)
auth_bp = Blueprint('auth', __name__)

# Home route - ONLY ONE DEFINITION
@task_bp.route('/')
def index():
    current_user_id = session.get('user_id')
    
    if current_user_id:
        tasks = Task.query.filter_by(user_id=current_user_id).all()
    else:
        tasks = Task.query.all()
    
    return render_template('index.html', 
                         tasks=tasks, 
                         current_user_id=current_user_id)

# Authentication Routes
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('task.index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# Task management routes
@task_bp.route('/add', methods=['GET','POST'])
def add_task():
    current_user_id = session.get('user_id')
    
    if not current_user_id:
        flash('Please login to add tasks', 'error')
        return redirect(url_for('auth.login'))
    
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=form.title.data,
            description=form.description.data,
            status=form.status.data,
            user_id=current_user_id
        )
        db.session.add(task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('add_task.html', form=form, current_user_id=current_user_id)

@task_bp.route('/edit/<int:id>', methods=['GET','POST'])
def edit_task(id):
    current_user_id = session.get('user_id')
    
    if not current_user_id:
        flash('Please login to edit tasks', 'error')
        return redirect(url_for('auth.login'))
    
    task = Task.query.filter_by(id=id, user_id=current_user_id).first_or_404()
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.status = form.status.data
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('task.index'))
    return render_template('edit_task.html', form=form, task=task, current_user_id=current_user_id)

@task_bp.route('/delete/<int:id>')
def delete_task_html(id):
    current_user_id = session.get('user_id')
    
    if not current_user_id:
        flash('Please login to delete tasks', 'error')
        return redirect(url_for('auth.login'))
    
    task = Task.query.filter_by(id=id, user_id=current_user_id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'info')
    return redirect(url_for('task.index'))

# Simple test route
@task_bp.route('/test')
def test():
    return "App is working!"