from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from flask import Flask, abort
#from extensions import login_managerr
from sqlalchemy import MetaData
from flask_login import LoginManager
from functools import wraps
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, logout_user, current_user
#from forms import LoginForm


import os
from werkzeug.utils import secure_filename

from flask_socketio import SocketIO, emit, join_room, leave_room

from flask_wtf import FlaskForm #CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Optional
#from models import User

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TaskForm(FlaskForm):
    room_number = StringField('Room Number', validators=[DataRequired()])
    service_type = SelectField(
        'Service Type',
        choices=[('full_clean', 'Full Clean'), ('refresh', 'Refresh'), ('items_only', 'Items Only')],
        validators=[DataRequired()]
    )
    priority = SelectField(
        'Priority Level',
        choices=[('1', '1 (Highest)'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5 (Lowest)')],
        validators=[DataRequired()]
    )
    notes = TextAreaField('Notes', validators=[Optional()])
    assigned_to = SelectField('Assign to Housekeeper', coerce=int, validators=[Optional()])
    submit = SubmitField('Create Task')

    def __init__(self, *args, **kwargs):
        super(TaskForm, self).__init__(*args, **kwargs)
        # Populate the assigned_to choices with housekeeper users
        self.assigned_to.choices = [(user.id, user.name) for user in User.query.filter_by(role='housekeeper').all()]

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = SelectField(
        'Role',
        choices=[('manager', 'Manager'), ('housekeeper', 'Housekeeper')],
        validators=[DataRequired()]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            EqualTo('confirm_password', message='Passwords must match.')
        ]
    )
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower().strip()).first()
        if user:
            raise ValidationError('Email address already registered.')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
#csrf= CSRFProtect()
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#csrf.init_app(app)
socketio = SocketIO(app)

from flask_login import UserMixin
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(256))
    role = db.Column(db.String(50))  # 'manager' or 'housekeeper'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    tasks = db.relationship('Task', backref='assigned_user', lazy='dynamic')
    logs= db.relationship('Log', backref='assigned_user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.email}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(50))
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')  # 'pending', 'in_progress', 'completed'
    priority = db.Column(db.Integer, default=3)  # 1 (High) to 5 (Low)
    service_type = db.Column(db.String(50))  # 'full_clean', 'refresh', 'items_only'
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime)

    photos = db.relationship('Photo', backref='task', lazy='dynamic')

    def __repr__(self):
        return f'<Task Room {self.room_number}>'

class Photo(db.Model):
    __tablename__ = 'photos'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(256))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Photo {self.filename}>'

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer)
    room_number = db.Column(db.String(50))
    service_type = db.Column(db.String(50))
    priority = db.Column(db.Integer)
    notes = db.Column(db.Text)
    status = db.Column(db.String(50))
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Log {self.action}>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'manager':
            return redirect(url_for('manager_dashboard'))
        elif current_user.role == 'housekeeper':
            return redirect(url_for('housekeeper_tasks'))
        else:
            abort(403)  # Forbidden if role is unrecognized

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        if user and user.verify_password(form.password.data):
            login_user(user)
            if user.role == 'manager':
                return redirect(url_for('manager_dashboard'))
            elif user.role == 'housekeeper':
                return redirect(url_for('housekeeper_tasks'))
            else:
                abort(403)  # Handle unknown role
            #next_page = request.args.get('next') or url_for('dashboard')
            #return redirect(next_page)
        else:
            flash('Invalid email or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manager/dashboard')
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        return redirect(url_for('housekeeper_tasks'))
    tasks = Task.query.order_by(Task.priority.asc(), Task.created_at.desc()).all()
    return render_template('manager_dashboard.html', tasks=tasks)

# @app.route('/manager/task/create', methods=['GET', 'POST'])
# @login_required
# def create_task():
#     if current_user.role != 'manager':
#         return redirect(url_for('housekeeper_tasks'))
#     form = TaskForm()
#     if form.validate_on_submit():
#         task = Task(
#             room_number=form.room_number.data,
#             notes=form.notes.data,
#             priority=form.priority.data,
#             service_type=form.service_type.data,
#             assigned_to=form.assigned_to.data  # Assuming a select field of users
#         )
#         db.session.add(task)
#         db.session.commit()
#         socketio.emit('new_task', {'room_number': task.room_number}, broadcast=True)
#         flash('Task created successfully.')
#         return redirect(url_for('manager_dashboard'))
#     return render_template('create_task.html', form=form)

@app.route('/housekeeper/tasks')
@login_required
def housekeeper_tasks():
    if current_user.role != 'housekeeper':
        return redirect(url_for('manager_dashboard'))
    tasks = Task.query.filter_by(assigned_to=current_user.id).order_by(Task.priority.asc()).all()
    return render_template('housekeeper_tasks.html', tasks=tasks)

@app.route('/task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    if current_user.role == 'housekeeper' and task.assigned_to != current_user.id:
        flash('You are not authorized to view this task.')
        return redirect(url_for('housekeeper_tasks'))
    # Handle task updates and photo uploads here

    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            photo = Photo(task_id=task.id, user_id=current_user.id, filename=filename)
            db.session.add(photo)
            task.status = 'completed'
            task.completed_at = datetime.utcnow()
            db.session.commit()
            flash('Task completed and photo uploaded.')
            return redirect(url_for('housekeeper_tasks'))
    return render_template('task_detail.html', task=task)

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Add User')

#with app.app_context():
    #db.create_all()

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_user.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        if user.role == 'manager':
            return redirect(url_for('manager_dashboard'))
        elif user.role == 'housekeeper':
            return redirect(url_for('housekeeper_tasks'))
        #return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User(
            name=form.name.data.strip(),
            email=email,
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/manager/task/create', methods=['GET', 'POST'])
@login_required
@role_required('manager')
def create_task():
    form = TaskForm()
    if form.validate_on_submit():
        # Process form data and create a new task
        task = Task(
            room_number=form.room_number.data.strip(),
            service_type=form.service_type.data,
            priority=int(form.priority.data),
            notes=form.notes.data.strip() if form.notes.data else None,
            assigned_to=form.assigned_to.data if form.assigned_to.data else None,
            status='pending',
            created_at=datetime.utcnow()
        )
        db.session.add(task)
        db.session.commit()
        flash('Task created successfully.', 'success')
        return redirect(url_for('manager_dashboard'))
    return render_template('create_task.html', form=form)

@app.route('/manager/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('manager')
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    form = TaskForm(obj=task)  # Pre-populate form with task data

    # Update the assigned_to choices
    form.assigned_to.choices = [(user.id, user.name) for user in User.query.filter_by(role='housekeeper').all()]

    if form.validate_on_submit():
        task.room_number = form.room_number.data.strip()
        task.service_type = form.service_type.data
        task.priority = int(form.priority.data)
        task.notes = form.notes.data.strip() if form.notes.data else None
        task.assigned_to = form.assigned_to.data if form.assigned_to.data else None
        task.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Task updated successfully.', 'success')
        return redirect(url_for('manager_dashboard'))
    return render_template('edit_task.html', form=form, task=task)

@app.route('/manager/task/<int:task_id>/delete', methods=['GET', 'POST'])
@login_required
@role_required('manager')
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        log = Log(
            task_id=task.id,
            room_number=task.room_number,
            service_type=task.service_type,
            priority=task.priority,
            notes=task.notes,
            status=task.status,
            assigned_to=task.assigned_to,
            created_at=task.created_at,
            updated_at=task.updated_at,
            completed_at=task.completed_at,
            deleted_at=datetime.utcnow()
        )
        db.session.add(log)
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully and logged.', 'success')
        return redirect(url_for('manager_dashboard'))
    return render_template('confirm_delete.html', task=task)

@app.route('/manager/task/<int:task_id>', methods=['GET', 'POST'])
@login_required
@role_required('manager')
def manager_task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    form = TaskForm(obj=task)  # Pre-populate form with task data

    # Update the assigned_to choices
    form.assigned_to.choices = [(user.id, user.name) for user in User.query.filter_by(role='housekeeper').all()]

    if form.validate_on_submit():
        if 'complete_task' in request.form:
            # Manager wants to mark the task as completed
            task.status = 'completed'
            task.completed_at = datetime.utcnow()
            db.session.commit()
            flash('Task marked as completed.', 'success')
            return redirect(url_for('manager_task_detail', task_id=task.id))
        else:
            
            
        # Update the task with form data
            task.room_number = form.room_number.data.strip()
            task.service_type = form.service_type.data
            task.priority = int(form.priority.data)
            task.notes = form.notes.data.strip() if form.notes.data else None
            task.assigned_to = form.assigned_to.data if form.assigned_to.data else None
            task.updated_at = datetime.utcnow()
            db.session.commit()
            flash('Task updated successfully.', 'success')
            return redirect(url_for('manager_task_detail', task_id=task.id))
    return render_template('manager_task_detail.html', task=task, form=form)

@app.route('/manager/tasks/delete_completed', methods=['GET', 'POST'])
@login_required
@role_required('manager')
def confirm_delete_completed_tasks():
    if request.method == 'POST':
        completed_tasks = Task.query.filter_by(status='completed').all()
        num_deleted = 0
        
        for task in completed_tasks:
            # Log task info before deletion
            log = Log(
                task_id=task.id,
                room_number=task.room_number,
                service_type=task.service_type,
                priority=task.priority,
                notes=task.notes,
                status=task.status,
                assigned_to=task.assigned_to,
                created_at=task.created_at,
                updated_at=task.updated_at,
                completed_at=task.completed_at,
                deleted_at=datetime.utcnow()
            )
            db.session.add(log)
            db.session.delete(task)
            num_deleted += 1
        # Perform deletion of all completed tasks
        #num_deleted = Task.query.filter_by(status='completed').delete()
        db.session.commit()
        flash(f'Deleted {num_deleted} completed task(s).', 'success')
        return redirect(url_for('manager_dashboard'))
    return render_template('confirm_delete_completed_tasks.html')

# app.py

@app.route('/manager/task/<int:task_id>/complete', methods=['POST'])
@login_required
@role_required('manager')
def mark_task_completed(task_id):
    task = Task.query.get_or_404(task_id)
    if task.status != 'completed':
        task.status = 'completed'
        task.completed_at = datetime.utcnow()
        db.session.commit()
        flash(f'Task {task.id} marked as completed.', 'success')
    else:
        flash(f'Task {task.id} is already completed.', 'info')
    return redirect(url_for('manager_dashboard'))

@app.route('/manager/logs')
@login_required
@role_required('manager')
def view_logs():
    logs = Log.query.order_by(Log.deleted_at.desc()).all()
    return render_template('view_logs.html', logs=logs)

# Run the app with socketio
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)