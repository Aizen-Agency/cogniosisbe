from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import os
from datetime import timedelta
import ssl
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy.sql import func
from flask import Blueprint

# Load environment variables
load_dotenv()

# Ensure SSL support
try:
    ssl_context = ssl.create_default_context()
except AttributeError:
    raise ImportError("The 'ssl' module is required to use this application. Make sure your Python installation includes the 'ssl' module.")

# Initialize Flask App
app = Flask(__name__)

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['OAUTH_CREDENTIALS'] = {
    'google': {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
    },
    'meta': {
        'client_id': os.getenv('META_CLIENT_ID'),
        'client_secret': os.getenv('META_CLIENT_SECRET'),
    },
    'apple': {
        'client_id': os.getenv('APPLE_CLIENT_ID'),
        'client_secret': os.getenv('APPLE_CLIENT_SECRET'),
    },
}

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
oauth = OAuth(app)

# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=True)  # Nullable for social logins
    social_id = db.Column(db.String(120), unique=True, nullable=True)
    provider = db.Column(db.String(50), nullable=True)  # e.g., google, meta, apple
    name = db.Column(db.String(120), nullable=True)  # Optional name field

# Define Task Model
class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    duration = db.Column(db.Interval, nullable=False)  # Store as PostgreSQL interval
    date = db.Column(db.DateTime, nullable=False)
    image = db.Column(db.String(500))  # URL or path to image
    duration_completed = db.Column(db.Interval, default=timedelta(0))
    note = db.Column(db.Text)
    is_completed = db.Column(db.Boolean, default=False)
    
    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, onupdate=func.now())

# Define Habit Model
class Habit(db.Model):
    __tablename__ = 'habits'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(50), nullable=False)  # Store time as a string
    days = db.Column(db.ARRAY(db.String), nullable=False)  # Store days as an array of strings
    
    # Foreign key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, server_default=func.now())
    updated_at = db.Column(db.DateTime, onupdate=func.now())

def initialize_db():
    with app.app_context():
        db.create_all()

# OAuth Clients
oauth.register(
    name='google',
    client_id=app.config['OAUTH_CREDENTIALS']['google']['client_id'],
    client_secret=app.config['OAUTH_CREDENTIALS']['google']['client_secret'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email profile'},
)
oauth.register(
    name='meta',
    client_id=app.config['OAUTH_CREDENTIALS']['meta']['client_id'],
    client_secret=app.config['OAUTH_CREDENTIALS']['meta']['client_secret'],
    access_token_url='https://graph.facebook.com/v12.0/oauth/access_token',
    authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
    api_base_url='https://graph.facebook.com/v12.0/',
    client_kwargs={'scope': 'email'},
)
oauth.register(
    name='apple',
    client_id=app.config['OAUTH_CREDENTIALS']['apple']['client_id'],
    client_secret=app.config['OAUTH_CREDENTIALS']['apple']['client_secret'],
    access_token_url='https://appleid.apple.com/auth/token',
    authorize_url='https://appleid.apple.com/auth/authorize',
    client_kwargs={'scope': 'name email'},
)

# Routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')  # Optional name field

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 400

    new_user = User(username=username, email=email, password=password, name=name)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email, password=password).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'name': user.name  # Include name in response
        }
    })
    
@app.route('/email_login', methods=['POST'])
def email_login():
    data = request.json
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Invalid email'}), 401

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'name': user.name  # Include name in response
        }
    })


@app.route('/auth/<provider>', methods=['GET'])
def social_login(provider):
    if provider not in ['google', 'meta', 'apple']:
        return jsonify({'message': 'Unsupported provider'}), 400
    redirect_uri = url_for('authorize', provider=provider, _external=True)
    return oauth.create_client(provider).authorize_redirect(redirect_uri)

@app.route('/authorize/<provider>', methods=['GET'])
def authorize(provider):
    token = oauth.create_client(provider).authorize_access_token()
    user_info = oauth.create_client(provider).get('userinfo').json()
    email = user_info.get('email')
    
    social_id = user_info.get('id')

    user = User.query.filter_by(social_id=social_id, provider=provider).first()
    if not user:
        user = User(email=email, social_id=social_id, provider=provider)
        db.session.add(user)
        db.session.commit()

    access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))
    return jsonify({'access_token': access_token})

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'name': user.name  # Include name in response
        }
    }), 200

tasks = Blueprint('tasks', __name__)

@tasks.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json
    try:
        duration = timedelta(seconds=data['duration_seconds'])
        new_task = Task(
            title=data['title'],
            duration=duration,
            date=datetime.fromisoformat(data['date']),
            image=data.get('image'),
            note=data.get('note'),
            user_id=current_user_id
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        return jsonify({
            'message': 'Task created successfully',
            'task_id': new_task.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@tasks.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = int(get_jwt_identity())
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    
    
    return jsonify([{
        'id': task.id,
        'title': task.title,
        'duration': str(task.duration),
        'date': task.date.isoformat(),
        'image': task.image,
        'duration_completed': str(task.duration_completed),
        'note': task.note,
        'is_completed': task.is_completed
    } for task in tasks]), 200

@tasks.route('/tasks/<int:task_id>', methods=['GET'])
@jwt_required()
def get_task(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify({
        'id': task.id,
        'title': task.title,
        'duration': str(task.duration),
        'date': task.date.isoformat(),
        'image': task.image,
        'duration_completed': str(task.duration_completed),
        'note': task.note,
        'is_completed': task.is_completed
    }), 200
    

@tasks.route('/user/update', methods=['POST'])
@jwt_required()
def update_user():
    current_user_id = get_jwt_identity()
    data = request.json
    
    try:
        user = User.query.filter_by(id=current_user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if 'name' in data:
            user.name = data['name']
        if 'email' in data:
            user.email = data['email']
        
        db.session.commit()
        return jsonify({'message': 'User updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

  
@tasks.route('/get-keys', methods=['GET'])
def get_keys():
    try:
        openai_key = os.getenv('OPENAI_API_KEY')
        hume_api_key = os.getenv('HUME_API_KEY')
        hume_secret_key = os.getenv('HUME_SECRET_KEY')
        hume_config_id = os.getenv('HUME_CONFIG_ID')
        hume_config_id_chat = os.getenv('HUME_CONFIG_ID_CHAT')
        if not openai_key:
            return jsonify({'error': 'OpenAI key not found'}), 404
        return jsonify({'openai_key': openai_key, 'hume_api_key': hume_api_key, 'hume_secret_key': hume_secret_key, 'hume_config_id': hume_config_id, 'hume_config_id_chat': hume_config_id_chat}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@tasks.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    data = request.json
    try:
        if 'title' in data:
            task.title = data['title']
        if 'duration_seconds' in data:
            task.duration = timedelta(seconds=data['duration_seconds'])
        if 'date' in data:
            task.date = datetime.fromisoformat(data['date'])
        if 'image' in data:
            task.image = data['image']
        if 'duration_completed_seconds' in data:
            task.duration_completed = timedelta(seconds=data['duration_completed_seconds'])
        if 'note' in data:
            task.note = data['note']
        if 'is_completed' in data:
            task.is_completed = data['is_completed']
            
        db.session.commit()
        return jsonify({'message': 'Task updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@tasks.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first()
    
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    try:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'message': 'Task deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# Register the tasks Blueprint
app.register_blueprint(tasks)

habits = Blueprint('habits', __name__)

@habits.route('/habits', methods=['POST'])
@jwt_required()
def create_habit():
    print("Creating habit")
    current_user_id = get_jwt_identity()
    print(f"Current user ID: {current_user_id}")
    data = request.json
    print(f"Received data: {data}")
    try:
        new_habit = Habit(
            name=data['name'],
            time=data['time'],
            days=data['days'],
            user_id=current_user_id
        )
        db.session.add(new_habit)
        db.session.commit()
        return jsonify({'message': 'Habit created successfully', 'habit_id': new_habit.id}), 201
    except Exception as e:
        print(f"Error creating habit: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@habits.route('/habits', methods=['GET'])
@jwt_required()
def get_habits():
    current_user_id = get_jwt_identity()
    habits = Habit.query.filter_by(user_id=current_user_id).all()
    return jsonify([{
        'id': habit.id,
        'name': habit.name,
        'time': habit.time,
        'days': habit.days
    } for habit in habits]), 200

@habits.route('/habits/<int:habit_id>', methods=['PUT'])
@jwt_required()
def update_habit(habit_id):
    current_user_id = get_jwt_identity()
    habit = Habit.query.filter_by(id=habit_id, user_id=current_user_id).first()
    if not habit:
        return jsonify({'error': 'Habit not found'}), 404
    
    data = request.json
    try:
        if 'name' in data:
            habit.name = data['name']
        if 'time' in data:
            habit.time = data['time']
        if 'days' in data:
            habit.days = data['days']
        
        db.session.commit()
        return jsonify({'message': 'Habit updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@habits.route('/habits/<int:habit_id>', methods=['DELETE'])
@jwt_required()
def delete_habit(habit_id):
    current_user_id = get_jwt_identity()
    habit = Habit.query.filter_by(id=habit_id, user_id=current_user_id).first()
    if not habit:
        return jsonify({'error': 'Habit not found'}), 404
    
    try:
        db.session.delete(habit)
        db.session.commit()
        return jsonify({'message': 'Habit deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

# Register the habits Blueprint
app.register_blueprint(habits)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    if user.password != old_password:
        return jsonify({'message': 'Old password is incorrect'}), 400

    try:
        user.password = new_password
        db.session.commit()
        return jsonify({'message': 'Password reset successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/delete_account', methods=['DELETE'])
@jwt_required()
def delete_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'Account deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    initialize_db()
    app.run(debug=True) 

