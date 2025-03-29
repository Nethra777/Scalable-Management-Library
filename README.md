from flask import Flask, request, jsonify, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging, datetime

app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY='supersecretkey'
)

db, bcrypt, jwt = SQLAlchemy(app), Bcrypt(app), JWTManager(app)
migrate, limiter = Migrate(app, db), Limiter(get_remote_address, app=app, default_limits=["10 per minute"])
CORS(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class User(db.Model):
    id, username, email, password, role = db.Column(db.Integer, primary_key=True), db.Column(db.String(50), unique=True, nullable=False), db.Column(db.String(100), unique=True, nullable=False), db.Column(db.String(255), nullable=False), db.Column(db.String(10), default='user')

user_bp, blacklist = Blueprint('user', __name__), set()

@user_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'User exists'}), 409
    new_user = User(username=data['username'], email=data['email'], password=bcrypt.generate_password_hash(data['password']).decode(), role=data.get('role', 'user'))
    db.session.add(new_user), db.session.commit()
    return jsonify({'message': 'User registered'}), 201

@user_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data, user = request.get_json(), User.query.filter_by(username=data.get('username')).first()
    if not user or not bcrypt.check_password_hash(user.password, data.get('password')):
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': create_access_token(identity={'username': user.username, 'role': user.role}, expires_delta=datetime.timedelta(hours=1))}), 200

@user_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    blacklist.add(get_jwt_identity())
    return jsonify({'message': 'Logged out'}), 200

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklist

@user_bp.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user = User.query.filter_by(username=get_jwt_identity()['username']).first()
    if not user: return jsonify({'error': 'User not found'}), 404
    data = request.get_json()
    if 'username' in data: user.username = data['username']
    if 'email' in data: user.email = data['email']
    if 'password' in data: user.password = bcrypt.generate_password_hash(data['password']).decode()
    db.session.commit()
    return jsonify({'message': 'Profile updated'}), 200

@user_bp.route('/update_role/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_role(user_id):
    if get_jwt_identity()['role'] != 'admin': return jsonify({'error': 'Access denied'}), 403
    user = User.query.get(user_id)
    if not user: return jsonify({'error': 'User not found'}), 404
    user.role = request.get_json().get('role', user.role)
    db.session.commit()
    return jsonify({'message': 'User role updated'}), 200

app.register_blueprint(user_bp, url_prefix='/users')

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True)

