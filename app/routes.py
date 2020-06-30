from app import app, bcrypt, db
from flask import request, jsonify
from app.src.models import User
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
import json

def get_current_user():
    user_data = get_jwt_identity()
    return User.query.get(user_data['id'])

@app.route('/')
def home():
    return "Hello World"

@app.route('/register', methods=['POST'])
def register():
    data = request.json

    username = User.query.filter_by(username=data["username"]).first()
    if username:
        return jsonify({"error": "username taken"})

    email = User.query.filter_by(email=data["email"]).first()
    if email:
        return jsonify({"error": "email taken"})

    hashed_pass = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    newUser = User(username=data["username"], email=data["email"], password=hashed_pass)

    db.session.add(newUser)
    db.session.commit()
    return jsonify(newUser.toJSON())

@app.route('/login', methods=['POST'])
def login():
    data = request.json

    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=user.toJSON())
        return jsonify(access_token=access_token), 200

    return jsonify({"error": "Incorrect Username or Password"})

@app.route('/logout')
@jwt_required
def logout():
    return jsonify({"ok": "logged out"})

@app.route('/test')
@jwt_required
def test():
    current_user = get_current_user()
    return jsonify(logged_in_as=current_user.toJSON()), 200
