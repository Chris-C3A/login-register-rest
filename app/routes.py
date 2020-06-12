from app import app, bcrypt, db
from flask import request
from app.src.models import User
from flask_login import login_user, current_user, logout_user, login_required
import json
import re

@app.route('/')
def home():
    return "Hello World"

@app.route('/register', methods=['POST'])
def register():
    data = request.json

    username = User.query.filter_by(username=data["username"]).first()
    if username:
        return json.dumps({"error": "username taken"})

    email = User.query.filter_by(email=data["email"]).first()
    if email:
        return json.dumps({"error": "email taken"})

    hashed_pass = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
    newUser = User(username=data["username"], email=data["email"], password=hashed_pass)

    db.session.add(newUser)
    db.session.commit()
    return json.dumps({
        "id": newUser.id,
        "username": newUser.username,
        "email": newUser.email
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.json

    user = User.query.filter_by(username=data["username"]).first()
    if user and bcrypt.check_password_hash(user.password, data["password"]):
        login_user(user)
        return json.dumps({
            "username": user.username,
            "email": user.email
        })
    return json.dumps({"error": "Incorrect Username or Password"})

@app.route('/logout')
def logout():
    logout_user()
    return json.dumps({"ok": "logged out"})

@app.route('/test')
@login_required
def test():
    return f"hello there {current_user.username}"
