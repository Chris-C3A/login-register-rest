from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

from app.src.config import Config

app = Flask(__name__)

cors = CORS(app)

# config
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = 'supersecretkey'  # Change this!
jwt = JWTManager(app)

from app import routes
