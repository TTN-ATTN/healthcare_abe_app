# authority/server/app.py
from flask import Flask, session
import os

from login_api import login_api
from auth_api import auth_api
from gen_keys import gen_keys_api
from process import create_sameple_user

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

app.register_blueprint(login_api)
app.register_blueprint(auth_api)
app.register_blueprint(gen_keys_api)

with app.app_context():
    create_sameple_user()

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)