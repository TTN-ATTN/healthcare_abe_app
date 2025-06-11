from flask import Flask
from login_api import login_api
from auth_api import auth_api
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config['SESSION_TYPE'] = 'filesystem'

app.register_blueprint(login_api)
app.register_blueprint(auth_api)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)