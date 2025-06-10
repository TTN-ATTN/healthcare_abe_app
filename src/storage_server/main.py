from flask import Flask
from admin_api import admin_api
from hospital_api import hospital_api
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config['SESSION_TYPE'] = 'filesystem'

app.register_blueprint(admin_api)
app.register_blueprint(hospital_api)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False)