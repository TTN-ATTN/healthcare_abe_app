# cloud_storage/server/app.py
from flask import Flask
from user_api import user_api
from patient_api import patient_api
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config['SESSION_TYPE'] = 'filesystem'

app.register_blueprint(user_api)
app.register_blueprint(patient_api)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)