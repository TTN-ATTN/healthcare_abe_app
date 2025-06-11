# storage_server/main.py
from flask import Flask, jsonify, redirect
from user_api import user_api
from patient_api import patient_api
import os

app = Flask(__name__)

# Configuration
app.secret_key = os.urandom(32)
app.config["SESSION_PERMANENT"] = False
app.config['SESSION_TYPE'] = 'filesystem'

# Register blueprints
app.register_blueprint(user_api, url_prefix='/api')
app.register_blueprint(patient_api, url_prefix='/api')

@app.route('/')
def home():
    return redirect('/health')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'authority_server': 'http://127.0.0.1:5000'
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("Starting Healthcare Storage Server...")
    print("Storage Server starting on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=True)
