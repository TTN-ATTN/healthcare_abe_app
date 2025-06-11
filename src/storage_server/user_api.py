# storage_server/user_api.py
from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from auth import check_token, check_permission
import hashlib
from bson import ObjectId
import json
import requests

user_api = Blueprint('user_api', __name__)

def DBConnect():
    """Connect to MongoDB database"""
    client = MongoClient("mongodb://localhost:27017/")
    try:
        client.server_info()
    except ServerSelectionTimeoutError:
        client = MongoClient("mongodb://localhost:27017/")
    
    client.drop_database("storage_server")  # Clear existing database for fresh start
    db = client["storage_server"]
    collection = db['user_data']
    
    # Create unique index on username
    try:
        collection.create_index([('username', 1)], unique=True)
    except:
        pass
    
    # Create admin user if doesn't exist
    admin_user = collection.find_one({'user_id': '0001'})  # Use string for consistency
    if admin_user is None:
        admin_user = {
            'user_id': '0001',
            'username': 'admin',
            'hash_password': hashlib.sha256('admin123'.encode()).hexdigest(),
            'attribute': ['admin'],
            'role': 'administrator'
        }
        collection.insert_one(admin_user)
    
    return db

# Initialize database connection
db = DBConnect()
users_collection = db['user_data']

def serialize_user(user):
    """Helper function to serialize user data for JSON response"""
    if user is None:
        return None
    
    # Remove MongoDB's default _id field since we use our own user_id
    if '_id' in user:
        del user['_id']
    
    return user


@user_api.route('/get_user_info', method=['POST'])
def get_user_info():
    if request.method == 'POST':
        username = request.form.get('username')
        
        user_info = users_collection.find_one({'username': username})
        
        if user_info:
            response = {
                'user_id': user_info['user_id'],
                'username': user_info['username'],
                'hash_passwd': user_info['hash_password'],
                'attribute': user_info['attribue'],
            }
            return jsonify(response), 200
        else:
            return jsonify({'error': 'User not found'}), 404

@user_api.route('/users', methods=['GET'])
@check_token
@check_permission(['admin'])
def get_all_users(current_user):
    """Get all users - requires admin privileges"""
    try:
        users = list(users_collection.find({}, {'hash_password': 0}))  # Exclude passwords
        
        # Convert ObjectId to string for JSON serialization
        serialized_users = [serialize_user(user) for user in users]
        
        return jsonify({
            'users': serialized_users,
            'count': len(serialized_users),
            'requested_by': current_user['user_id']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve users', 'message': str(e)}), 500

@user_api.route('/user/<user_id>', methods=['GET'])
@check_token
def get_user_by_id(user_id, current_user):
    """Get specific user by ID"""
    try:
        # Users can view their own profile, admins can view any profile
        if current_user['user_id'] != user_id and 'admin' not in current_user['attributes']:
            return jsonify({'error': 'Access denied'}), 403
        
        user = users_collection.find_one({'user_id': user_id}, {'hash_password': 0})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        serialized_user = serialize_user(user)
        
        return jsonify({'user': serialized_user}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve user', 'message': str(e)}), 500

@user_api.route('/user', methods=['POST'])
@check_token
@check_permission(['admin'])
def create_user(current_user):
    """Create new user - admin only"""
    try:
        data = request.json
        
        required_fields = ['username', 'password', 'user_id', 'attributes']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields', 'required': required_fields}), 400
        
        # Check if user already exists
        existing_user = users_collection.find_one({
            '$or': [
                {'username': data['username']},
                {'user_id': data['user_id']}
            ]
        })
        
        if existing_user:
            return jsonify({'error': 'User already exists'}), 409
        
        # Create new user
        new_user = {
            'user_id': data['user_id'],
            'username': data['username'],
            'hash_password': hashlib.sha256(data['password'].encode()).hexdigest(),
            'attributes': data['attributes'],
            'role': data.get('role', 'user'),
            'created_by': current_user['user_id']
        }
        
        result = users_collection.insert_one(new_user)
        
        # Prepare response (exclude password and remove _id)
        response_user = new_user.copy()
        del response_user['hash_password']  # Don't return password
        if '_id' in response_user:
            del response_user['_id']  # Remove MongoDB's _id, we use user_id
        
        return jsonify({'message': 'User created successfully', 'user': response_user}), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to create user', 'message': str(e)}), 500

@user_api.route('/user/<user_id>', methods=['DELETE'])
@check_token
@check_permission(['admin'])
def delete_user(user_id, current_user):
    """Delete user - admin only"""
    try:
        result = users_collection.delete_one({'user_id': user_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to delete user', 'message': str(e)}), 500

@user_api.route('/reset_users', methods=['POST'])
@check_token
@check_permission(['admin'])    
def reset_users(current_user):
    """Reset all users - admin only"""
    try:
        result = users_collection.delete_many({'user_id': {'$ne': '0001'}})
        
        if result.deleted_count == 0:
            return jsonify({'message': 'No users to reset'}), 200
        
        # Recreate the admin user
        admin_user = {
            'user_id': '0001',
            'username': 'admin',
            'hash_password': hashlib.sha256('admin123'.encode()).hexdigest(),
            'attributes': ['admin', 'super_user'],
            'role': 'administrator'
        }
        users_collection.insert_one(admin_user)
        
        return jsonify({'message': f'Users reset successfully, {result.deleted_count - 1} users removed'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to reset users', 'message': str(e)}), 500

