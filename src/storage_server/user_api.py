# storage_server/user_api.py
from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from auth import check_token, check_permission
import hashlib
from bson import ObjectId
import json

user_api = Blueprint('user_api', __name__)

def DBConnect():
    """Connect to MongoDB database"""
    client = MongoClient("mongodb://localhost:27017/")
    try:
        client.server_info()
    except ServerSelectionTimeoutError:
        client = MongoClient("mongodb://localhost:27017/")
    
    db = client["storage_server"]  # Different DB name from authority
    collection = db['user_data']
    
    # Create unique index on username
    try:
        collection.create_index([('username', 1)], unique=True)
    except:
        pass
    
    # Create admin user if doesn't exist
    admin_user = collection.find_one({'username': 'admin'})
    if admin_user is None:
        admin_user = {
            'user_id': 1,
            'username': 'admin',
            'hash_password': hashlib.sha256('admin123'.encode()).hexdigest(),
            'attributes': ['admin', 'super_user'],
            'role': 'administrator'
        }
        collection.insert_one(admin_user)
    
    return db

# Initialize database connection
db = DBConnect()
users_collection = db['user_data']

@user_api.route('/users', methods=['GET'])
@check_token
@check_permission(['admin', 'doctor'])
def get_all_users(current_user):
    """Get all users - requires admin or doctor privileges"""
    try:
        users = list(users_collection.find({}, {'hash_password': 0}))  # Exclude passwords
        
        # Convert ObjectId to string for JSON serialization
        for user in users:
            if '_id' in user:
                user['_id'] = str(user['_id'])
        
        return jsonify({
            'users': users,
            'count': len(users),
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
        
        if '_id' in user:
            user['_id'] = str(user['_id'])
        
        return jsonify({'user': user}), 200
        
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
        new_user['_id'] = str(result.inserted_id)
        del new_user['hash_password']  # Don't return password
        
        return jsonify({'message': 'User created successfully', 'user': new_user}), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to create user', 'message': str(e)}), 500

@user_api.route('/user/<user_id>', methods=['PUT'])
@check_token
def update_user(user_id, current_user):
    """Update user information"""
    try:
        data = request.json
        
        # Users can update their own profile, admins can update any profile
        if current_user['user_id'] != user_id and 'admin' not in current_user['attributes']:
            return jsonify({'error': 'Access denied'}), 403
        
        # Prepare update data
        update_data = {}
        allowed_fields = ['attributes', 'role'] if 'admin' in current_user['attributes'] else ['username']
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        # Handle password update separately
        if 'password' in data:
            update_data['hash_password'] = hashlib.sha256(data['password'].encode()).hexdigest()
        
        if not update_data:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        result = users_collection.update_one(
            {'user_id': user_id},
            {'$set': update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': 'User updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to update user', 'message': str(e)}), 500

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

@user_api.route('/profile', methods=['GET'])
@check_token
def get_profile(current_user):
    """Get current user's profile"""
    try:
        user = users_collection.find_one({'user_id': current_user['user_id']}, {'hash_password': 0})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if '_id' in user:
            user['_id'] = str(user['_id'])
        
        return jsonify({'profile': user, 'token_info': current_user}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve profile', 'message': str(e)}), 500

@user_api.route('/sync_users', methods=['POST'])
@check_token
@check_permission(['admin'])
def sync_users_from_authority(current_user):
    """Sync users from authority server to storage server"""
    try:
        import requests
        
        # Get users from authority server (this would need to be implemented there)
        # For now, we'll create sample users that match the authority server
        authority_users = [
            {
                "username": "doctor1",
                "user_id": "1001",
                "attributes": ["doctor", "cardiology"]
            },
            {
                "username": "nurse1",
                "user_id": "2001",
                "attributes": ["nurse", "emergency"]
            },
            {
                "username": "patient1",
                "user_id": "3001",
                "attributes": ["patient"]
            },
            {
                "username": "researcher1",
                "user_id": "4001",
                "attributes": ["researcher", "cardiology"]
            }
        ]
        
        synced_count = 0
        for user_data in authority_users:
            # Check if user exists
            existing_user = users_collection.find_one({'user_id': user_data['user_id']})
            
            if not existing_user:
                # Create user in storage server
                new_user = {
                    'user_id': user_data['user_id'],
                    'username': user_data['username'],
                    'hash_password': hashlib.sha256('password123'.encode()).hexdigest(),  # Default password
                    'attributes': user_data['attributes'],
                    'role': 'user',
                    'synced_from_authority': True
                }
                users_collection.insert_one(new_user)
                synced_count += 1
        
        return jsonify({
            'message': f'Synced {synced_count} users from authority server',
            'synced_by': current_user['user_id']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to sync users', 'message': str(e)}), 500
