# storage_server/patient_api.py
from flask import Blueprint, request, jsonify
from auth import check_token, check_permission
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from ast import literal_eval
from bson import ObjectId
import datetime

patient_api = Blueprint('patient_api', __name__)

def DBConnect():
    """Connect to MongoDB database"""
    client = MongoClient("mongodb://localhost:27017/")
    try:
        client.server_info()
    except ServerSelectionTimeoutError:
        client = MongoClient("mongodb://localhost:27017/")
    
    db = client["hospital"]
    return db

# Initialize database connection
db = DBConnect()

# Access control policies aligned with authority server attributes
VIEW_POLICIES = {
    'health_record': ['doctor', 'nurse', 'patient'],
    'medicine_record': ['doctor', 'pharmacist', 'patient'],
    'financial_record': ['accountant', 'admin'],
    'research_record': ['doctor', 'researcher'],
    'emergency_record': ['doctor', 'nurse', 'emergency'],
}

UPDATE_POLICIES = {
    'health_record': ['doctor', 'nurse'],
    'medicine_record': ['doctor', 'pharmacist'],
    'financial_record': ['accountant', 'admin'],
    'research_record': ['researcher', 'doctor'],
    'emergency_record': ['doctor', 'nurse'],
}

DELETE_POLICIES = {
    'health_record': ['doctor', 'admin'],
    'medicine_record': ['doctor', 'admin'],
    'financial_record': ['accountant', 'admin'],
    'research_record': ['admin'],
    'emergency_record': ['admin'],
}

def check_record_access(record_type, action='view'):
    """
    Check if user has access to specific record type and action
    """
    def decorator(f):
        def decorated_function(*args, **kwargs):  # Changed from 'decorated' to 'decorated_function'
            current_user = kwargs.get('current_user')
            if not current_user:
                return jsonify({'error': 'User information not found'}), 401
            
            user_attributes = current_user.get("expanded_attributes", [])

            # Determine required attributes based on action
            if action == 'view':
                required_attrs = VIEW_POLICIES.get(record_type, [])
            elif action == 'update':
                required_attrs = UPDATE_POLICIES.get(record_type, [])
            elif action == 'delete':
                required_attrs = DELETE_POLICIES.get(record_type, [])
            else:
                return jsonify({'error': 'Invalid action'}), 400
            
            # Check if user has required attributes
            has_access = any(attr in user_attributes for attr in required_attrs)
            
            if not has_access:
                return jsonify({
                    'error': 'Access denied!',
                    'message': f'Insufficient privileges for {action} on {record_type}',
                    'required_attributes': required_attrs,
                    'user_attributes': user_attributes
                }), 403
            
            return f(*args, **kwargs)
        
        decorated_function.__name__ = f.__name__ + f'_{record_type}_{action}'
        return decorated_function
    return decorator

@patient_api.route('/health_records', methods=['GET'])
@check_token
@check_record_access('health_record', 'view')
def get_health_records(current_user):
    """Get health records based on user privileges"""
    try:
        collection = db['health_records']
        user_attributes = current_user.get('attributes', [])
        
        # Patients can only see their own records
        if 'patient' in user_attributes and 'doctor' not in user_attributes and 'nurse' not in user_attributes:
            query = {'patient_id': current_user['user_id']}
        else:
            # Doctors and nurses can see all records
            query = {}
        
        records = list(collection.find(query))
        
        # Convert ObjectId to string
        for record in records:
            if '_id' in record:
                record['_id'] = str(record['_id'])
        
        return jsonify({
            'records': records,
            'count': len(records),
            'accessed_by': current_user['user_id'],
            'user_type': user_attributes
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve health records', 'message': str(e)}), 500

@patient_api.route('/health_records', methods=['POST'])
@check_token
@check_record_access('health_record', 'update')
def create_health_record(current_user):
    """Create new health record"""
    try:
        data = request.json
        collection = db['health_records']
        
        required_fields = ['patient_id', 'diagnosis', 'treatment']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields', 'required': required_fields}), 400
        
        # Create new health record
        new_record = {
            'patient_id': data['patient_id'],
            'diagnosis': data['diagnosis'],
            'treatment': data['treatment'],
            'notes': data.get('notes', ''),
            'created_by': current_user['user_id'],
            'created_at': datetime.datetime.utcnow(),
            'record_type': 'health_record'
        }
        
        result = collection.insert_one(new_record)
        new_record['_id'] = str(result.inserted_id)
        
        return jsonify({
            'message': 'Health record created successfully',
            'record': new_record
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to create health record', 'message': str(e)}), 500

@patient_api.route('/medicine_records', methods=['GET'])
@check_token
@check_record_access('medicine_record', 'view')
def get_medicine_records(current_user):
    """Get medicine records"""
    try:
        collection = db['medicine_records']
        user_attributes = current_user.get('attributes', [])
        
        # Patients can only see their own records
        if 'patient' in user_attributes and not any(attr in ['pharmacist'] for attr in user_attributes):
            query = {'patient_id': current_user['user_id']}
        else:
            query = {}
        
        records = list(collection.find(query))
        
        # Convert ObjectId to string
        for record in records:
            if '_id' in record:
                record['_id'] = str(record['_id'])
        
        return jsonify({
            'records': records,
            'count': len(records),
            'accessed_by': current_user['user_id']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve medicine records', 'message': str(e)}), 500

@patient_api.route('/research_records', methods=['GET'])
@check_token
@check_record_access('research_record', 'view')
def get_research_records(current_user):
    """Get research records - researchers only"""
    try:
        collection = db['research_records']
        
        records = list(collection.find({}))
        
        # Convert ObjectId to string and anonymize patient data for research
        for record in records:
            if '_id' in record:
                record['_id'] = str(record['_id'])
            # Anonymize patient ID for research purposes
            if 'patient_id' in record:
                record['anonymized_patient_id'] = hash(record['patient_id']) % 10000
                del record['patient_id']
        
        return jsonify({
            'records': records,
            'count': len(records),
            'accessed_by': current_user['user_id'],
            'note': 'Patient data has been anonymized for research purposes'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve research records', 'message': str(e)}), 500

@patient_api.route('/emergency_access', methods=['POST'])
@check_token
@check_permission(['doctor', 'nurse', 'emergency'])
def emergency_access(current_user):
    """Emergency access to patient records"""
    try:
        data = request.json
        patient_id = data.get('patient_id')
        
        if not patient_id:
            return jsonify({'error': 'Patient ID is required'}), 400
        
        # Log emergency access
        emergency_log = db['emergency_access_log']
        log_entry = {
            'patient_id': patient_id,
            'accessed_by': current_user['user_id'],
            'access_time': datetime.datetime.utcnow(),
            'user_attributes': current_user['attributes'],
            'reason': data.get('reason', 'Emergency access')
        }
        emergency_log.insert_one(log_entry)
        
        # Get all patient records
        health_records = list(db['health_records'].find({'patient_id': patient_id}))
        medicine_records = list(db['medicine_records'].find({'patient_id': patient_id}))
        
        # Convert ObjectId to string
        for record in health_records + medicine_records:
            if '_id' in record:
                record['_id'] = str(record['_id'])
        
        return jsonify({
            'message': 'Emergency access granted',
            'patient_id': patient_id,
            'health_records': health_records,
            'medicine_records': medicine_records,
            'access_logged': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Emergency access failed', 'message': str(e)}), 500

@patient_api.route('/create_sample_data', methods=['POST'])
@check_token
@check_permission(['admin'])
def create_sample_data(current_user):
    """Create sample patient data for testing"""
    try:
        # Sample health records
        health_records = [
            {
                'patient_id': '3001',
                'diagnosis': 'Hypertension',
                'treatment': 'ACE inhibitor medication',
                'notes': 'Monitor blood pressure weekly',
                'created_by': '1001',
                'created_at': datetime.datetime.utcnow(),
                'record_type': 'health_record'
            },
            {
                'patient_id': '3001',
                'diagnosis': 'Type 2 Diabetes',
                'treatment': 'Metformin 500mg twice daily',
                'notes': 'Check blood glucose regularly',
                'created_by': '1001',
                'created_at': datetime.datetime.utcnow(),
                'record_type': 'health_record'
            }
        ]
        
        # Sample medicine records
        medicine_records = [
            {
                'patient_id': '3001',
                'medication': 'Lisinopril 10mg',
                'dosage': 'Once daily',
                'prescribed_by': '1001',
                'prescribed_at': datetime.datetime.utcnow(),
                'record_type': 'medicine_record'
            }
        ]
        
        # Insert sample data
        db['health_records'].insert_many(health_records)
        db['medicine_records'].insert_many(medicine_records)
        
        return jsonify({
            'message': 'Sample data created successfully',
            'health_records': len(health_records),
            'medicine_records': len(medicine_records)
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Failed to create sample data', 'message': str(e)}), 500
