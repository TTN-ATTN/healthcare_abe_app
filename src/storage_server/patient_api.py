# storage_server/patient_api.py
from flask import Blueprint, request, jsonify
from auth import check_token, check_permission
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from ast import literal_eval
from bson import ObjectId
from abac import checker
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

db = DBConnect()


def serialize_record(record):
    """Helper function to serialize record data for JSON response"""
    if record is None:
        return None
    
    # Remove MongoDB's default _id field since we use our own IDs
    if '_id' in record:
        del record['_id']
    
    return record

POLICIES = {
    'view': {
        'health_record': "doctor or nurse or patient",
        'medicine_record': "doctor or pharmacist or patient",
        'financial_record': "accountant",
        'research_record': "doctor or researcher",
    },
    'update': {
        'health_record': "doctor or nurse",
        'medicine_record': "doctor or pharmacist",
        'financial_record': "accountant",
        'research_record': "researcher or doctor",
    }
}

def check_record_access(record_type, action='view'):
    """
    Check if user has access to specific record type and action using ABAC
    """
    def decorator(f):
        def decorated_function(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                return jsonify({'error': 'User information not found'}), 401
            
            user_attributes = current_user.get("attributes", [])
            
            # Get the appropriate policy for the action and record type
            policy = POLICIES.get(action, {}).get(record_type)
            if not policy:
                return jsonify({'error': 'Invalid policy configuration'}), 500
            
            # Use ABAC checker to verify access
            has_access = checker(user_attributes, policy.split(' or '))
            
            if not has_access:
                return jsonify({
                    'error': 'Access denied!',
                    'message': f'Insufficient privileges for {action} on {record_type}',
                    'required_policy': policy,
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
        elif 'doctor' in user_attributes or 'nurse' in user_attributes:
            if 'patient_name' in request.args:
                query = {'patient_name': request.args.get('patient_name')}
            elif 'patient_id' in request.args:
                query = {'patient_id': request.args.get('patient_id')}
            elif 'patient_name' and 'patient_id' in request.args:
                query = {
                    'patient_name': request.args.get('patient_name'),
                    'patient_id': request.args.get('patient_id')
                }
            else:
                query = {}
        
        records = list(collection.find(query))
        
        # Serialize records for JSON response
        serialized_records = [serialize_record(record) for record in records]
        
        return jsonify({
            'records': serialized_records,
            'count': len(serialized_records),
            'accessed_by': current_user['user_id'],
            'attributes': user_attributes
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
        
        # Create new health record with unique ID
        import uuid
        new_record = {
            'record_id': str(uuid.uuid4()),  # Generate unique record ID
            'patient_id': data['patient_id'],
            'patient_name': data['patient_name'],
            'diagnosis': data['diagnosis'],
            'treatment': data['treatment'],
            'notes': data.get('notes', ''),
            'created_by': current_user['user_id'],
            'created_at': datetime.datetime.utcnow(),
            'record_type': 'health_record'
        }
        
        result = collection.insert_one(new_record)
        
        # Prepare response record (remove MongoDB _id)
        response_record = new_record.copy()
        if '_id' in response_record:
            del response_record['_id']
        
        return jsonify({
            'message': 'Health record created successfully',
            'record': response_record
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
        
        # Serialize records for JSON response
        serialized_records = [serialize_record(record) for record in records]
        
        return jsonify({
            'records': serialized_records,
            'count': len(serialized_records),
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
        
        # Process records and anonymize patient data for research
        processed_records = []
        for record in records:
            # Serialize record
            serialized_record = serialize_record(record)
            
            # Anonymize patient ID for research purposes
            if 'patient_id' in serialized_record:
                serialized_record['anonymized_patient_id'] = hash(serialized_record['patient_id']) % 10000
                del serialized_record['patient_id']
            
            processed_records.append(serialized_record)
        
        return jsonify({
            'records': processed_records,
            'count': len(processed_records),
            'accessed_by': current_user['user_id'],
            'note': 'Patient data has been anonymized for research purposes'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to retrieve research records', 'message': str(e)}), 500

@patient_api.route('/create_sample_data', methods=['POST'])
@check_token
@check_permission(['admin'])
def create_sample_data(current_user):
    """Create sample patient data for testing"""
    try:
        # Sample health records
        import uuid
        health_records = [
            {
                'record_id': str(uuid.uuid4()),
                'patient_id': '3001',
                'patient_name': 'Josh',
                'diagnosis': 'Hypertension',
                'treatment': 'ACE inhibitor medication',
                'notes': 'Monitor blood pressure weekly',
                'created_by': '1001',
                'created_at': datetime.datetime.utcnow(),
                'record_type': 'health_record'
            },
            {
                'record_id': str(uuid.uuid4()),
                'patient_id': '3001',
                'patient_name': 'John',
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
                'record_id': str(uuid.uuid4()),
                'patient_id': '3001',
                'patient_name': 'Dave',
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