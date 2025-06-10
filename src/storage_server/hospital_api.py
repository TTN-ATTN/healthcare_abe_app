from flask import Blueprint, request, jsonify
from abac import checker
from auth import check_token
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from ast import literal_eval

hospital_api = Blueprint('hospital_api', __name__)

def DBConnect():
    client = MongoClient("mongodb://localhost:27017/")
    try:
        client.server_info()
    except ServerSelectionTimeoutError:
        client = MongoClient("mongodb://localhost:27017/")
    db = client["hospital"]
    
    return db

db = DBConnect()

VIEW_POLICIES = {
    'health_record': ['doctor', 'nurse', 'patient'],
    'medicine_record': ['doctor', 'pharmacist', 'patient'],
    'financial_record': ['accountant'],
    'research_record': ['doctor', 'researcher'],
}

UPDATE_POLICIES = {
    'health_record': ['doctor', 'nurse'],
    'medicine_record': ['doctor', 'pharmacist'],
    'financial_record': ['accountant'],
    'research_record': ['doctor', 'researcher'],
}

@hospital_api.route("/api/search_record", methods=["POST"])
@check_token
def searchRecord(user):
    data = request.json

    uid = data.get("uid", "")
    collection_name = data.get("collection_name", "")
    patient_name = data.get("patient_name", "")

    user_attr = literal_eval(user['attribute'])
    if collection_name in UPDATE_POLICIES:
        POLICY = UPDATE_POLICIES[collection_name]
        if not checker(user_attr, POLICY):
            return jsonify({"error": "You don't have permission to view this"}), 404
    else:
        return jsonify({"error": "Invalid collection name"}), 400
      
    query_criteria = {}
    if uid != "":
        query_criteria["uid"] = uid
    if patient_name != "":
        query_criteria["patient_name"] = {"$regex": f".*{patient_name}.*"}
    result = db[collection_name].find(query_criteria, {"_id": 0, "patient_name": 1, "uid": 1})
    
    return jsonify(list(result)), 200


@hospital_api.route('/api/view_patient_record', methods=['POST'])
@check_token
def viewRecord(user):
    data = request.json

    collection_name = data.get('collection_name', '')
    uid = data.get('uid', '')

    user_attr = literal_eval(user['attribute'])
    if collection_name in VIEW_POLICIES:
        POLICY = VIEW_POLICIES[collection_name]
        if not checker(user_attr, POLICY):
            return jsonify({"error": "You don't have permission to view this"}), 404
    else:
        return jsonify({"error": "Invalid collection name"}), 400
    
    query_criteria = {}
    if uid != "":
        query_criteria["uid"] = uid
    collection = db[collection_name]
    patient_record = collection.find(query_criteria, {"_id": 0})
    if not patient_record:
        return jsonify({"error": "Patient record not found"}), 404

    return jsonify({"message": "Record retrieved successfully", "patient_data": list(patient_record)}), 200


@hospital_api.route('/api/upload_patient_record', methods=['POST'])
@check_token
def uploadPatient(user):
    data = request.json
    
    collection_name = data.get('collection_name')
    patient_data = data.get('patient_data', {})

    user_attr = literal_eval(user['attribute'])
    if collection_name in UPDATE_POLICIES:
        POLICY = UPDATE_POLICIES[collection_name]
        if not checker(user_attr, POLICY):
            return jsonify({"error": "You don't have permission to upload this"}), 404
    else:
        return jsonify({"error": "Invalid collection name"}), 400


    collection = db[collection_name]
    patient_id = patient_data.get('uid')
    existing_record = collection.find_one({'uid': patient_id})
    if existing_record is None:
        result = collection.insert_one(patient_data)
        return jsonify({"message": "Record uploaded successfully", "inserted_id": patient_id}), 200
    else:
        return jsonify({"error": "Record with the provided UID already exists"}), 409


@hospital_api.route('/api/update_patient_record', methods=['POST'])
@check_token
def updateRecord(user):
    data = request.json

    collection_name = data.get('collection_name')
    updated_data = data.get('updated_data', {})
    uid = updated_data.get('uid')

    user_attr = literal_eval(user['attribute'])
    if collection_name in UPDATE_POLICIES:
        POLICY = UPDATE_POLICIES[collection_name]
        if not checker(user_attr, POLICY):
            return jsonify({"error": "You don't have permission to update this"}), 404
    else:
        return jsonify({"error": "Invalid collection name"}), 400

    collection = db[collection_name]
    existing_record = collection.find_one({"uid": uid})
    collection = db[collection_name]
    if not existing_record:
        return jsonify({"error": "Patient record not found"}), 404
    collection.update_one({"uid": uid}, {"$set": updated_data})

    return jsonify({"message": "Record updated successfully"}), 200