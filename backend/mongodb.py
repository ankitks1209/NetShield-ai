"""Persistence helpers. Storage failures propagate instead of looking like empty data."""
from datetime import datetime, timezone
import hashlib

from bson import ObjectId
from pymongo import MongoClient
from config import settings

client = MongoClient(settings.mongo_url, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000, tz_aware=True, connect=False)
mongo_db = client['netshield_ai']
packet_logs = mongo_db['packet_logs']
incident_logs = mongo_db['incident_logs']
sensor_offsets = mongo_db['sensor_offsets']

def utcnow():
    return datetime.now(timezone.utc)

def serialize(doc):
    data = dict(doc)
    data['id'] = str(data.pop('_id'))
    for key, value in tuple(data.items()):
        if isinstance(value, datetime):
            data[key] = value.replace(tzinfo=value.tzinfo or timezone.utc).isoformat()
    data['time'] = data.pop('time_formatted', data.get('timestamp', ''))
    data['assignee'] = data.pop('assigned_to', data.get('assignee', 'Unassigned'))
    return data

def ensure_indexes():
    packet_logs.create_index([('timestamp', -1)])
    incident_logs.create_index([('timestamp', -1)])
    incident_logs.create_index([('status', 1), ('timestamp', -1)])
    incident_logs.create_index([('source', 1), ('timestamp', -1)])
    incident_logs.create_index([('notification_status', 1), ('notification_next_attempt', 1)])

def log_packet_to_db(packet_data):
    event_id = packet_data['event_id']
    entry = {
        '_id': event_id, 'timestamp': utcnow(), 'packet_features': packet_data,
        'analyzed': packet_data.get('analysis_status') == 'analyzed',
        'is_anomaly': packet_data.get('is_anomaly'),
        'simulated': packet_data.get('simulated', False),
        'source_mode': packet_data.get('source_mode', 'api'),
        'dataset': packet_data.get('dataset_used', packet_data.get('active_dataset')),
        'sensor_id': packet_data.get('sensor_id'),
        'event_time': packet_data.get('event_time'),
    }
    packet_logs.update_one({'_id': event_id}, {'$setOnInsert': entry}, upsert=True)

def log_anomaly_to_db(threat_data):
    from notifications import initial_status
    # Stable incident ID makes retries idempotent across process restarts.
    event_id = threat_data['event_id']
    incident_id = ObjectId(hashlib.sha256(event_id.encode()).hexdigest()[:24])
    now = utcnow()
    entry = {
        **threat_data, '_id': incident_id, 'timestamp': now,
        'status': 'Open', 'assignee': 'Unassigned', 'investigation_notes': [],
        'notification_status': initial_status(threat_data),
        'notification_attempts': 0, 'notification_next_attempt': now,
    }
    incident_logs.update_one({'_id': incident_id}, {'$setOnInsert': entry}, upsert=True)
    return serialize(incident_logs.find_one({'_id': incident_id}))

def get_recent_anomalies(limit=50):
    return [serialize(doc) for doc in incident_logs.find().sort('timestamp', -1).limit(limit)]

def get_sensor_checkpoint(key):
    record = sensor_offsets.find_one({'_id': key})
    return record.get('cursor') if record else None

def save_sensor_checkpoint(key, cursor):
    sensor_offsets.update_one({'_id': key}, {'$set': {'cursor': cursor, 'updated_at': utcnow()}}, upsert=True)
