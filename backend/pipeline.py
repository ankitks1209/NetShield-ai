"""Persist canonical detection results before publishing them to viewers."""
import logging
from uuid import uuid4

from detection import detector, InvalidFeatures, ModelUnavailable
from mongodb import log_packet_to_db, log_anomaly_to_db

logger = logging.getLogger(__name__)

def process_detection(dataset, features, source='Replay dataset', event_id=None, source_mode='replay', simulated=False):
    result = detector.predict(dataset, features)
    return persist_detection(result, source, event_id, source_mode, simulated)

def persist_detection(result, source, event_id=None, source_mode='api', simulated=False):
    result = {**result, 'event_id': event_id or str(uuid4()), 'source_mode': source_mode, 'simulated': simulated}
    if result['is_anomaly']:
        incident = log_anomaly_to_db({
            **result, 'source': source, 'type': result['ai_classification'],
            'description': 'Simulated test incident' if simulated else f'Classification from {result["dataset_used"]}',
        })
        result['incident'] = incident
    log_packet_to_db(result)
    return result

def unknown_result(dataset, error):
    return {
        'analysis_status': 'unavailable', 'active_dataset': dataset,
        'ai_classification': 'UNKNOWN', 'is_anomaly': None, 'confidence': None,
        'error': str(error), 'source_mode': 'replay',
    }
