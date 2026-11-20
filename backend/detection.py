"""One feature contract and inference path for REST and replay."""
import hashlib
import logging
import math
import time
from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd

from config import settings

logger = logging.getLogger(__name__)


class ModelUnavailable(Exception):
    pass


class InvalidFeatures(ValueError):
    pass


@dataclass
class Engine:
    model: object
    encoder: object
    features: list
    version: str


class DetectionService:
    def __init__(self):
        self.engines = {}
        self.load_errors = {}

    def load(self):
        for dataset, model_name, encoder_name in [
            ('cicids2017', 'rf_model_optimized.joblib', 'label_encoder.joblib'),
            ('unsw-nb15', 'xgboost_unsw_model.joblib', 'label_encoder1.joblib'),
        ]:
            try:
                path = settings.model_dir / model_name
                # Only administrator-provisioned, trusted joblib artifacts belong here.
                model = joblib.load(path)
                encoder = joblib.load(settings.model_dir / encoder_name)
                features = list(model.feature_names_in_)
                version = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
                if len(features) != model.n_features_in_:
                    raise ValueError('Inconsistent model feature schema')
                self.engines[dataset] = Engine(model, encoder, features, version)
                self.load_errors.pop(dataset, None)
            except Exception:
                self.engines.pop(dataset, None)
                self.load_errors[dataset] = 'Model artifacts could not be loaded'
                logger.exception('Cannot load %s model', dataset)

    def feature_frame(self, engine, dataset, values):
        if isinstance(values, list):
            if len(values) != len(engine.features):
                raise InvalidFeatures(f'{dataset} requires exactly {len(engine.features)} numeric features')
            frame = pd.DataFrame([values], columns=engine.features)
        else:
            values = {k.strip(): v for k, v in values.items()}
            if {'Label', 'label', 'attack_cat'} & values.keys():
                raise InvalidFeatures('Target labels must not be supplied as model inputs')
            if dataset == 'unsw-nb15' and {'proto', 'service', 'state'} <= values.keys():
                # Compatibility adapter for the existing one-hot legacy artifact.
                # Baselines match the absent first categories in its saved schema.
                # This is NOT a replacement for reproducing its training pipeline.
                transformed = dict(values)
                for category, baseline in [('proto', '3pc'), ('service', '-'), ('state', 'ACC')]:
                    value = str(transformed.pop(category))
                    feature = f'{category}_{value}'
                    if feature not in engine.features and value != baseline:
                        raise InvalidFeatures(f'Unsupported {category} category')
                    for name in engine.features:
                        if name.startswith(category + '_'):
                            transformed[name] = int(name == feature)
                values = transformed
            missing = set(engine.features) - values.keys()
            extra = values.keys() - set(engine.features)
            if missing or extra:
                raise InvalidFeatures(f'Feature schema mismatch: {len(missing)} missing, {len(extra)} unexpected fields')
            frame = pd.DataFrame([[values[name] for name in engine.features]], columns=engine.features)
        try:
            frame = frame.astype(float)
        except (ValueError, TypeError) as exc:
            raise InvalidFeatures('All transformed features must be numeric') from exc
        if not np.isfinite(frame.to_numpy()).all():
            raise InvalidFeatures('Feature values must be finite')
        return frame

    def predict(self, dataset, values):
        if dataset not in {'cicids2017', 'unsw-nb15'}:
            raise InvalidFeatures('Unsupported dataset')
        engine = self.engines.get(dataset)
        if not engine:
            raise ModelUnavailable('The selected detection model is unavailable')
        frame = self.feature_frame(engine, dataset, values)
        start = time.perf_counter()
        try:
            code = engine.model.predict(frame)[0]
            label = str(engine.encoder.inverse_transform([int(code)])[0])
            confidence = float(np.max(engine.model.predict_proba(frame)[0]))
            if not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise ValueError('Invalid model probability')
        except Exception as exc:
            logger.exception('Inference failed for %s', dataset)
            raise ModelUnavailable('Model inference failed; traffic verdict is unknown') from exc
        return {
            'status': 'success', 'analysis_status': 'analyzed', 'dataset_used': dataset,
            'ai_classification': label, 'prediction': label,
            'is_anomaly': label.upper() not in {'BENIGN', 'NORMAL'},
            'confidence': f'{confidence * 100:.2f}%', 'confidence_raw': confidence,
            'model_version': engine.version,
            'inference_ms': round((time.perf_counter() - start) * 1000, 3),
            'severity': severity_for(label),
        }


def severity_for(label):
    value = label.lower()
    if value in {'benign', 'normal'}:
        return None
    if any(term in value for term in ['exfil', 'infiltration', 'backdoor', 'shellcode']):
        return 'Critical'
    if any(term in value for term in ['dos', 'exploit', 'brute', 'patator']):
        return 'High'
    return 'Medium'


detector = DetectionService()
