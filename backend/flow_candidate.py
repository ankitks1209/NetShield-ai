"""Explicit shadow-only scoring. Candidate scores never become live verdicts."""
import hashlib
import json
import logging
import math
from pathlib import Path
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.exceptions import InconsistentVersionWarning

from flow_features import FEATURES, FEATURE_SCHEMA_VERSION, InvalidFlow, from_zeek

logger = logging.getLogger(__name__)


class FlowCandidate:
    def __init__(self):
        self.bundle = None
        self.report = None
        self.mode = 'disabled'
        self.error = None

    def load(self, directory, mode='disabled'):
        self.bundle = self.report = None
        self.mode, self.error = mode, None
        if mode not in {'disabled', 'shadow'}: raise ValueError('Candidate supports disabled or shadow mode only')
        if mode == 'disabled': return
        try:
            directory = Path(directory)
            report = json.loads((directory / 'evaluation.json').read_text())
            if report.get('live_approved') is not False or not isinstance(report.get('offline_gate_passed'), bool):
                raise ValueError('Candidate evaluation must record its offline gate and shadow-only status')
            if not isinstance(report.get('offline_gate_failures'), list):
                raise ValueError('Candidate evaluation is incomplete')
            artifact = directory / 'model.joblib'
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != report['artifact_sha256']:
                raise ValueError('Artifact checksum does not match its evaluation')
            if report['schema_version'] != FEATURE_SCHEMA_VERSION or report['features'] != FEATURES:
                raise ValueError('Feature contract does not match the runtime')
            runtime = {'sklearn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__, 'joblib': joblib.__version__}
            if any(report['runtime'].get(key) != value for key, value in runtime.items()):
                raise ValueError('Candidate requires its recorded library versions')
            # Joblib is executable serialization; only administrator-provisioned artifacts are allowed.
            with warnings.catch_warnings():
                warnings.simplefilter('error', InconsistentVersionWarning)
                bundle = joblib.load(artifact)
            for key in ['schema_version', 'features', 'model_version', 'threshold', 'runtime']:
                if bundle[key] != report[key]: raise ValueError('Artifact metadata does not match its evaluation')
            classes = list(bundle['pipeline'].classes_)
            if 'Normal' not in classes or len(classes) < 2:
                raise ValueError('Candidate requires normal and attack classes')
            threshold = bundle['threshold']
            if not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or not 0 <= threshold <= 1.000001:
                raise ValueError('Invalid candidate threshold')
            self.bundle, self.report = bundle, report
        except Exception:
            self.error = 'Candidate unavailable: invalid artifact, evaluation metadata, or runtime compatibility'
            logger.exception('Cannot load flow candidate')

    def status(self):
        return {'mode': self.mode, 'loaded': self.bundle is not None, 'live_approved': False,
                'error': self.error, 'schema_version': FEATURE_SCHEMA_VERSION,
                'model_version': self.bundle['model_version'] if self.bundle else None,
                'offline_gate_passed': self.report['offline_gate_passed'] if self.report else None,
                'offline_gate_failures': self.report['offline_gate_failures'] if self.report else [],
                'purpose': 'Unvalidated candidate observations; no live verdicts, incidents, or notifications'}

    def score(self, flow):
        if self.mode == 'disabled': return {'status': 'disabled'}
        if self.bundle is None: return {'status': 'unavailable', 'reason': self.error}
        try:
            features = from_zeek(flow)
        except InvalidFlow as exc:
            return {'status': 'abstained', 'reason': str(exc)}
        start = time.perf_counter()
        try:
            probabilities = self.bundle['pipeline'].predict_proba(pd.DataFrame([features], columns=FEATURES))[0]
            if not np.isfinite(probabilities).all() or ((probabilities < 0) | (probabilities > 1)).any():
                raise ValueError('Invalid candidate score')
            classes = list(self.bundle['pipeline'].classes_)
            attack_score = float(1 - probabilities[classes.index('Normal')])
            candidate_attack = attack_score >= self.bundle['threshold']
            attack_indices = [i for i, name in enumerate(classes) if name != 'Normal']
            label = classes[max(attack_indices, key=lambda i: probabilities[i])] if candidate_attack else 'Normal'
            return {'status': 'shadow', 'candidate_label': str(label), 'candidate_attack': bool(candidate_attack),
                    'attack_score': attack_score, 'threshold': self.bundle['threshold'],
                    'model_version': self.bundle['model_version'], 'schema_version': FEATURE_SCHEMA_VERSION,
                    'inference_ms': round((time.perf_counter() - start) * 1000, 3), 'live_approved': False}
        except Exception:
            logger.exception('Shadow scoring failed; live verdict remains unknown')
            return {'status': 'unavailable', 'reason': 'Candidate inference failed'}


flow_candidate = FlowCandidate()
