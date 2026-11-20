"""Reproducible UNSW baseline for the minimal Zeek-compatible feature contract.

The official holdout is evaluated once, after fitting and threshold selection.
This experiment never authorizes production/live classification.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
from threadpoolctl import threadpool_limits

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from flow_features import FEATURES, NUMERIC_FEATURES, TRANSPORTS, UNSW_FIELDS, FEATURE_SCHEMA_VERSION

SEED = 42
GATES = {'max_false_positive_rate': .01, 'min_attack_recall': .80,
         'min_novel_attack_recall': .80, 'min_attack_macro_recall': .50}
PARAMETERS = {'n_estimators': 160, 'max_depth': 18, 'min_samples_leaf': 5,
              'class_weight': 'balanced_subsample', 'n_jobs': 2, 'random_state': SEED}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1048576), b''): digest.update(chunk)
    return digest.hexdigest()


def read_dataset(path):
    frame = pd.read_csv(path, usecols=[*UNSW_FIELDS, 'attack_cat', 'label'])
    labels = frame['attack_cat'].str.strip()
    if labels.isna().any() or (labels == '').any(): raise ValueError('Missing ground truth labels')
    if not np.array_equal((labels != 'Normal').astype(int), frame['label']):
        raise ValueError('Binary and multiclass ground truth disagree')
    supported = frame['proto'].isin(TRANSPORTS)
    excluded = frame.loc[~supported, 'proto'].value_counts().to_dict()
    selected = frame.loc[supported, list(UNSW_FIELDS)].rename(columns=UNSW_FIELDS)[FEATURES]
    numeric = selected[NUMERIC_FEATURES].to_numpy(dtype=float)
    if not np.isfinite(numeric).all() or (numeric < 0).any(): raise ValueError('Invalid numeric training feature')
    if not np.equal(numeric[:, 1:], np.floor(numeric[:, 1:])).all(): raise ValueError('Fractional packet counts')
    return selected.reset_index(drop=True), labels.loc[supported].reset_index(drop=True), {
        'raw_rows': len(frame), 'supported_rows': int(supported.sum()),
        'excluded_protocols': excluded, 'class_support': labels.loc[supported].value_counts().to_dict(),
    }


def feature_groups(frame):
    # Identical model inputs cannot be independent examples for group validation.
    return pd.util.hash_pandas_object(frame[FEATURES], index=False).to_numpy()


def select_threshold(labels, probabilities, classes, max_fpr):
    attack = (np.asarray(labels) != 'Normal').astype(int)
    scores = 1 - probabilities[:, list(classes).index('Normal')]
    fpr, recall, thresholds = roc_curve(attack, scores, drop_intermediate=False)
    eligible = np.flatnonzero(fpr <= max_fpr)
    # Max recall subject to the declared validation FPR budget; tie -> lower FPR.
    selected = max(eligible, key=lambda index: (recall[index], -fpr[index], thresholds[index]))
    threshold = float(thresholds[selected])
    if not np.isfinite(threshold): threshold = 1.000001
    return threshold, {'false_positive_rate': float(fpr[selected]), 'attack_recall': float(recall[selected])}


def summarize(labels, probabilities, classes, threshold):
    labels = np.asarray(labels)
    classes = np.asarray(classes)
    normal = list(classes).index('Normal')
    attack_score = 1 - probabilities[:, normal]
    predicted_attack = attack_score >= threshold
    attack_columns = np.flatnonzero(classes != 'Normal')
    attack_label = classes[attack_columns[np.argmax(probabilities[:, attack_columns], axis=1)]]
    predicted = np.where(predicted_attack, attack_label, 'Normal')
    actual_attack = labels != 'Normal'
    tp = int(np.sum(actual_attack & predicted_attack)); fn = int(np.sum(actual_attack & ~predicted_attack))
    fp = int(np.sum(~actual_attack & predicted_attack)); tn = int(np.sum(~actual_attack & ~predicted_attack))
    precision, recall, f1, _ = precision_recall_fscore_support(actual_attack, predicted_attack, average='binary', zero_division=0)
    reported_classes = sorted(set(classes) | set(labels))
    report = classification_report(labels, predicted, labels=reported_classes, output_dict=True, zero_division=0)
    supported_attack_recalls = [report[str(label)]['recall'] for label in reported_classes if label != 'Normal' and report[str(label)]['support'] > 0]
    return {'rows': len(labels), 'binary': {'true_positive': tp, 'false_negative': fn, 'false_positive': fp, 'true_negative': tn,
            'precision': float(precision), 'attack_recall': float(recall), 'f1': float(f1),
            'false_positive_rate': fp / (fp + tn) if fp + tn else None,
            'roc_auc': float(roc_auc_score(actual_attack, attack_score)) if len(set(actual_attack)) == 2 else None},
            'attack_macro_recall': float(np.mean(supported_attack_recalls)) if supported_attack_recalls else None,
            'multiclass_accuracy': float(accuracy_score(labels, predicted)),
            'classes': [str(label) for label in reported_classes], 'classification_report': report,
            'confusion_matrix': confusion_matrix(labels, predicted, labels=reported_classes).tolist()}


def offline_gate(metrics, novel):
    failures = []
    if metrics['binary']['false_positive_rate'] is None or metrics['binary']['false_positive_rate'] > GATES['max_false_positive_rate']:
        failures.append('Holdout false-positive rate exceeds budget')
    if metrics['binary']['attack_recall'] < GATES['min_attack_recall']:
        failures.append('Holdout attack recall below target')
    if metrics['attack_macro_recall'] is None or metrics['attack_macro_recall'] < GATES['min_attack_macro_recall']:
        failures.append('Per-attack macro recall below target')
    if novel is None or novel['binary']['attack_recall'] < GATES['min_novel_attack_recall']:
        failures.append('Novel-feature holdout recall below target or unavailable')
    return failures


def train(train_path, test_path, output):
    output = Path(output)
    if output.exists() and any(output.iterdir()): raise ValueError('Use a new/empty model output directory')
    train_path, test_path = Path(train_path), Path(test_path)
    if train_path.resolve() == test_path.resolve(): raise ValueError('Training and holdout files must differ')
    train_hash, test_hash = sha256(train_path), sha256(test_path)
    if train_hash == test_hash: raise ValueError('Training and holdout contents must differ')
    features, labels, training_info = read_dataset(train_path)
    groups = feature_groups(features)
    fit_indices, valid_indices = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(features, labels, groups))
    if set(groups[fit_indices]) & set(groups[valid_indices]): raise AssertionError('Feature group leakage')
    if set(labels.iloc[fit_indices]) != set(labels): raise ValueError('Training split lost a target class')
    pipeline = Pipeline([
        ('features', ColumnTransformer([
            ('numeric', FunctionTransformer(np.log1p, feature_names_out='one-to-one'), NUMERIC_FEATURES),
            ('transport', OneHotEncoder(categories=[list(TRANSPORTS)], handle_unknown='error', sparse_output=False), ['transport']),
        ], remainder='drop')),
        ('classifier', RandomForestClassifier(**PARAMETERS)),
    ])
    started = time.perf_counter()
    with threadpool_limits(limits=2):
        pipeline.fit(features.iloc[fit_indices], labels.iloc[fit_indices])
        classes = pipeline.classes_
        validation_probabilities = pipeline.predict_proba(features.iloc[valid_indices])
        threshold, selection = select_threshold(labels.iloc[valid_indices], validation_probabilities, classes, GATES['max_false_positive_rate'])
        validation = summarize(labels.iloc[valid_indices], validation_probabilities, classes, threshold)
        # The official holdout is first opened here. No fitting, refitting, or tuning follows.
        holdout_features, holdout_labels, holdout_info = read_dataset(test_path)
        holdout_probabilities = pipeline.predict_proba(holdout_features)
        holdout = summarize(holdout_labels, holdout_probabilities, classes, threshold)
        novel_mask = ~np.isin(feature_groups(holdout_features), groups)
        novel = summarize(holdout_labels.loc[novel_mask], holdout_probabilities[novel_mask], classes, threshold) if novel_mask.any() else None
        baseline = DummyClassifier(strategy='most_frequent').fit(features.iloc[fit_indices], labels.iloc[fit_indices])
        baseline_metrics = summarize(holdout_labels, baseline.predict_proba(holdout_features), baseline.classes_, .5)
    elapsed = time.perf_counter() - started
    inference_times = []
    with threadpool_limits(limits=2):
        for index in range(min(50, len(holdout_features))):
            start = time.perf_counter(); pipeline.predict_proba(holdout_features.iloc[[index]])
            inference_times.append((time.perf_counter() - start) * 1000)
    failures = offline_gate(holdout, novel)
    manifest = {
        'schema_version': FEATURE_SCHEMA_VERSION, 'features': FEATURES, 'target': 'attack_cat',
        'seed': SEED, 'hyperparameters': PARAMETERS,
        'datasets': {'training_sha256': train_hash, 'testing_sha256': test_hash},
        'training_code_sha256': sha256(Path(__file__)),
        'feature_contract_code_sha256': sha256(Path(__file__).resolve().parents[1]/'backend/flow_features.py'),
        'runtime': {'python': platform.python_version(), 'sklearn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__, 'joblib': joblib.__version__},
    }
    version = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    report = {
        **manifest, 'model_version': version, 'trained_at': datetime.now(timezone.utc).isoformat(),
        'training': training_info, 'official_holdout': holdout_info,
        'split': {'method': 'GroupShuffleSplit on exact four-feature fingerprints within official training file',
                  'fit_rows': len(fit_indices), 'validation_rows': len(valid_indices), 'shared_fit_validation_groups': 0,
                  'holdout_rows_with_features_seen_in_official_training': int((~novel_mask).sum()),
                  'novel_holdout_rows': int(novel_mask.sum())},
        'threshold': threshold, 'threshold_selection': {'source': 'training-only grouped validation', **selection},
        'validation_metrics': validation, 'holdout_metrics': holdout, 'novel_holdout_metrics': novel,
        'majority_baseline_metrics': baseline_metrics, 'declared_offline_gates': GATES,
        'offline_gate_passed': not failures, 'offline_gate_failures': failures,
        'live_approved': False,
        'live_approval_reason': 'No independent labeled Zeek holdout or cross-extractor equivalence validation is available',
        'timing': {'train_and_evaluate_seconds': round(elapsed, 3), 'single_flow_pipeline_ms_p50': float(np.percentile(inference_times, 50)),
                   'single_flow_pipeline_ms_p95': float(np.percentile(inference_times, 95)), 'samples': len(inference_times)},
        'limitations': ['UNSW used Argus; live Zeek flow boundaries and packet counting can differ.',
                        'Transport scope is TCP/UDP/ICMP only; no extrapolation to other protocols.',
                        'Duration and directional counts omit much information required to distinguish attacks.',
                        'Probabilities are uncalibrated classifier scores, not attack likelihood guarantees.',
                        'Identical feature vectors occur within and across official partitions; novel-only results are reported separately.',
                        'Local live observations are unlabeled and cannot establish precision or recall.'],
        'sources': ['https://research.unsw.edu.au/projects/unsw-nb15-dataset', 'https://docs.zeek.org/en/v8.2.1/scripts/base/protocols/conn/main.zeek.html'],
    }
    output.mkdir(parents=True, exist_ok=True)
    bundle = {'pipeline': pipeline, 'schema_version': FEATURE_SCHEMA_VERSION, 'features': FEATURES,
              'model_version': version, 'threshold': threshold, 'runtime': manifest['runtime']}
    artifact = output / 'model.joblib'
    joblib.dump(bundle, artifact, compress=3)
    report['artifact_sha256'] = sha256(artifact)
    (output / 'evaluation.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'output': str(output), 'holdout': holdout['binary'], 'novel_holdout': novel['binary'] if novel else None,
                      'offline_gate_passed': not failures, 'offline_gate_failures': failures, 'live_approved': False}, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    raw = Path(__file__).resolve().parent / 'data/raw/UNSW-NB15/Training and Testing Sets'
    parser.add_argument('--train', type=Path, default=raw / 'UNSW_NB15_training-set.csv')
    parser.add_argument('--test', type=Path, default=raw / 'UNSW_NB15_testing-set.csv')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    train(args.train, args.test, args.output)


if __name__ == '__main__': main()
