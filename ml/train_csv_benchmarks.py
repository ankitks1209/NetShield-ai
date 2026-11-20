"""Rebuild full-feature CSV benchmarks without replacing deployed legacy models.

UNSW preserves its official holdout. CICIDS uses a deterministic bounded,
per-class reservoir and grouped internal splits; it has no independent holdout
here. Neither experiment authorizes live Zeek classification.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from threadpoolctl import threadpool_limits

from train_flow_candidate import SEED, sha256, select_threshold, summarize

PARAMETERS = {'n_estimators': 120, 'max_depth': 22, 'min_samples_leaf': 2,
              'class_weight': 'balanced_subsample', 'n_jobs': 2, 'random_state': SEED}


def groups_for(features):
    return pd.util.hash_pandas_object(features, index=False).to_numpy()


def read_unsw(path):
    frame = pd.read_csv(path)
    labels = frame.pop('attack_cat').str.strip()
    binary = frame.pop('label')
    frame = frame.drop(columns=['id'])
    if not np.array_equal((labels != 'Normal').astype(int), binary): raise ValueError('Inconsistent ground truth')
    categorical = ['proto', 'service', 'state']
    numeric = frame.drop(columns=categorical).to_numpy(dtype=float)
    if not np.isfinite(numeric).all() or frame.isna().any().any(): raise ValueError('Invalid feature values')
    return frame, labels, {'rows': len(frame), 'class_support': labels.value_counts().to_dict()}, categorical


def read_cicids(directory, per_class_limit):
    reservoir = {}
    source_counts, invalid, classes = {}, Counter(), Counter()
    rng = np.random.default_rng(SEED)
    checksums = {}
    for path in sorted(Path(directory).glob('*.csv')):
        checksums[path.name] = sha256(path)
        rows = 0
        for chunk in pd.read_csv(path, chunksize=25000, low_memory=False, encoding_errors='replace'):
            chunk.columns = chunk.columns.str.strip()
            label = chunk.pop('Label').str.strip().replace({'BENIGN': 'Normal'})
            chunk = chunk.apply(pd.to_numeric, errors='coerce')
            valid = np.isfinite(chunk.to_numpy(dtype=float)).all(axis=1) & label.notna() & label.ne('')
            invalid[path.name] += int((~valid).sum())
            rows += len(chunk)
            label, chunk = label.loc[valid], chunk.loc[valid]
            classes.update(label.value_counts().to_dict())
            chunk = chunk.assign(__label=label, __priority=rng.random(len(chunk)))
            for name, group in chunk.groupby('__label'):
                previous = reservoir.get(name)
                combined = pd.concat([previous, group], ignore_index=True) if previous is not None else group
                reservoir[name] = combined.nsmallest(per_class_limit, '__priority').copy()
        source_counts[path.name] = rows
        print(f'Read {path.name}: {rows} rows', flush=True)
    if not reservoir: raise ValueError('No CICIDS CSV files found')
    data = pd.concat(reservoir.values(), ignore_index=True).drop(columns=['__priority'])
    labels = data.pop('__label')
    return data, labels, {'source_rows': source_counts, 'source_class_support': dict(classes),
                         'invalid_rows': dict(invalid), 'retained_class_support': labels.value_counts().to_dict(),
                         'sampling': f'Uniform random-priority reservoir, at most {per_class_limit} rows per class',
                         'source_sha256': checksums}, []


def run(dataset, output, per_class_limit=20000, raw_root=None):
    output = Path(output)
    if output.exists() and any(output.iterdir()): raise ValueError('Use a new/empty output directory')
    if dataset not in {'unsw-nb15','cicids2017'}: raise ValueError('Unsupported dataset')
    root = Path(raw_root) if raw_root else Path(__file__).resolve().parent / 'data/raw'
    if dataset == 'unsw-nb15':
        directory = root / 'UNSW-NB15/Training and Testing Sets'
        train_path, test_path = directory/'UNSW_NB15_training-set.csv', directory/'UNSW_NB15_testing-set.csv'
        features, labels, source_info, categorical = read_unsw(train_path)
        provenance = {'train_sha256': sha256(train_path), 'holdout_sha256': sha256(test_path)}
        all_groups = groups_for(features)
        train_pool = set(all_groups)
        fit, valid = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(features, labels, all_groups))
        eval_features = eval_labels = None
        split_description = 'Official UNSW holdout; grouped training-only validation'
    else:
        features, labels, source_info, categorical = read_cicids(root/'CICIDS2017/MachineLearningCVE', per_class_limit)
        provenance = source_info['source_sha256']
        all_groups = groups_for(features)
        pool, holdout = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED).split(features, labels, all_groups))
        pool_fit, pool_valid = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=SEED+1).split(features.iloc[pool], labels.iloc[pool], all_groups[pool]))
        fit, valid = pool[pool_fit], pool[pool_valid]
        eval_features, eval_labels = features.iloc[holdout], labels.iloc[holdout]
        train_pool = set(all_groups[pool])
        split_description = 'Internal grouped holdout from per-class sample; not independent capture/session validation'
    if set(all_groups[fit]) & set(all_groups[valid]): raise AssertionError('Training/validation group overlap')
    numeric = [name for name in features if name not in categorical]
    transformers = [('numeric', 'passthrough', numeric)]
    if categorical:
        transformers.append(('categorical', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical))
    pipeline = Pipeline([('features', ColumnTransformer(transformers)), ('classifier', RandomForestClassifier(**PARAMETERS))])
    start = time.perf_counter()
    with threadpool_limits(limits=2):
        pipeline.fit(features.iloc[fit], labels.iloc[fit])
        if 'Normal' not in pipeline.classes_: raise ValueError('Training split has no normal traffic')
        if set(labels.iloc[valid])-set(pipeline.classes_): raise ValueError('Validation contains classes absent from training')
        valid_probabilities = pipeline.predict_proba(features.iloc[valid])
        threshold, selection = select_threshold(labels.iloc[valid], valid_probabilities, pipeline.classes_, .01)
        if dataset == 'unsw-nb15':
            eval_features, eval_labels, holdout_info, _ = read_unsw(test_path)
        else:
            holdout_info = {'rows': len(eval_features), 'class_support': eval_labels.value_counts().to_dict()}
        known_classes = list(pipeline.classes_)
        unseen_labels = sorted(set(eval_labels)-set(known_classes))
        probabilities = pipeline.predict_proba(eval_features)
        metrics = summarize(eval_labels, probabilities, pipeline.classes_, threshold)
        novel_mask = ~np.isin(groups_for(eval_features), list(train_pool))
        novel = summarize(eval_labels.iloc[np.flatnonzero(novel_mask)], probabilities[novel_mask], pipeline.classes_, threshold) if novel_mask.any() else None
        # Standard multiclass argmax is reported separately from the low-FPR operating threshold.
        from sklearn.metrics import accuracy_score, classification_report
        argmax_labels = pipeline.classes_[np.argmax(probabilities, axis=1)]
        argmax_metrics = {'accuracy': float(accuracy_score(eval_labels, argmax_labels)),
                         'classification_report': classification_report(eval_labels, argmax_labels, output_dict=True, zero_division=0)}
    manifest = {'dataset': dataset, 'features': list(features), 'categorical': categorical,
                'excluded': ['id', 'label', 'attack_cat'] if dataset=='unsw-nb15' else ['Label'],
                'seed': SEED, 'hyperparameters': PARAMETERS, 'provenance': provenance,
                'sampling': source_info.get('sampling'), 'split_method': split_description,
                'training_code_sha256': sha256(Path(__file__)),
                'evaluation_code_sha256': sha256(Path(__file__).resolve().parent/'train_flow_candidate.py'),
                'runtime': {'python': platform.python_version(), 'sklearn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__, 'joblib': joblib.__version__}}
    version = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    report = {**manifest, 'model_version': version, 'trained_at': datetime.now(timezone.utc).isoformat(),
              'source': source_info, 'holdout': holdout_info,
              'split': {'method': split_description, 'fit_rows': len(fit), 'validation_rows': len(valid),
                        'holdout_rows': len(eval_features), 'shared_fit_validation_groups': 0,
                        'novel_holdout_rows': int(novel_mask.sum()), 'unlearned_holdout_classes': unseen_labels},
              'threshold': threshold, 'threshold_selection': {'source': 'training-only grouped validation', **selection},
              'validation_metrics': summarize(labels.iloc[valid], valid_probabilities, pipeline.classes_, threshold),
              'holdout_metrics': metrics, 'novel_holdout_metrics': novel, 'argmax_metrics': argmax_metrics,
              'train_and_evaluate_seconds': round(time.perf_counter()-start, 3),
              'live_approved': False, 'deployment': 'Offline CSV benchmark; legacy models unchanged',
              'limitations': ['No live Zeek equivalence or labeled live evaluation is established.',
                              'CICIDS per-class sampling changes class prevalence; accuracy is sample-specific.',
                              'CICIDS grouped rows do not establish day/session separation.',
                              'Novel-feature results exclude exact model-input matches in the training/validation pool.']}
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump({'pipeline': pipeline, 'features': list(features), 'threshold': threshold, 'model_version': version}, output/'model.joblib', compress=3)
    report['artifact_sha256'] = sha256(output/'model.joblib')
    (output/'evaluation.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'dataset': dataset, 'argmax_accuracy': argmax_metrics['accuracy'], 'thresholded_holdout':metrics['binary'],
                      'unlearned_classes':unseen_labels,'output':str(output)},indent=2))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=['unsw-nb15','cicids2017'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--per-class-limit', type=int, default=20000)
    parser.add_argument('--raw-root', type=Path)
    args = parser.parse_args()
    if not 100 <= args.per_class_limit <= 100000: parser.error('per-class-limit must be in [100,100000]')
    run(args.dataset,args.output,args.per_class_limit,args.raw_root)
