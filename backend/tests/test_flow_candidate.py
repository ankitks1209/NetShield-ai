import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import FEATURES, FEATURE_SCHEMA_VERSION, InvalidFlow, from_unsw, from_zeek
from flow_candidate import FlowCandidate

spec = importlib.util.spec_from_file_location('train_flow_candidate', Path(__file__).resolve().parents[2] / 'ml/train_flow_candidate.py')
trainer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trainer)


class FlowFeatureTests(unittest.TestCase):
    def test_adapters_produce_identical_contract_for_equivalent_measurements(self):
        zeek = {'Flow Duration': .5, 'Fwd Packets': 10, 'Bwd Packets': 5, 'Protocol': 'TCP', 'missed_bytes': 0}
        unsw = {'dur': .5, 'spkts': 10, 'dpkts': 5, 'proto': 'tcp', 'id': 99, 'attack_cat': 'Exploits', 'label': 1}
        self.assertEqual(from_zeek(zeek), from_unsw(unsw))
        self.assertEqual(set(from_zeek(zeek)), set(FEATURES))

    def test_missing_corrupt_and_gap_affected_flows_abstain(self):
        good = {'Flow Duration': .5, 'Fwd Packets': 10, 'Bwd Packets': 5, 'Protocol': 'TCP', 'missed_bytes': 0}
        for key, value in [('missed_bytes', None), ('missed_bytes', 1), ('Flow Duration', None),
                           ('Fwd Packets', 1.5), ('Bwd Packets', -1), ('Flow Duration', float('nan')),
                           ('Protocol', 'unknown'), ('Fwd Packets', True)]:
            with self.subTest(key=key, value=value), self.assertRaises(InvalidFlow):
                from_zeek({**good, key: value})


class TrainingProtocolTests(unittest.TestCase):
    def test_identical_features_group_together_without_labels_or_ids(self):
        features = pd.DataFrame([[1, 2, 3, 'tcp'], [1, 2, 3, 'tcp'], [2, 3, 4, 'udp']], columns=FEATURES)
        groups = trainer.feature_groups(features)
        self.assertEqual(groups[0], groups[1]); self.assertNotEqual(groups[0], groups[2])

    def test_threshold_selection_respects_validation_false_positive_budget(self):
        labels = ['Normal'] * 100 + ['Exploits'] * 100
        scores = np.concatenate([np.linspace(0, .5, 100), np.linspace(.3, 1, 100)])
        probabilities = np.column_stack([scores, 1 - scores])
        threshold, metrics = trainer.select_threshold(labels, probabilities, ['Exploits', 'Normal'], .01)
        self.assertLessEqual(metrics['false_positive_rate'], .01)
        self.assertGreater(threshold, .4)
        self.assertGreater(metrics['attack_recall'], .6)

    def test_same_file_cannot_be_train_and_holdout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, 'same.csv'); source.write_text('not read')
            with self.assertRaisesRegex(ValueError, 'must differ'):
                trainer.train(source, source, Path(directory, 'model'))

    def test_labels_and_unsupported_transports_do_not_enter_features(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, 'rows.csv')
            pd.DataFrame([{'dur': 1, 'proto': 'tcp', 'spkts': 2, 'dpkts': 3, 'id': 77, 'label': 1, 'attack_cat': 'Exploits'},
                          {'dur': 2, 'proto': 'arp', 'spkts': 2, 'dpkts': 3, 'id': 88, 'label': 0, 'attack_cat': 'Normal'}]).to_csv(source, index=False)
            features, labels, info = trainer.read_dataset(source)
            self.assertEqual(features.columns.tolist(), FEATURES)
            self.assertEqual(labels.tolist(), ['Exploits'])
            self.assertEqual(info['excluded_protocols'], {'arp': 1})

    def test_offline_gate_rejects_low_recall_and_high_false_positive_rate(self):
        metrics = {'binary': {'false_positive_rate': .1, 'attack_recall': .2}, 'attack_macro_recall': .1}
        self.assertEqual(len(trainer.offline_gate(metrics, None)), 4)

    def test_unlearned_holdout_class_is_counted_as_a_miss(self):
        metrics = trainer.summarize(['Normal', 'UnseenAttack'], np.array([[.1,.9],[.1,.9]]), ['Exploits','Normal'], .5)
        self.assertIn('UnseenAttack', metrics['classes'])
        self.assertEqual(metrics['classification_report']['UnseenAttack']['support'], 1)
        self.assertEqual(metrics['classification_report']['UnseenAttack']['recall'], 0)
        self.assertEqual(metrics['binary']['false_negative'], 1)

    def test_full_training_pipeline_reloads_without_prediction_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def data(offset):
                return pd.DataFrame([{'dur': offset+i/100, 'proto': 'tcp' if i%2 else 'udp',
                    'spkts': i+2, 'dpkts': i%8, 'attack_cat': 'Exploits' if i%2 else 'Normal', 'label': i%2}
                    for i in range(100)])
            data(1).to_csv(root/'train.csv',index=False);data(2).to_csv(root/'test.csv',index=False)
            with patch.object(trainer,'PARAMETERS',{**trainer.PARAMETERS,'n_estimators':3}):
                report=trainer.train(root/'train.csv',root/'test.csv',root/'model')
            candidate=FlowCandidate();candidate.load(root/'model','shadow')
            self.assertTrue(candidate.status()['loaded'])
            flow={'Flow Duration':2.01,'Fwd Packets':3,'Bwd Packets':1,'Protocol':'TCP','missed_bytes':0}
            self.assertEqual(candidate.score(flow)['status'],'shadow')
            self.assertFalse(report['live_approved'])


class ShadowArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        features = pd.DataFrame([[.1, 1, 1, 'tcp'], [10, 100, 100, 'udp'], [.2, 1, 2, 'tcp'], [20, 200, 200, 'udp']], columns=FEATURES)
        pipeline = Pipeline([('features', ColumnTransformer([('transport', OneHotEncoder(handle_unknown='error'), ['transport']),
                                                            ('numeric', 'passthrough', FEATURES[:3])])),
                             ('classifier', RandomForestClassifier(n_estimators=3, random_state=42))]).fit(features, ['Normal', 'Exploits', 'Normal', 'Exploits'])
        runtime = {'sklearn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__, 'joblib': joblib.__version__}
        self.bundle = {'pipeline': pipeline, 'schema_version': FEATURE_SCHEMA_VERSION, 'features': FEATURES,
                       'model_version': 'test-model', 'threshold': .5, 'runtime': runtime}
        self.report = {key: value for key, value in self.bundle.items() if key != 'pipeline'}
        self.report.update(offline_gate_passed=False, offline_gate_failures=['Unvalidated'], live_approved=False)
        self.save()

    def save(self):
        path = self.directory / 'model.joblib'
        joblib.dump(self.bundle, path)
        self.report['artifact_sha256'] = trainer.sha256(path)
        self.save_report()

    def save_report(self):
        (self.directory / 'evaluation.json').write_text(json.dumps(self.report))

    def test_default_mode_never_loads_or_scores_an_artifact(self):
        candidate = FlowCandidate()
        candidate.load(self.directory)
        self.assertFalse(candidate.status()['loaded'])
        self.assertEqual(candidate.score({})['status'], 'disabled')

    def test_production_mode_is_not_supported(self):
        with self.assertRaises(ValueError): FlowCandidate().load(self.directory, 'active')

    def test_checksum_mismatch_is_rejected_before_joblib_execution(self):
        (self.directory / 'model.joblib').write_bytes(b'corrupt artifact')
        candidate = FlowCandidate()
        with patch('flow_candidate.joblib.load') as loader, self.assertLogs('flow_candidate', level='ERROR'):
            candidate.load(self.directory, 'shadow')
        loader.assert_not_called()
        self.assertFalse(candidate.status()['loaded'])

    def test_runtime_mismatch_is_rejected_before_loading(self):
        self.report['runtime']['sklearn'] = 'different-version'; self.save_report()
        with patch('flow_candidate.joblib.load') as loader, self.assertLogs('flow_candidate', level='ERROR'):
            candidate = FlowCandidate(); candidate.load(self.directory, 'shadow')
        loader.assert_not_called()
        self.assertFalse(candidate.status()['loaded'])

    def test_shadow_prediction_matches_persisted_pipeline(self):
        candidate = FlowCandidate(); candidate.load(self.directory, 'shadow')
        flow = {'Flow Duration': 10, 'Fwd Packets': 100, 'Bwd Packets': 100, 'Protocol': 'UDP', 'missed_bytes': 0}
        scored = candidate.score(flow)
        expected = candidate.bundle['pipeline'].predict_proba(pd.DataFrame([from_zeek(flow)], columns=FEATURES))[0]
        classes = list(candidate.bundle['pipeline'].classes_)
        self.assertEqual(scored['status'], 'shadow')
        self.assertAlmostEqual(scored['attack_score'], 1 - expected[classes.index('Normal')])
        self.assertFalse(scored['live_approved'])
        self.assertNotIn('is_anomaly', scored)

    def test_invalid_flow_and_pipeline_failure_are_never_benign_verdicts(self):
        candidate = FlowCandidate(); candidate.load(self.directory, 'shadow')
        self.assertEqual(candidate.score({})['status'], 'abstained')
        flow = {'Flow Duration': 10, 'Fwd Packets': 100, 'Bwd Packets': 100, 'Protocol': 'UDP', 'missed_bytes': 0}
        with patch.object(candidate.bundle['pipeline'], 'predict_proba', side_effect=ValueError('broken')), self.assertLogs('flow_candidate', level='ERROR'):
            result = candidate.score(flow)
        self.assertEqual(result['status'], 'unavailable')
