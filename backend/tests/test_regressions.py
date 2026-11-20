"""Network-free regressions: real ASGI routes + SQLite + an in-memory Mongo substitute.

Run: backend/venv/bin/python -m unittest discover -s backend/tests -v
"""
import asyncio
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

os.environ.update(DATABASE_URL='sqlite://', MONGO_URL='mongodb://127.0.0.1:27017',
                  JWT_SECRET_KEY='a' * 64, MONITORING_DATASETS='')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
from fastapi import WebSocketDisconnect
from pymongo.errors import ServerSelectionTimeoutError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import database

database.engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
database.SessionLocal = sessionmaker(bind=database.engine)
import main
import mongodb
import traffic
from auth_utils import create_access_token, hash_password, password_version
from detection import DetectionService, Engine, InvalidFeatures, ModelUnavailable, detector
from models import User


def matches(doc, query):
    for key, wanted in query.items():
        value = doc.get(key)
        if isinstance(wanted, dict):
            for op, operand in wanted.items():
                if op == '$ne' and value == operand: return False
                if op == '$in' and value not in operand: return False
                if op == '$lt' and (value is None or value >= operand): return False
                if op == '$gte' and (value is None or value < operand): return False
                if op == '$lte' and (value is None or value > operand): return False
        elif value != wanted:
            return False
    return True


class Cursor(list):
    def sort(self, key, direction):
        return Cursor(sorted(self, key=lambda row: row.get(key, ''), reverse=direction < 0))
    def limit(self, count): return Cursor(self[:count])
    def skip(self, count): return Cursor(self[count:])


class Collection:
    def __init__(self): self.docs = {}
    def find(self, query=None, *args): return Cursor(deepcopy([x for x in self.docs.values() if matches(x, query or {})]))
    def find_one(self, query): return next(iter(self.find(query)), None)
    def count_documents(self, query): return len(self.find(query))
    def distinct(self, key, query=None): return list({x.get(key) for x in self.find(query)})
    def create_index(self, *args, **kwargs): pass
    def update_one(self, query, changes, upsert=False):
        doc = next((x for x in self.docs.values() if matches(x, query)), None)
        exists = doc is not None
        if not exists and upsert:
            doc = {**query, **deepcopy(changes.get('$setOnInsert', {}))}
            self.docs[doc['_id']] = doc
        if doc is not None:
            doc.update(deepcopy(changes.get('$set', {})))
            for key, value in changes.get('$push', {}).items(): doc.setdefault(key, []).append(deepcopy(value))
            for key, value in changes.get('$inc', {}).items(): doc[key] = doc.get(key, 0) + value
        return types.SimpleNamespace(matched_count=int(exists), upserted_id=doc['_id'] if not exists and doc else None)
    def update_many(self, query, changes):
        docs = self.find(query)
        for row in docs: self.update_one({'_id': row['_id']}, changes)
        return types.SimpleNamespace(modified_count=len(docs))
    def find_one_and_update(self, query, changes, **kwargs):
        doc = self.find_one(query)
        if not doc: return None
        self.update_one({'_id': doc['_id']}, changes)
        return self.find_one({'_id': doc['_id']})


class FixtureModel:
    def predict(self, frame): return np.array([int(frame.iloc[0, 0] > 0)])
    def predict_proba(self, frame): return np.array([[0.1, 0.9]])


class FixtureEncoder:
    def inverse_transform(self, codes): return np.array(['DDoS' if int(code) else 'BENIGN' for code in codes])


async def request(method, path, body=None, token=None, query=''):
    headers = [(b'content-type', b'application/json')]
    if token: headers.append((b'authorization', f'Bearer {token}'.encode()))
    payload = b'' if body is None else json.dumps(body).encode()
    messages = []
    scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.4'}, 'http_version': '1.1',
             'method': method, 'scheme': 'http', 'path': path, 'raw_path': path.encode(),
             'query_string': query.encode(), 'headers': headers, 'client': ('test-client', 123),
             'server': ('test-app', 80), 'root_path': ''}
    async def receive(): return {'type': 'http.request', 'body': payload, 'more_body': False}
    async def send(message): messages.append(message)
    await main.app(scope, receive, send)
    status = next(x['status'] for x in messages if x['type'] == 'http.response.start')
    raw = b''.join(x.get('body', b'') for x in messages if x['type'] == 'http.response.body').decode()
    try: data = json.loads(raw)
    except ValueError: data = raw
    return status, data


class Regressions(unittest.TestCase):
    def setUp(self):
        database.Base.metadata.drop_all(database.engine)
        database.Base.metadata.create_all(database.engine)
        mongodb.packet_logs = Collection()
        mongodb.incident_logs = Collection()
        mongodb.sensor_offsets = Collection()
        detector.engines = {'cicids2017': Engine(FixtureModel(), FixtureEncoder(), ['feature'], 'fixture-v1')}
        main.attempts.clear()
        self.password = 'correct-password-123'
        with database.SessionLocal() as db:
            user = User(username='analyst', email='analyst@example.com', full_name='Analyst',
                        role='analyst', hashed_password=hash_password(self.password), is_active=True)
            admin = User(username='admin', email='admin@example.com', full_name='Admin',
                         role='administrator', hashed_password=hash_password(self.password), is_active=True)
            db.add_all([user, admin]); db.commit()
            self.user_id, self.admin_id = user.id, admin.id
            self.token = create_access_token({'sub': str(user.id), 'pv': password_version(user.hashed_password)})
            self.admin_token = create_access_token({'sub': str(admin.id), 'pv': password_version(admin.hashed_password)})

    def call(self, method, path, body=None, token=None, query=''):
        return asyncio.run(request(method, path, body, token, query))

    def test_public_registration_cannot_choose_admin(self):
        body = dict(full_name='Test User', username='test', email='test@example.com', password=self.password)
        self.assertEqual(self.call('POST', '/api/auth/register', {**body, 'role': 'administrator'})[0], 422)
        status, data = self.call('POST', '/api/auth/register', body)
        self.assertEqual((status, data['role']), (200, 'analyst'))

    def test_all_operational_http_routes_require_authentication(self):
        schema = main.app.openapi()
        for path, methods in schema['paths'].items():
            if not path.startswith('/api/') or path in {'/api/auth/login', '/api/auth/register'}: continue
            path = path.replace('{dataset}', 'cicids2017').replace('{alert_id}', '123456789012345678901234').replace('{target_user_id}', '1').replace('{source_ip}', '192.0.2.1')
            for method in methods:
                with self.subTest(path=path, method=method):
                    self.assertEqual(self.call(method.upper(), path, {})[0], 401)

    def test_analyst_cannot_administer(self):
        for method, path in [('GET', '/api/admin/audit-logs'), ('GET', '/api/system/settings'),
                             ('PUT', '/api/system/settings'), ('POST', '/api/models/retrain'),
                             ('POST', '/api/users/invite'), ('PUT', f'/api/users/{self.admin_id}')]:
            with self.subTest(path=path): self.assertEqual(self.call(method, path, {}, self.token)[0], 403)

    def test_suspension_rejects_login_and_existing_token(self):
        with database.SessionLocal() as db:
            db.get(User, self.user_id).is_active = False; db.commit()
        self.assertEqual(self.call('POST', '/api/auth/login', {'email': 'analyst@example.com', 'password': self.password})[0], 401)
        self.assertEqual(self.call('GET', '/api/auth/me', token=self.token)[0], 401)

    def test_bad_credentials_never_raise_server_error(self):
        for token in [None, 'invalid', create_access_token({'sub': 'not-an-integer'})]:
            self.assertEqual(self.call('GET', '/api/auth/me', token=token)[0], 401)

    def test_password_change_revokes_existing_tokens(self):
        self.assertEqual(self.call('PUT', '/api/users/password', {'current_password': self.password, 'new_password': 'another-password-123'}, self.token)[0], 200)
        self.assertEqual(self.call('GET', '/api/auth/me', token=self.token)[0], 401)

    def test_short_password_rejected(self):
        self.assertEqual(self.call('PUT', '/api/users/password', {'current_password': self.password, 'new_password': 'short'}, self.token)[0], 422)

    def test_final_admin_cannot_be_demoted(self):
        self.assertEqual(self.call('PUT', f'/api/users/{self.admin_id}', {'role': 'analyst', 'is_active': True}, self.admin_token)[0], 409)

    def test_login_is_rate_limited(self):
        body = {'email': 'nobody@example.com', 'password': 'invalid'}
        for _ in range(10): self.assertEqual(self.call('POST', '/api/auth/login', body)[0], 401)
        self.assertEqual(self.call('POST', '/api/auth/login', body)[0], 429)

    def test_model_offline_and_bad_dimensions_are_errors(self):
        self.assertEqual(self.call('POST', '/api/predict', {'features': []}, self.token)[0], 422)
        detector.engines.clear()
        self.assertEqual(self.call('POST', '/api/predict', {'features': [1]}, self.token)[0], 503)

    def test_failing_model_never_becomes_benign(self):
        with patch.object(detector.engines['cicids2017'].model, 'predict', side_effect=ValueError('broken model')):
            status, body = self.call('POST', '/api/predict', {'features': [1]}, self.token)
        self.assertEqual(status, 503)
        self.assertNotIn('BENIGN', json.dumps(body))

    def test_attack_is_canonical_persisted_triageable_and_exportable(self):
        status, body = self.call('POST', '/api/predict', {'features': [1], 'source_ip': '192.0.2.1'}, self.token)
        self.assertEqual(status, 200)
        incident = body['incident']
        self.assertEqual(incident['confidence'], '90.00%')
        history = self.call('GET', '/api/alerts', token=self.token)[1]['alerts']
        self.assertEqual(history[0]['id'], incident['id'])
        status, updated = self.call('PATCH', '/api/alerts/' + incident['id'], {'status': 'Closed', 'note': 'Reviewed'}, self.token)
        self.assertEqual(status, 200)
        self.assertEqual(updated['incident']['investigation_notes'][0]['actor_id'], self.user_id)
        status, exported = self.call('GET', '/api/alerts/export', token=self.token)
        self.assertEqual(status, 200)
        self.assertIn(incident['id'], exported)
        self.assertIn('Closed', exported)

    def test_benign_does_not_create_an_incident(self):
        self.assertEqual(self.call('POST', '/api/predict', {'features': [0]}, self.token)[0], 200)
        self.assertEqual(mongodb.incident_logs.count_documents({}), 0)

    def test_simulations_do_not_pollute_operational_stats(self):
        self.assertEqual(self.call('POST', '/api/predict-manual', {'force_attack': True}, self.token)[0], 200)
        stats = self.call('GET', '/api/network/stats', token=self.token)[1]
        self.assertEqual((stats['totalScanned'], stats['totalDeviations'], stats['riskScore']), (0, 0, 0))
        self.assertEqual(self.call('GET', '/api/alerts', token=self.token)[1]['alerts'], [])
        self.assertEqual(len(self.call('GET', '/api/alerts', token=self.token, query='include_simulated=true')[1]['alerts']), 1)

    def test_unimplemented_operations_do_not_claim_success(self):
        for path in ['/api/models/retrain', '/api/users/invite', '/api/system/settings']:
            method = 'PUT' if 'settings' in path else 'POST'
            body = {'email': 'invite@example.com', 'role': 'analyst'} if 'invite' in path else {}
            self.assertEqual(self.call(method, path, body, self.admin_token)[0], 501)

    def test_empty_database_has_no_fabricated_metrics(self):
        stats = self.call('GET', '/api/network/stats', token=self.token)[1]
        self.assertEqual((stats['totalScanned'], stats['totalDeviations'], stats['riskScore']), (0, 0, 0))
        self.assertEqual(self.call('GET', '/api/alerts/forecast', token=self.token)[1]['data'], [])

    def test_storage_failure_is_service_unavailable(self):
        with patch.object(mongodb.incident_logs, 'count_documents', side_effect=ServerSelectionTimeoutError('offline')):
            self.assertEqual(self.call('GET', '/api/alerts', token=self.token)[0], 503)

    def test_status_values_are_validated(self):
        self.assertEqual(self.call('PATCH', '/api/alerts/123456789012345678901234', {'status': 'invented'}, self.token)[0], 422)

    def test_nonfinite_features_are_rejected_without_server_error(self):
        for value in [float('nan'), float('inf'), float('-inf')]:
            self.assertEqual(self.call('POST', '/api/predict', {'features': [value]}, self.token)[0], 422)

    def test_assignment_uses_active_real_user_ids(self):
        incident = self.call('POST', '/api/predict', {'features': [1]}, self.token)[1]['incident']
        path = '/api/alerts/' + incident['id']
        self.assertEqual(self.call('PATCH', path, {'assignee': 'Invented User'}, self.token)[0], 422)
        self.assertEqual(self.call('PATCH', path, {'assignee': str(self.admin_id)}, self.token)[1]['incident']['assignee'], str(self.admin_id))

    def test_notification_success_and_retry_are_persisted(self):
        import notifications
        with patch.dict(os.environ, {'SECURITY_WEBHOOK_URL': 'https://example.invalid/test-webhook'}):
            incident = self.call('POST', '/api/predict', {'features': [1]}, self.token)[1]['incident']
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.status = 200
            with patch.object(notifications, 'urlopen', return_value=response) as transport:
                self.assertTrue(notifications.deliver_due_notification())
                self.assertEqual(transport.call_count, 1)
            doc = mongodb.incident_logs.find_one({'_id': main.ObjectId(incident['id'])})
            self.assertEqual(doc['notification_status'], 'sent')
            second = self.call('POST', '/api/predict', {'features': [1]}, self.token)[1]['incident']
            with patch.object(notifications, 'urlopen', side_effect=OSError('offline')):
                notifications.deliver_due_notification()
            doc = mongodb.incident_logs.find_one({'_id': main.ObjectId(second['id'])})
            self.assertEqual((doc['notification_status'], doc['notification_attempts']), ('retrying', 1))

    def test_simulation_never_sends_notifications(self):
        with patch.dict(os.environ, {'SECURITY_WEBHOOK_URL': 'https://example.invalid/test-webhook'}):
            body = self.call('POST', '/api/predict-manual', {'force_attack': True}, self.token)[1]
            self.assertEqual(body['incident']['notification_status'], 'excluded')

    @classmethod
    def tearDownClass(cls):
        database.engine.dispose()

    def test_csv_formula_cells_are_escaped(self):
        self.assertEqual(main.csv_cell('=1+1'), "'=1+1")
        self.assertEqual(main.csv_cell(' safe text'), ' safe text')

    def test_replay_processes_all_rows_with_zero_or_two_viewers(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as directory:
                Path(directory, 'cicids2017_clean.csv').write_text('feature,Label\n' + ''.join(f'{i},ATTACK\n' for i in range(201)))
                configured = replace(traffic.settings, data_dir=Path(directory), replay_interval=0)
                broker = traffic.TrafficBroker()
                with patch.object(traffic, 'settings', configured):
                    await broker.collect('cicids2017')
                    self.assertEqual(mongodb.packet_logs.count_documents({}), 201)
                    first, second = asyncio.Queue(300), asyncio.Queue(300)
                    broker.subscribers['cicids2017'].update([first, second])
                    await broker.collect('cicids2017')
                self.assertEqual(first.qsize(), 202)  # every flow plus completion status
                self.assertEqual(second.qsize(), 202)
                self.assertEqual(mongodb.packet_logs.count_documents({}), 201)
                self.assertEqual(mongodb.incident_logs.count_documents({}), 200)
        asyncio.run(exercise())

    def test_slow_viewer_gets_explicit_resync(self):
        broker = traffic.TrafficBroker()
        queue = asyncio.Queue(1)
        broker.subscribers['cicids2017'].add(queue)
        broker.publish('cicids2017', {'type': 'packet'})
        broker.publish('cicids2017', {'type': 'packet'})
        self.assertEqual(queue.get_nowait()['type'], 'resync_required')

    def test_stream_error_is_unknown(self):
        async def exercise():
            with tempfile.TemporaryDirectory() as directory:
                Path(directory, 'cicids2017_clean.csv').write_text('wrong,Label\n1,ATTACK\n')
                broker = traffic.TrafficBroker()
                queue = asyncio.Queue(10)
                broker.subscribers['cicids2017'].add(queue)
                with patch.object(traffic, 'settings', replace(traffic.settings, data_dir=Path(directory), replay_interval=0)):
                    await broker.collect('cicids2017')
                event = queue.get_nowait()
                self.assertEqual(event['ai_classification'], 'UNKNOWN')
                self.assertIsNone(event['is_anomaly'])
        asyncio.run(exercise())

    def test_live_zeek_checkpoint_resumes_without_duplicate_flows(self):
        from test_zeek_reader import line
        async def exercise():
            async def wait_for_count(broker, count):
                while broker.state['live_network']['processed'] < count: await asyncio.sleep(0.01)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory, 'conn.log'); path.write_text(line('live-1') + line('live-2'))
                configured = replace(traffic.settings, zeek_log=path, sensor_id='fixture-sensor')
                with patch.object(traffic, 'settings', configured):
                    first = traffic.TrafficBroker()
                    task = asyncio.create_task(first.collect('live_network'))
                    await asyncio.wait_for(wait_for_count(first, 2), timeout=3)
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)
                    with path.open('a') as handle: handle.write(line('live-3'))
                    resumed = traffic.TrafficBroker()
                    task = asyncio.create_task(resumed.collect('live_network'))
                    await asyncio.wait_for(wait_for_count(resumed, 1), timeout=3)
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)
                    self.assertEqual(resumed.state['live_network']['processed'], 1)
                self.assertEqual(mongodb.packet_logs.count_documents({}), 3)
                self.assertEqual(mongodb.incident_logs.count_documents({}), 0)
                self.assertTrue(all(not row['analyzed'] for row in mongodb.packet_logs.find()))
        asyncio.run(exercise())

    def test_sensor_freshness_is_measured_from_capture_time(self):
        from datetime import timedelta
        broker = traffic.TrafficBroker()
        state = broker.state['live_network']
        state.update(status='telemetry_only', last_capture_time=(mongodb.utcnow() - timedelta(hours=1)).isoformat())
        self.assertEqual(broker.snapshot()['live_network']['status'], 'stale')
        state['last_capture_time'] = (mongodb.utcnow() + timedelta(minutes=1)).isoformat()
        self.assertEqual(broker.snapshot()['live_network']['status'], 'clock_skew')

    def test_shadow_attack_score_never_creates_a_live_incident(self):
        from test_zeek_reader import line
        async def exercise():
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory,'conn.log');path.write_text(line('shadow-flow'))
                configured=replace(traffic.settings,zeek_log=path,sensor_id='shadow-fixture')
                broker=traffic.TrafficBroker()
                result={'status':'shadow','candidate_attack':True,'candidate_label':'DDoS','attack_score':1.0,'live_approved':False}
                with patch.object(traffic,'settings',configured),patch.object(traffic.flow_candidate,'score',return_value=result):
                    task=asyncio.create_task(broker.collect('live_network'))
                    async def wait():
                        while broker.state['live_network']['processed']<1: await asyncio.sleep(.01)
                    await asyncio.wait_for(wait(),3)
                    task.cancel();await asyncio.gather(task,return_exceptions=True)
                record=mongodb.packet_logs.find()[0]
                self.assertFalse(record['analyzed'])
                self.assertIsNone(record['is_anomaly'])
                self.assertEqual(record['packet_features']['ai_classification'],'UNKNOWN')
                self.assertTrue(record['packet_features']['shadow_detection']['candidate_attack'])
                self.assertEqual(mongodb.incident_logs.count_documents({}),0)
        asyncio.run(exercise())

    def test_websocket_authenticates_before_subscribing(self):
        class Socket:
            headers = {'origin': 'http://localhost:5173'}
            def __init__(self, token): self.token, self.sent, self.code = token, [], None
            async def accept(self): pass
            async def receive_json(self): return {'type': 'authenticate', 'token': self.token}
            async def close(self, code): self.code = code
            async def send_json(self, data):
                self.sent.append(data)
                raise WebSocketDisconnect()
        async def exercise():
            bad = Socket('bad')
            await traffic.traffic_stream(bad)
            self.assertEqual((bad.sent, bad.code), ([], 1008))
            valid = Socket(self.token)
            await traffic.traffic_stream(valid)
            self.assertEqual(valid.sent[0]['type'], 'source_status')
            self.assertEqual(len(traffic.broker.subscribers['cicids2017']), 0)
        asyncio.run(exercise())

    def test_unsw_adapter_excludes_targets_and_validates_categories(self):
        service = DetectionService()
        engine = Engine(None, None, ['dur', 'proto_tcp', 'service_http', 'state_FIN'], 'fixture')
        frame = service.feature_frame(engine, 'unsw-nb15', {'dur': 1, 'proto': 'tcp', 'service': 'http', 'state': 'FIN'})
        self.assertEqual(frame.iloc[0].tolist(), [1, 1, 1, 1])
        for bad in [{'dur': 1, 'label': 1}, {'dur': 1, 'proto': 'unknown', 'service': 'http', 'state': 'FIN'}]:
            with self.assertRaises(InvalidFeatures): service.feature_frame(engine, 'unsw-nb15', bad)


if __name__ == '__main__':
    unittest.main()
