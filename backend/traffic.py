"""One collector per configured source, independent of browser subscriptions.

Run a single API worker until a shared broker/worker service is introduced.
"""
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import hashlib
import json
import logging

import pandas as pd
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from config import settings
from database import SessionLocal
from detection import detector, InvalidFeatures, ModelUnavailable
from mongodb import log_packet_to_db, get_sensor_checkpoint, save_sensor_checkpoint
from pipeline import process_detection, unknown_result
from security import authenticate_token
from zeek_reader import ZeekLogReader
from sensor_health import SensorHealth
from flow_candidate import flow_candidate

logger = logging.getLogger(__name__)
router = APIRouter()
SOURCES = {'cicids2017': 'cicids2017_clean.csv', 'unsw-nb15': 'unsw_nb15_clean.csv'}

def check_socket_token(token):
    with SessionLocal() as db:
        authenticate_token(token, db)

class TrafficBroker:
    def __init__(self):
        self.subscribers = {name: set() for name in (*SOURCES, 'live_network')}
        self.tasks = {}
        self.health = SensorHealth(settings)
        self.state = {name: {'status': 'disabled', 'processed': 0, 'last_event_at': None} for name in self.subscribers}

    def snapshot(self):
        states = {name: dict(state) for name, state in self.state.items()}
        live = states['live_network']
        if 'live_network' in self.tasks or live['status'] != 'disabled':
            live['capture_health'] = self.health.snapshot()
        if live.get('last_capture_time') and live['status'] in {'telemetry_only', 'degraded'}:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(live['last_capture_time'])).total_seconds()
            live['capture_age_seconds'] = round(age, 2)
            if age > settings.zeek_stale_seconds: live['status'] = 'stale'
            if age < -5: live['status'] = 'clock_skew'
            live['flow_freshness'] = live['status'] if live['status'] in {'stale', 'clock_skew'} else 'current'
            # Quiet networks can have no completed connections while capture heartbeats remain current.
            stats = live['capture_health']['logs']['stats']
            if live['status'] == 'stale' and stats['status'] == 'current':
                live['status'] = 'telemetry_only'
        return states

    async def start(self):
        for dataset in settings.monitoring_datasets:
            if dataset not in self.tasks:
                self.tasks[dataset] = asyncio.create_task(self.supervise(dataset))
                if dataset == 'live_network':
                    for kind in ['stats', 'capture_loss']:
                        self.tasks[f'health:{kind}'] = asyncio.create_task(self.health.follow(kind))

    async def supervise(self, dataset):
        delay = 1
        while True:
            await self.collect(dataset)
            if self.state[dataset]['status'] != 'unavailable':
                return  # A finite replay completed; never silently replay the dataset forever.
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

    async def stop(self):
        for task in self.tasks.values(): task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        self.tasks.clear()

    def publish(self, dataset, payload):
        for queue in tuple(self.subscribers[dataset]):
            if queue.full():
                # Tell a slow viewer to reload durable state instead of silently losing incidents.
                while not queue.empty(): queue.get_nowait()
                queue.put_nowait({'type': 'resync_required', 'active_dataset': dataset})
            else:
                queue.put_nowait(payload)

    async def collect(self, dataset):
        state = self.state[dataset]
        state.update(status='starting', error=None)
        try:
            if dataset == 'live_network':
                checkpoint_key = f'{settings.sensor_id}:{settings.zeek_log.absolute()}'
                saved = await asyncio.to_thread(get_sensor_checkpoint, checkpoint_key)
                reader = ZeekLogReader(settings.zeek_log, saved)
                state.update(status='telemetry_only', sensor_id=settings.sensor_id)
                state.setdefault('malformed_lines', 0)
                try:
                    while True:
                        events = await asyncio.to_thread(reader.poll)
                        for event in events:
                            if event.kind == 'error':
                                state['malformed_lines'] += 1
                                state['last_parse_error'] = event.error
                            elif event.kind == 'flow':
                                flow = event.flow
                                identity = f"{settings.sensor_id}:{flow['uid']}:{flow['event_time']}"
                                result = {
                                    **unknown_result(dataset, 'Live classification needs a validated feature adapter'),
                                    **flow, 'sensor_id': settings.sensor_id, 'source_mode': 'live',
                                    'event_id': hashlib.sha256(identity.encode()).hexdigest(),
                                }
                                result['shadow_detection'] = await asyncio.to_thread(flow_candidate.score, flow)
                                await asyncio.to_thread(log_packet_to_db, result)
                                self.record(dataset, result)
                                state['last_flow_event_time'] = flow['event_time']
                                state['last_capture_time'] = flow['flow_ended_at'] or flow['event_time']
                            # Do not checkpoint a flow until its durable write succeeds.
                            await asyncio.to_thread(save_sensor_checkpoint, checkpoint_key, event.cursor)
                        state['status'] = ('degraded' if state['malformed_lines'] else 'telemetry_only') if reader.state == 'following' else 'waiting_for_log'
                        if not events: await asyncio.sleep(0.2)
                finally:
                    reader.close()
                return

            path = settings.data_dir / SOURCES[dataset]
            stat = path.stat()
            model = detector.engines.get(dataset)
            source_version = f'{dataset}:{stat.st_size}:{stat.st_mtime_ns}:{model.version if model else "offline"}'
            # Chunk loading and model/database work stay outside the event loop.
            reader = pd.read_csv(path, chunksize=200)
            row_index = 0
            try:
                while True:
                    chunk = await asyncio.to_thread(next, reader, None)
                    if chunk is None: break
                    for _, row in chunk.iterrows():
                        raw = {key.strip(): value for key, value in row.to_dict().items()}
                        features = {key: value for key, value in raw.items() if key not in {'Label', 'label', 'attack_cat'}}
                        event_id = hashlib.sha256(f'{source_version}:{row_index}'.encode()).hexdigest()
                        try:
                            result = await asyncio.to_thread(process_detection, dataset, features, 'Replay dataset', event_id, 'replay')
                        except (InvalidFeatures, ModelUnavailable) as exc:
                            result = {**unknown_result(dataset, exc), 'event_id': event_id, 'dataset_used': dataset}
                            await asyncio.to_thread(log_packet_to_db, result)
                        result.update(active_dataset=dataset, Protocol=str(raw.get('proto', 'UNKNOWN')).upper())
                        self.record(dataset, result)
                        row_index += 1
                        await asyncio.sleep(settings.replay_interval)
            finally:
                reader.close()
            state['status'] = 'completed'
        except asyncio.CancelledError:
            state['status'] = 'stopped'
            raise
        except Exception:
            logger.exception('Collector stopped: %s', dataset)
            state.update(status='unavailable', error='Source or persistence unavailable; check service logs')
        finally:
            self.publish(dataset, {'type': 'source_status', 'active_dataset': dataset, **state})

    def record(self, dataset, result):
        state = self.state[dataset]
        state['processed'] += 1
        state['last_event_at'] = datetime.now(timezone.utc).isoformat()
        state['status'] = 'telemetry_only' if dataset == 'live_network' else ('degraded' if result['analysis_status'] != 'analyzed' else 'running')
        self.publish(dataset, {'type': 'packet', **result})

broker = TrafficBroker()

@router.websocket('/ws/traffic/stream')
async def traffic_stream(websocket: WebSocket, dataset: str = 'cicids2017'):
    if websocket.headers.get('origin') not in settings.origins or dataset not in broker.subscribers:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    queue = asyncio.Queue(maxsize=256)
    subscribed = False
    try:
        # Browsers cannot set an Authorization header on WebSocket handshakes.
        # Authenticate in the first frame, before subscribing or disclosing data.
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        if not isinstance(message, dict) or message.get('type') != 'authenticate':
            raise HTTPException(401, 'Authentication required')
        token = message.get('token')
        await asyncio.to_thread(check_socket_token, token)
        broker.subscribers[dataset].add(queue)
        subscribed = True
        await websocket.send_json({'type': 'source_status', 'active_dataset': dataset, **broker.snapshot()[dataset]})
        while True:
            await asyncio.to_thread(check_socket_token, token)
            try:
                payload = await asyncio.wait_for(queue.get(), timeout=10)
            except asyncio.TimeoutError:
                payload = {'type': 'source_status', 'active_dataset': dataset, **broker.snapshot()[dataset]}
            await websocket.send_json(payload)
    except (HTTPException, asyncio.TimeoutError, ValueError, TypeError, KeyError):
        with suppress(RuntimeError):
            await websocket.close(code=1008)
    except WebSocketDisconnect:
        pass
    finally:
        if subscribed: broker.subscribers[dataset].discard(queue)
