"""Zeek's capture counters and TCP-gap estimates retain their distinct meanings."""
import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import logging
import math
from threading import RLock

from zeek_reader import ZeekLogReader, ZeekParser, ZeekParseError, number

logger = logging.getLogger(__name__)
MAX_PEERS = 64


def timestamp(value):
    epoch = number(value, 'measurement timestamp')
    if epoch is None: raise ZeekParseError('Missing measurement timestamp')
    try: return datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError): raise ZeekParseError('Invalid measurement timestamp')


def normalize_health(record, kind):
    peer = record.get('peer')
    if not isinstance(peer, str) or not peer or len(peer) > 128:
        raise ZeekParseError('Missing or invalid Zeek peer')
    result = {'timestamp': timestamp(record.get('ts')), 'peer': peer}
    if kind == 'stats':
        fields = {'pkts_proc': 'packets_processed', 'pkts_dropped': 'packets_dropped',
                  'pkts_link': 'packets_seen_on_link', 'pkts_filtered': 'packets_filtered',
                  'bytes_recv': 'bytes_received', 'mem': 'memory_mb'}
        for source, target in fields.items():
            result[target] = number(record.get(source), source, integer=True)
        if result['packets_processed'] is None:
            raise ZeekParseError('Missing processed packet count')
        lag = record.get('pkt_lag')
        try: lag = float(lag) if lag is not None else None
        except (ValueError, TypeError): raise ZeekParseError('Invalid packet lag')
        if lag is not None and not math.isfinite(lag): raise ZeekParseError('Invalid packet lag')
        result['packet_lag_seconds'] = lag
        # No inferred drop percentage: capture APIs differ in their link counters.
        result['counter_scope'] = 'last Zeek reporting interval'
    else:
        for source in ['acks', 'gaps']:
            result[source] = number(record.get(source), source, integer=True)
            if result[source] is None: raise ZeekParseError(f'Missing {source}')
        result['interval_seconds'] = number(record.get('ts_delta'), 'measurement interval')
        if not result['interval_seconds']: raise ZeekParseError('Invalid measurement interval')
        percent = number(record.get('percent_lost'), 'TCP gap percentage', maximum=100)
        if percent is None: raise ZeekParseError('Missing TCP gap percentage')
        expected = 100 * result['gaps'] / result['acks'] if result['acks'] else 0
        if result['gaps'] > result['acks'] or not math.isclose(percent, expected, abs_tol=1e-4):
            raise ZeekParseError('Inconsistent TCP gap measurement')
        result['tcp_gap_percent'] = percent if result['acks'] else None
        result['evidence'] = 'TCP ACK gap estimate' if result['acks'] else 'insufficient_tcp_acks'
    return result


def parser_for(kind):
    return lambda schema=None: ZeekParser(schema, expected_path=kind,
                                         normalizer=lambda record: normalize_health(record, kind))


class SensorHealth:
    def __init__(self, configuration=None, checkpoint_collection=None, stale_seconds=120):
        self.configuration = configuration
        self.checkpoint_collection = checkpoint_collection
        self.stale_seconds = configuration.zeek_stale_seconds if configuration else stale_seconds
        self.lock = RLock()
        self.logs = {kind: {'status': 'waiting_for_log', 'malformed_lines': 0, 'peers': {}}
                     for kind in ['stats', 'capture_loss']}

    def ingest(self, kind, sample):
        with self.lock:
            self._ingest(kind, sample)

    def _ingest(self, kind, sample):
        peers = self.logs[kind]['peers']
        previous = peers.get(sample['peer'])
        if previous and sample['timestamp'] < previous['timestamp']:
            return
        if sample['peer'] not in peers and len(peers) >= MAX_PEERS:
            oldest = min(peers, key=lambda peer: peers[peer]['timestamp'])
            del peers[oldest]
        peers[sample['peer']] = sample

    def snapshot(self, now=None):
        now = now or datetime.now(timezone.utc)
        with self.lock:
            result = deepcopy(self.logs)
        observed_drops = False
        fresh_samples = False
        for kind, log in result.items():
            for peer, sample in log['peers'].items():
                age = (now - datetime.fromisoformat(sample['timestamp'])).total_seconds()
                sample['age_seconds'] = round(age, 3)
                sample['freshness'] = 'clock_skew' if age < -5 else ('stale' if age > self.stale_seconds else 'current')
                if sample['freshness'] == 'current' and log['status'] == 'following':
                    fresh_samples = True
                    observed_drops |= (sample.get('packets_dropped') or 0) > 0 or (sample.get('tcp_gap_percent') or 0) > 0
            if log['status'] == 'following':
                freshness = {sample['freshness'] for sample in log['peers'].values()}
                log['status'] = 'no_samples' if not freshness else ('clock_skew' if 'clock_skew' in freshness else 'stale' if 'stale' in freshness else 'current')
        # A current TCP-gap estimate alone does not measure the capture API's drop counter.
        current_stats = [sample for sample in result['stats']['peers'].values()
                         if sample['freshness'] == 'current' and result['stats']['status'] == 'current']
        if observed_drops:
            status = 'loss_observed'
        elif any(log['status'] in {'unavailable', 'clock_skew'} or log['malformed_lines'] for log in result.values()):
            status = 'degraded'
        elif current_stats and all(sample['packets_dropped'] is not None for sample in current_stats):
            status = 'no_local_drops_reported'
        else:
            status = 'unmeasured' if fresh_samples else 'telemetry_unavailable'
        return {'status': status, 'logs': result,
                'meaning': 'Local capture drops and TCP ACK gap estimates; zero counters do not prove lossless network capture'}

    async def follow(self, kind):
        configuration = self.configuration
        if configuration is None:
            from config import settings
            configuration = settings
        collection = self.checkpoint_collection
        if collection is None:
            from mongodb import sensor_offsets
            collection = sensor_offsets
        path = configuration.zeek_log.parent / f'{kind}.log'
        key = f'{configuration.sensor_id}:{path.absolute()}'
        delay = 1
        while True:
            reader = None
            try:
                saved = await asyncio.to_thread(collection.find_one, {'_id': key})
                if saved and saved.get('health'):
                    with self.lock: self.logs[kind] = saved['health']
                reader = ZeekLogReader(path, saved.get('cursor') if saved else None, parser_for(kind))
                while True:
                    events = await asyncio.to_thread(reader.poll)
                    for event in events:
                        if event.kind == 'flow': self.ingest(kind, event.flow)
                        if event.kind == 'error':
                            with self.lock:
                                self.logs[kind]['malformed_lines'] += 1
                                self.logs[kind]['last_parse_error'] = event.error
                        self.logs[kind]['status'] = reader.state
                        with self.lock: persisted_health = deepcopy(self.logs[kind])
                        await asyncio.to_thread(collection.update_one, {'_id': key},
                            {'$set': {'cursor': event.cursor, 'health': persisted_health, 'updated_at': datetime.now(timezone.utc)}}, upsert=True)
                    self.logs[kind]['status'] = reader.state
                    delay = 1
                    await asyncio.sleep(0 if events else 0.5)
            except asyncio.CancelledError:
                self.logs[kind]['status'] = 'stopped'
                raise
            except Exception:
                self.logs[kind]['status'] = 'unavailable'
                logger.exception('Zeek %s telemetry unavailable; retrying', kind)
            finally:
                if reader: reader.close()
            await asyncio.sleep(delay)
            delay = min(30, delay * 2)
