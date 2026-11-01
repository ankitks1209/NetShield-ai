"""Typed Zeek conn.log parsing and resumable, rotation-safe file following.

Offsets advance only for complete lines. The caller persists each cursor AFTER
persisting its flow. Replaying a line after a crash is safe with stable event IDs.
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re


class ZeekParseError(ValueError):
    pass


def unescape(value):
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda match: chr(int(match[1], 16)), value)


def number(value, name, integer=False, maximum=None):
    if value is None or value == '-':
        return None
    if isinstance(value, bool):
        raise ZeekParseError(f'{name} must be numeric')
    if integer and (isinstance(value, int) or isinstance(value, str) and re.fullmatch(r'\d+', value)):
        parsed = int(value)
        if parsed < 0 or maximum is not None and parsed > maximum:
            raise ZeekParseError(f'{name} exceeds its valid range')
        return parsed
    try:
        parsed = float(value)
    except (ValueError, TypeError):
        raise ZeekParseError(f'{name} must be numeric')
    if not math.isfinite(parsed) or parsed < 0 or (integer and not parsed.is_integer()):
        raise ZeekParseError(f'Invalid {name}')
    if maximum is not None and parsed > maximum:
        raise ZeekParseError(f'{name} exceeds its valid range')
    return int(parsed) if integer else parsed


class ZeekParser:
    def __init__(self, schema=None):
        self.schema = schema or {'separator': '\t', 'empty': '(empty)', 'unset': '-', 'fields': [], 'types': []}

    def parse(self, line):
        if line.startswith('#'):
            if line.startswith('#separator '):
                self.schema = {'separator': unescape(line.split(' ', 1)[1]), 'empty': '(empty)', 'unset': '-', 'fields': [], 'types': []}
            else:
                parts = line.split(self.schema['separator'])
                key, values = parts[0], parts[1:]
                if key == '#path' and values:
                    self.schema['path'] = values[0]
                    if values[0] != 'conn': raise ZeekParseError('Configured log is not a Zeek connection log')
                if key == '#fields': self.schema['fields'] = values
                if key == '#types': self.schema['types'] = values
                if key == '#empty_field' and values: self.schema['empty'] = values[0]
                if key == '#unset_field' and values: self.schema['unset'] = values[0]
            return None
        if self.schema.get('path', 'conn') != 'conn':
            raise ZeekParseError('Configured log is not a Zeek connection log')
        if line.lstrip().startswith('{'):
            try:
                record = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ZeekParseError('Nonfinite JSON value')))
            except (ValueError, TypeError) as exc:
                raise ZeekParseError('Malformed JSON connection record') from exc
            if not isinstance(record, dict): raise ZeekParseError('Expected a JSON object')
        else:
            fields, types = self.schema['fields'], self.schema['types']
            values = line.split(self.schema['separator'])
            if not fields or len(fields) != len(types) or len(values) != len(fields):
                raise ZeekParseError('TSV schema or column count mismatch')
            record = {}
            for key, kind, value in zip(fields, types, values):
                if value == self.schema['unset']:
                    record[key] = None
                elif value == self.schema['empty']:
                    record[key] = ''
                elif kind in {'count', 'port', 'int'}:
                    record[key] = number(value, key, integer=True)
                elif kind in {'time', 'interval', 'double'}:
                    record[key] = number(value, key)
                elif kind == 'bool':
                    if value not in {'T', 'F'}: raise ZeekParseError('Invalid boolean field')
                    record[key] = value == 'T'
                else:
                    record[key] = unescape(value)
        return normalize(record)


def normalize(record):
    uid = record.get('uid')
    if not isinstance(uid, str) or not uid or len(uid) > 128:
        raise ZeekParseError('Missing or invalid connection UID')
    try:
        source = str(ipaddress.ip_address(record['id.orig_h']))
        destination = str(ipaddress.ip_address(record['id.resp_h']))
    except (KeyError, ValueError, TypeError):
        raise ZeekParseError('Invalid originator or responder address')
    timestamp = number(record.get('ts'), 'timestamp')
    if timestamp is None: raise ZeekParseError('Missing connection timestamp')
    try:
        started = datetime.fromtimestamp(timestamp, timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise ZeekParseError('Connection timestamp out of range')
    protocol = record.get('proto')
    if protocol not in {'tcp', 'udp', 'icmp', 'unknown'}:
        raise ZeekParseError('Unsupported transport protocol')
    state = record.get('conn_state')
    if not isinstance(state, str) or not state or len(state) > 16:
        raise ZeekParseError('Missing connection state; this may not be a conn.log record')
    duration = number(record.get('duration'), 'duration')
    orig_bytes = number(record.get('orig_bytes'), 'orig_bytes', integer=True)
    resp_bytes = number(record.get('resp_bytes'), 'resp_bytes', integer=True)
    try:
        ended = (started + timedelta(seconds=duration)).isoformat() if duration is not None else None
    except (ValueError, OverflowError):
        raise ZeekParseError('Connection duration out of range')
    orig_port = number(record.get('id.orig_p'), 'originator port', True, 65535)
    resp_port = number(record.get('id.resp_p'), 'responder port', True, 65535)
    if protocol in {'tcp', 'udp'} and (orig_port is None or resp_port is None):
        raise ZeekParseError('TCP/UDP records require both endpoint ports')
    return {
        'uid': uid, 'event_time': started.isoformat(), 'flow_ended_at': ended,
        'Source IP': source, 'Destination IP': destination,
        'Source Port': orig_port,
        'Destination Port': resp_port,
        'Protocol': protocol.upper(), 'Flow Duration': duration,
        'Fwd Bytes': orig_bytes, 'Bwd Bytes': resp_bytes,
        'Fwd Packets': number(record.get('orig_pkts'), 'orig_pkts', True),
        'Bwd Packets': number(record.get('resp_pkts'), 'resp_pkts', True),
        'Fwd IP Bytes': number(record.get('orig_ip_bytes'), 'orig_ip_bytes', True),
        'Bwd IP Bytes': number(record.get('resp_ip_bytes'), 'resp_ip_bytes', True),
        'service': record.get('service'), 'connection_state': record.get('conn_state'),
        'history': record.get('history'), 'missed_bytes': number(record.get('missed_bytes'), 'missed_bytes', True),
        'observed_at': datetime.now(timezone.utc).isoformat(),
    }


@dataclass
class ReadEvent:
    kind: str
    cursor: dict
    flow: dict | None = None
    error: str | None = None


class ZeekLogReader:
    def __init__(self, path, checkpoint=None):
        self.path = Path(path)
        self.checkpoint = checkpoint
        self.handle = None
        self.parser = ZeekParser()
        self.identity = None
        self.prefix = b''
        self.pending = b''
        self.discarding = False
        self.state = 'waiting_for_log'
        self.anchor = None

    def close(self):
        if self.handle: self.handle.close()
        self.handle = None

    def open(self):
        self.close()
        try:
            self.handle = self.path.open('rb')
        except FileNotFoundError:
            self.state = 'waiting_for_log'
            return False
        stat = os.fstat(self.handle.fileno())
        self.identity = (stat.st_dev, stat.st_ino)
        self.prefix = self.handle.read(128)
        self.handle.seek(0)
        self.pending = b''
        self.discarding = False
        self.parser = ZeekParser()
        self.anchor = None
        saved = self.checkpoint
        if saved and tuple(saved.get('identity', ())) == self.identity and saved.get('offset', 0) <= stat.st_size:
            length = saved.get('prefix_length', 0)
            if length and hashlib.sha256(self.prefix[:length]).hexdigest() == saved.get('prefix_hash'):
                anchor = saved.get('anchor')
                valid = True
                if anchor:
                    self.handle.seek(anchor['offset'] - anchor['length'])
                    valid = hashlib.sha256(self.handle.read(anchor['length'])).hexdigest() == anchor['hash']
                if valid:
                    self.handle.seek(saved['offset'])
                    self.parser = ZeekParser(saved.get('schema'))
                    self.anchor = anchor
                else:
                    self.handle.seek(0)
        self.checkpoint = None
        self.state = 'following'
        return True

    def cursor(self):
        return {'identity': list(self.identity), 'offset': self.handle.tell(),
                'prefix_length': len(self.prefix), 'prefix_hash': hashlib.sha256(self.prefix).hexdigest(),
                'anchor': self.anchor,
                'schema': {key: list(value) if isinstance(value, list) else value for key, value in self.parser.schema.items()}}

    def poll(self, maximum_lines=200):
        if self.handle is None and not self.open(): return []
        events = []
        try:
            stat = self.path.stat()
            if (stat.st_dev, stat.st_ino) == self.identity:
                position = self.handle.tell()
                self.handle.seek(0); prefix = self.handle.read(len(self.prefix)); self.handle.seek(position)
                anchor_valid = True
                if self.anchor:
                    self.handle.seek(self.anchor['offset'] - self.anchor['length'])
                    anchor_valid = hashlib.sha256(self.handle.read(self.anchor['length'])).hexdigest() == self.anchor['hash']
                    self.handle.seek(position)
                if stat.st_size < position or prefix != self.prefix or not anchor_valid:
                    self.open()  # copy-truncate or an in-place replacement; restart at byte zero
        except FileNotFoundError:
            pass  # Drain the old descriptor even when its name has disappeared.
        for _ in range(maximum_lines):
            part = self.handle.readline(65537)
            if not part:
                try: current = self.path.stat()
                except FileNotFoundError: current = None
                if current and (current.st_dev, current.st_ino) != self.identity:
                    if self.pending:
                        events.append(ReadEvent('error', self.cursor(), error='Incomplete line discarded at log rotation'))
                    self.open()  # New rotation is read from its beginning, including all headers.
                self.state = 'following' if current else 'waiting_for_log'
                break
            self.pending += part
            if len(self.pending) > 65536:
                self.discarding = True
                self.pending = b''
            if not part.endswith(b'\n'):
                continue  # Retain fragments; never parse or checkpoint an incomplete record.
            if self.discarding:
                events.append(ReadEvent('error', self.cursor(), error='Oversized log line discarded'))
                self.discarding = False
                self.pending = b''
                continue
            raw, self.pending = self.pending, b''
            self.anchor = {'offset': self.handle.tell(), 'length': min(len(raw), 128), 'hash': hashlib.sha256(raw[-128:]).hexdigest()}
            try:
                line = raw.decode('utf-8').rstrip('\r\n')
                if not line: continue
                flow = self.parser.parse(line)
                events.append(ReadEvent('flow' if flow else 'header', self.cursor(), flow=flow))
            except (UnicodeDecodeError, ZeekParseError) as exc:
                events.append(ReadEvent('error', self.cursor(), error=str(exc)))
        return events
