import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zeek_reader import ZeekLogReader, ZeekParser, ZeekParseError, normalize

FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'conn_state']
TYPES = ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'interval', 'count', 'count', 'count', 'count', 'string']
HEADER = '#separator \\x09\n#path\tconn\n#fields\t' + '\t'.join(FIELDS) + '\n#types\t' + '\t'.join(TYPES) + '\n'


def record(uid='flow-1'):
    return dict(zip(FIELDS, [1700000000.125, uid, '192.0.2.1', 34567, '198.51.100.2', 443, 'tcp', 1.5, 100, 250, 3, 4, 'SF']))


def line(uid='flow-1'):
    return json.dumps(record(uid)) + '\n'


class ZeekReaderTests(unittest.TestCase):
    def test_json_and_standard_tsv_have_same_semantics(self):
        parser = ZeekParser()
        for header in HEADER.splitlines(): parser.parse(header)
        a = parser.parse('\t'.join(str(value) for value in record().values()))
        b = ZeekParser().parse(json.dumps(record()))
        a.pop('observed_at'); b.pop('observed_at')
        self.assertEqual(a, b)
        self.assertEqual((a['Fwd Packets'], a['Bwd Packets']), (3, 4))
        self.assertEqual((a['Fwd Bytes'], a['Bwd Bytes']), (100, 250))
        self.assertEqual(a['Flow Duration'], 1.5)
        self.assertTrue(a['event_time'].endswith('+00:00'))

    def test_unset_is_unknown_instead_of_zero(self):
        data = record(); data.update(duration=None, orig_bytes=None, orig_pkts=None)
        result = normalize(data)
        self.assertIsNone(result['Flow Duration'])
        self.assertIsNone(result['Fwd Bytes'])
        self.assertIsNone(result['Fwd Packets'])

    def test_ipv6_addresses_are_preserved(self):
        data = record(); data['id.orig_h'] = '2001:db8::1'; data['id.resp_h'] = '2001:db8::2'
        self.assertEqual(normalize(data)['Source IP'], '2001:db8::1')

    def test_invalid_core_fields_are_rejected(self):
        for key, value in [('uid', ''), ('ts', float('nan')), ('duration', -1), ('id.resp_p', 70000),
                           ('orig_pkts', -2), ('id.orig_h', 'invalid'), ('id.orig_p', None), ('proto', 'invented')]:
            with self.subTest(key=key), self.assertRaises(ZeekParseError):
                normalize({**record(), key: value})

    def test_large_integer_counts_do_not_lose_precision(self):
        data = record(); data['orig_bytes'] = 2 ** 60 + 1
        self.assertEqual(normalize(data)['Fwd Bytes'], 2 ** 60 + 1)

    def test_partial_lines_are_not_consumed_or_checkpointed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); text = line()
            path.write_text(text[:50])
            reader = ZeekLogReader(path)
            try:
                self.assertEqual(reader.poll(), [])
                with path.open('a') as handle: handle.write(text[50:])
                events = reader.poll()
                self.assertEqual([event.flow['uid'] for event in events], ['flow-1'])
                self.assertEqual(events[0].cursor['offset'], path.stat().st_size)
            finally: reader.close()

    def test_restart_resumes_tsv_with_saved_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log')
            row = '\t'.join(str(value) for value in record().values()) + '\n'
            path.write_text(HEADER + row)
            reader = ZeekLogReader(path)
            saved = reader.poll()[-1].cursor
            reader.close()
            with path.open('a') as handle: handle.write(row.replace('flow-1', 'flow-2'))
            resumed = ZeekLogReader(path, saved)
            try: self.assertEqual([event.flow['uid'] for event in resumed.poll()], ['flow-2'])
            finally: resumed.close()

    def test_rotation_drains_old_file_and_reads_new_file_from_beginning(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); path.write_text(line('first'))
            reader = ZeekLogReader(path)
            try:
                self.assertEqual(reader.poll()[0].flow['uid'], 'first')
                with path.open('a') as handle: handle.write(line('old-tail'))
                path.rename(Path(directory, 'conn.1.log')); path.write_text(line('new-head'))
                events = reader.poll() + reader.poll()
                self.assertEqual([event.flow['uid'] for event in events if event.flow], ['old-tail', 'new-head'])
            finally: reader.close()

    def test_copy_truncate_resets_instead_of_skipping_new_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); path.write_text(line('original'))
            reader = ZeekLogReader(path)
            try:
                reader.poll()
                path.write_text(line('replacement-longer-than-original'))
                self.assertEqual(reader.poll()[0].flow['uid'], 'replacement-longer-than-original')
            finally: reader.close()

    def test_rewritten_tsv_with_same_headers_and_larger_size_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log')
            row = '\t'.join(str(value) for value in record().values()) + '\n'
            path.write_text(HEADER + row)
            reader = ZeekLogReader(path)
            try:
                reader.poll()
                path.write_text(HEADER + row.replace('flow-1', 'new-flow-with-longer-uid'))
                flows = [event.flow for event in reader.poll() if event.flow]
                self.assertEqual([flow['uid'] for flow in flows], ['new-flow-with-longer-uid'])
            finally: reader.close()

    def test_malformed_line_does_not_hide_following_valid_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); path.write_text('{broken json}\n' + line())
            reader = ZeekLogReader(path)
            try:
                events = reader.poll()
                self.assertEqual([event.kind for event in events], ['error', 'flow'])
            finally: reader.close()

    def test_missing_log_can_appear_later(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); reader = ZeekLogReader(path)
            try:
                self.assertEqual(reader.poll(), [])
                self.assertEqual(reader.state, 'waiting_for_log')
                path.write_text(line())
                self.assertEqual(reader.poll()[0].flow['uid'], 'flow-1')
            finally: reader.close()

    def test_oversized_line_is_reported_and_reader_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'conn.log'); path.write_text('x' * 100000 + '\n' + line())
            reader = ZeekLogReader(path)
            try:
                events = reader.poll()
                self.assertEqual([event.kind for event in events], ['error', 'flow'])
            finally: reader.close()
