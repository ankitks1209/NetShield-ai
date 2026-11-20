"""Actual Zeek integration, using synthetic PCAP records without sending packets."""
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zeek_reader import ZeekLogReader
from sensor_health import parser_for


def checksum(data):
    words = struct.unpack('!' + 'H' * (len(data) // 2), data)
    value = sum(words)
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def udp_frame(source, destination, source_port, destination_port, payload):
    udp = struct.pack('!HHHH', source_port, destination_port, len(payload) + 8, 0) + payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex('0200000000020200000000010800') + header + udp


@unittest.skipUnless(shutil.which('zeek'), 'Zeek executable is not installed')
class ActualZeekTests(unittest.TestCase):
    def test_sensor_policy_produces_parseable_health_logs_for_sustained_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'sustained.pcap'
            pairs = 1000
            with capture.open('wb') as handle:
                handle.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                for index in range(pairs):
                    # Distinct bidirectional UDP flows, spanning 100 capture seconds.
                    for direction in range(2):
                        endpoints = ('192.0.2.1', '198.51.100.2', 30000 + index, 9999) if not direction else ('198.51.100.2', '192.0.2.1', 9999, 30000 + index)
                        packet = udp_frame(*endpoints, b'netshield fixture')
                        microseconds = (index % 10) * 100000 + direction * 1000
                        handle.write(struct.pack('<IIII', 1700000000 + index // 10, microseconds, len(packet), len(packet)))
                        handle.write(packet)
            policy = Path(__file__).resolve().parents[2] / 'sensor/netshield.zeek'
            for mode in ['json', 'tsv']:
                output = root / mode; output.mkdir()
                command = [shutil.which('zeek'), '-r', str(capture), str(policy)]
                if mode == 'tsv': command += ['-e', 'redef LogAscii::use_json = F;']
                subprocess.run(command, cwd=output, check=True, capture_output=True, timeout=30)
                parsed = {}
                for kind in ['conn', 'stats', 'capture_loss']:
                    reader = ZeekLogReader(output / f'{kind}.log', parser_factory=parser_for(kind)) if kind != 'conn' else ZeekLogReader(output / 'conn.log')
                    samples, errors = [], []
                    try:
                        while True:
                            events = reader.poll()
                            if not events: break
                            samples.extend(event.flow for event in events if event.kind == 'flow')
                            errors.extend(event.error for event in events if event.kind == 'error')
                    finally: reader.close()
                    self.assertFalse(errors, (kind, errors))
                    self.assertTrue(samples, kind)
                    parsed[kind] = samples
                self.assertEqual(len(parsed['conn']), pairs)
                self.assertEqual(sum(flow['Fwd Packets'] + flow['Bwd Packets'] for flow in parsed['conn']), pairs * 2)
                self.assertTrue(all(row['packets_dropped'] is None for row in parsed['stats']))
                self.assertTrue(all(row['evidence'] == 'insufficient_tcp_acks' for row in parsed['capture_loss']))

    def test_generated_capture_has_equivalent_json_and_tsv_flows(self):
        question = b'\x07example\x04test\x00\x00\x01\x00\x01'
        query = struct.pack('!HHHHHH', 1234, 0x0100, 1, 0, 0, 0) + question
        answer = struct.pack('!HHHHHH', 1234, 0x8180, 1, 1, 0, 0) + question
        answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('203.0.113.10')
        packets = [udp_frame('192.0.2.1', '198.51.100.2', 53000, 53, query),
                   udp_frame('198.51.100.2', '192.0.2.1', 53, 53000, answer)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'fixture.pcap'
            with capture.open('wb') as handle:
                handle.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                for index, packet in enumerate(packets):
                    handle.write(struct.pack('<IIII', 1700000000, index * 250000, len(packet), len(packet)))
                    handle.write(packet)
            results = []
            for mode in ['json', 'tsv']:
                output = root / mode; output.mkdir()
                command = [shutil.which('zeek'), '-r', str(capture)]
                if mode == 'json': command += ['-e', 'redef LogAscii::use_json = T;']
                subprocess.run(command, cwd=output, check=True, capture_output=True, timeout=30)
                reader = ZeekLogReader(output / 'conn.log')
                try:
                    events = reader.poll()
                    self.assertFalse([event for event in events if event.kind == 'error'])
                    flows = [event.flow for event in events if event.kind == 'flow']
                    self.assertEqual(len(flows), 1)
                    flow = flows[0]
                    self.assertEqual((flow['Source IP'], flow['Destination IP']), ('192.0.2.1', '198.51.100.2'))
                    self.assertEqual((flow['Fwd Packets'], flow['Bwd Packets']), (1, 1))
                    self.assertEqual(flow['Protocol'], 'UDP')
                    self.assertAlmostEqual(flow['Flow Duration'], 0.25)
                    results.append(flow)
                finally: reader.close()
            for key in ['Source Port', 'Destination Port', 'Fwd Bytes', 'Bwd Bytes', 'Fwd IP Bytes', 'Bwd IP Bytes', 'connection_state']:
                self.assertEqual(results[0][key], results[1][key], key)
