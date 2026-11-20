"""Versioned, minimal flow contract shared by training and Zeek shadow scoring.

UNSW was extracted with Argus, not Zeek. Matching these four broad field meanings
does not establish cross-extractor or live-network equivalence. No payload/IP
byte substitution, identifiers, labels, services, or connection states are used.
"""
import math

FEATURE_SCHEMA_VERSION = 'zeek-flow-v1'
NUMERIC_FEATURES = ['duration_seconds', 'originator_packets', 'responder_packets']
FEATURES = [*NUMERIC_FEATURES, 'transport']
TRANSPORTS = ('tcp', 'udp', 'icmp')
UNSW_FIELDS = {'dur': 'duration_seconds', 'spkts': 'originator_packets',
               'dpkts': 'responder_packets', 'proto': 'transport'}
ZEEK_FIELDS = {'Flow Duration': 'duration_seconds', 'Fwd Packets': 'originator_packets',
               'Bwd Packets': 'responder_packets', 'Protocol': 'transport'}


class InvalidFlow(ValueError):
    pass


def validate_flow(values):
    if set(values) != set(FEATURES):
        raise InvalidFlow('The flow must match the versioned four-feature contract')
    result = {}
    for name in NUMERIC_FEATURES:
        value = values[name]
        if value is None or isinstance(value, (bool, str)):
            raise InvalidFlow(f'{name} must be a measured number')
        try: value = float(value)
        except (ValueError, TypeError, OverflowError): raise InvalidFlow(f'Invalid {name}')
        if not math.isfinite(value) or value < 0:
            raise InvalidFlow(f'{name} must be finite and nonnegative')
        if name != 'duration_seconds' and not value.is_integer():
            raise InvalidFlow('Packet counts must be whole numbers')
        result[name] = value
    transport = values['transport']
    if not isinstance(transport, str) or transport.lower() not in TRANSPORTS:
        raise InvalidFlow('Transport is outside the evaluated TCP/UDP/ICMP scope')
    result['transport'] = transport.lower()
    return result


def from_zeek(flow):
    if flow.get('missed_bytes') is None or flow['missed_bytes'] != 0:
        raise InvalidFlow('Missing capture-completeness evidence or reported TCP gaps')
    return validate_flow({target: flow.get(source) for source, target in ZEEK_FIELDS.items()})


def from_unsw(row):
    return validate_flow({target: row.get(source) for source, target in UNSW_FIELDS.items()})
