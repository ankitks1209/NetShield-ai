"""Authenticated simulation benchmark. Error responses never count as fast inference."""
import argparse
from getpass import getpass
import json
import math
import os
from pathlib import Path
import statistics
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

def request_json(base, path, payload, token=None):
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    request = Request(base.rstrip('/') + path, data=json.dumps(payload).encode(), headers=headers)
    try:
        with urlopen(request, timeout=15) as response:
            return json.load(response)
    except HTTPError as exc:
        raise SystemExit(f'API rejected the request (HTTP {exc.code}); no benchmark reported')
    except URLError:
        raise SystemExit('API unavailable; no benchmark reported')

def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    parser.add_argument('--sample', type=Path, required=True, help='JSON with dataset, features, and expected_prediction')
    parser.add_argument('--samples', type=int, default=50)
    parser.add_argument('--email', help='Login email, unless NETSHIELD_BENCHMARK_TOKEN is set')
    args = parser.parse_args()
    if not 1 <= args.samples <= 1000: parser.error('--samples must be between 1 and 1000')
    sample = json.loads(args.sample.read_text())
    expected = sample.get('expected_prediction')
    if not isinstance(expected, str) or not expected: parser.error('Sample must include an expected_prediction label')
    token = os.getenv('NETSHIELD_BENCHMARK_TOKEN')
    if not token:
        if not args.email: parser.error('Provide --email or NETSHIELD_BENCHMARK_TOKEN')
        token = request_json(args.base_url, '/api/auth/login', {'email': args.email, 'password': getpass('Password: ')})['access_token']
    elapsed, inference = [], []
    for _ in range(args.samples):
        start = time.perf_counter()
        result = request_json(args.base_url, '/api/predict-manual', {
            'dataset': sample.get('dataset', 'cicids2017'), 'features': sample['features'], 'force_attack': False,
        }, token)
        duration = (time.perf_counter() - start) * 1000
        if result.get('analysis_status') != 'analyzed' or result.get('prediction') != expected:
            raise SystemExit('Prediction did not match the control sample; no benchmark reported')
        value = result.get('inference_ms')
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            raise SystemExit('Missing measured inference time; no benchmark reported')
        elapsed.append(duration); inference.append(value)
    print(json.dumps({
        'samples': len(elapsed), 'mode': 'simulation; persisted separately from operational incidents',
        'round_trip_ms': {'p50': statistics.median(elapsed), 'p95': percentile(elapsed, .95), 'p99': percentile(elapsed, .99)},
        'model_inference_ms': {'p50': statistics.median(inference), 'p95': percentile(inference, .95)},
        'scope': 'Single-client control-sample timing; not accuracy, packet-loss, or concurrent-capacity validation',
    }, indent=2))

if __name__ == '__main__':
    main()
