"""Validated runtime configuration; secrets have no source-code defaults."""
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR.parent / '.env')
load_dotenv(BACKEND_DIR / '.env')

def required(name):
    value = os.getenv(name, '').strip()
    if not value:
        raise RuntimeError(f'{name} must be configured')
    return value

@dataclass(frozen=True)
class Settings:
    database_url: str
    mongo_url: str
    jwt_secret: str
    token_minutes: int
    origins: tuple
    model_dir: Path
    data_dir: Path
    zeek_log: Path
    monitoring_datasets: tuple
    replay_interval: float
    sensor_id: str
    zeek_stale_seconds: int

def load_settings():
    secret = required('JWT_SECRET_KEY')
    if len(secret) < 32 or secret.lower().startswith(('change', 'replace')):
        raise RuntimeError('JWT_SECRET_KEY must be a randomly generated secret of at least 32 characters')
    origins = tuple(x.strip() for x in os.getenv('CORS_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173').split(',') if x.strip())
    if not origins or '*' in origins:
        raise RuntimeError('CORS_ORIGINS must list explicit application origins')
    sources = tuple(x.strip() for x in os.getenv('MONITORING_DATASETS', '').split(',') if x.strip())
    if set(sources) - {'cicids2017', 'unsw-nb15', 'live_network'}:
        raise RuntimeError('Unsupported MONITORING_DATASETS value')
    minutes = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '60'))
    interval = float(os.getenv('REPLAY_INTERVAL_SECONDS', '1'))
    stale_seconds = int(os.getenv('ZEEK_STALE_SECONDS', '120'))
    if not 1 <= minutes <= 1440 or not 0 <= interval <= 60:
        raise RuntimeError('Invalid token lifetime or replay interval')
    if not 1 <= stale_seconds <= 86400:
        raise RuntimeError('ZEEK_STALE_SECONDS must be between 1 and 86400')
    sensor_id = os.getenv('SENSOR_ID', 'local-sensor').strip()
    if not sensor_id or len(sensor_id) > 128:
        raise RuntimeError('SENSOR_ID must contain 1 to 128 characters')
    return Settings(
        required('DATABASE_URL'), os.getenv('MONGO_URL') or required('MONGO_URI'),
        secret, minutes, origins,
        Path(os.getenv('MODEL_DIR', str(BACKEND_DIR))),
        Path(os.getenv('DATA_DIR', str(BACKEND_DIR.parent / 'ml/data/processed'))),
        Path(os.getenv('ZEEK_LOG_PATH', '/var/log/zeek/conn.log')),
        sources, interval, sensor_id, stale_seconds,
    )

settings = load_settings()
