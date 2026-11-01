"""NetShield API: authenticated operations backed by shared detection services."""
import asyncio
from collections import Counter, OrderedDict
from contextlib import asynccontextmanager
import csv
from datetime import datetime, timezone
import io
import json
import logging
import threading
import time

from bson import ObjectId
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.exceptions import RequestValidationError
from pymongo.errors import PyMongoError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from auth_utils import create_access_token, hash_password, password_version, verify_password
from config import settings
from database import Base, engine, get_db
from detection import detector, InvalidFeatures, ModelUnavailable
from models import AuditLog, User
import mongodb as storage
from pipeline import persist_detection, process_detection
from schemas import (
    InviteRequest, LoginRequest, PasswordUpdateRequest, PredictionRequest, ProfileUpdateRequest,
    RegisterRequest, TokenResponse, UpdateAlertRequest, UserResponse, UserUpdateRequest,
)
from security import get_current_user, normalize_role, require_admin
from traffic import broker, router as traffic_router
from notifications import notification_worker, webhook_url

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app):
    webhook_url()  # Reject insecure notification URLs before starting collectors.
    await asyncio.to_thread(Base.metadata.create_all, bind=engine)
    await asyncio.to_thread(detector.load)
    try:
        await asyncio.to_thread(storage.ensure_indexes)
    except PyMongoError:
        logger.exception('Storage indexes unavailable; collectors will retry persistence')
    await broker.start()
    notification_task = asyncio.create_task(notification_worker())
    try:
        yield
    finally:
        await broker.stop()
        notification_task.cancel()
        await asyncio.gather(notification_task, return_exceptions=True)

app = FastAPI(title='NetShield AI Backend', version='3.1.0', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.origins), allow_credentials=True,
                   allow_methods=['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS'], allow_headers=['Authorization', 'Content-Type', 'Cache-Control', 'Pragma'])
api = APIRouter(prefix='/api', dependencies=[Depends(get_current_user)])
app.include_router(traffic_router)

@app.exception_handler(RequestValidationError)
async def invalid_request(request, exc):
    # Do not echo passwords, arbitrary payloads, or non-JSON NaN/Inf values.
    errors = [{key: error[key] for key in ('loc', 'msg', 'type')} for error in exc.errors()]
    return JSONResponse(status_code=422, content={'detail': errors})

@app.exception_handler(PyMongoError)
async def mongo_unavailable(request, exc):
    logger.error('MongoDB operation failed: %s', type(exc).__name__)
    return JSONResponse(status_code=503, content={'detail': 'Incident storage is unavailable; retry later'})

@app.exception_handler(SQLAlchemyError)
async def sql_unavailable(request, exc):
    logger.error('SQL operation failed: %s', type(exc).__name__)
    return JSONResponse(status_code=503, content={'detail': 'Account storage is unavailable; retry later'})

def audit(db, user, action, target, details=None):
    db.add(AuditLog(user_id=user.id, action=action, target=target, details=details))

def user_payload(user):
    return {**UserResponse.model_validate(user).model_dump(), 'role': normalize_role(user.role)}

# Bounded, process-local throttling. Use an edge/shared limiter for multi-instance deployments.
attempts = OrderedDict()
attempt_lock = threading.Lock()

def throttle(request, identity, limit=10):
    key = (request.client.host if request.client else 'unknown', identity.lower())
    now = time.monotonic()
    with attempt_lock:
        bucket = [t for t in attempts.pop(key, []) if now - t < 300]
        if len(bucket) >= limit:
            attempts[key] = bucket
            raise HTTPException(429, 'Too many attempts; try again later', headers={'Retry-After': '300'})
        attempts[key] = [*bucket, now]
        while len(attempts) > 5000:
            attempts.popitem(last=False)

@app.get('/health')
def health_check():
    return {'status': 'ok', 'service': 'NetShield AI Backend', 'version': '3.1.0'}

@api.get('/ready')
def readiness(db: Session = Depends(get_db)):
    db.execute(text('SELECT 1'))
    storage.client.admin.command('ping')
    return {'status': 'ready', 'models_active': {name: name in detector.engines for name in ['cicids2017', 'unsw-nb15']},
            'sources': broker.snapshot()}

@app.post('/api/auth/register', response_model=UserResponse)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    throttle(request, 'register', 10)
    email = str(payload.email).lower()
    if db.query(User).filter((User.email == email) | (User.username == payload.username)).first():
        raise HTTPException(409, 'Email or username already registered')
    user = User(full_name=payload.full_name.strip(), username=payload.username, email=email,
                hashed_password=hash_password(payload.password), role='analyst')
    db.add(user)
    try:
        db.flush()
        audit(db, user, 'USER_REGISTERED', user.username)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Email or username already registered')
    db.refresh(user)
    return user

@app.post('/api/auth/login', response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    throttle(request, str(payload.email))
    user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if not user or not user.is_active or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(401, 'Invalid email or password')
    if normalize_role(user.role) not in {'analyst', 'administrator'}:
        raise HTTPException(401, 'Invalid email or password')
    audit(db, user, 'USER_LOGIN', 'Authentication')
    db.commit()
    token = create_access_token({'sub': str(user.id), 'pv': password_version(user.hashed_password)})
    return {'access_token': token, 'token_type': 'bearer', 'user': user_payload(user)}

@api.get('/auth/me')
def current_account(user: User = Depends(get_current_user)):
    return {'user': user_payload(user)}

@api.get('/admin/audit-logs')
def get_audit_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return {'status': 'success', 'logs': [
        {'id': row.id, 'user_id': row.user_id, 'action': row.action, 'target': row.target,
         'details': row.details, 'timestamp': row.timestamp.replace(tzinfo=row.timestamp.tzinfo or timezone.utc).isoformat()}
        for row in rows]}

def run_prediction(payload, simulated=False):
    try:
        if payload.force_attack:
            if not simulated:
                raise HTTPException(422, 'Synthetic attacks are only available in the simulation endpoint')
            return persist_detection({
                'status': 'success', 'analysis_status': 'simulated', 'dataset_used': payload.dataset,
                'ai_classification': 'Simulated DDoS', 'prediction': 'Simulated DDoS', 'is_anomaly': True,
                'confidence': None, 'confidence_raw': None, 'severity': 'High', 'model_version': None,
            }, 'Analyst simulation', source_mode='simulation', simulated=True)
        return process_detection(payload.dataset, payload.features, payload.source_ip,
                                 source_mode='simulation' if simulated else 'api', simulated=simulated)
    except InvalidFeatures as exc:
        raise HTTPException(422, str(exc))
    except ModelUnavailable as exc:
        raise HTTPException(503, str(exc))

@api.post('/predict')
def predict_threat(payload: PredictionRequest):
    return run_prediction(payload)

@api.post('/predict-manual')
def predict_manual_packet(payload: PredictionRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = run_prediction(payload, simulated=True)
    audit(db, user, 'SIMULATED_DETECTION', result['event_id'], 'Excluded from operational metrics')
    db.commit()
    return result

@api.get('/model-metrics/{dataset}')
def get_model_metrics(dataset: str):
    names = {'cicids2017': 'cicids_metrics.json', 'unsw-nb15': 'unsw_metrics.json'}
    if dataset not in names:
        raise HTTPException(422, 'Select CICIDS2017 or UNSW-NB15 to view a saved benchmark')
    path = settings.model_dir / names[dataset]
    if not path.is_file(): raise HTTPException(404, 'Saved benchmark is unavailable')
    return {**json.loads(path.read_text()), 'provenance': 'Legacy saved benchmark; evaluation has not been reproduced'}

def alert_query(include_simulated=False):
    return {} if include_simulated else {'simulated': {'$ne': True}}

@api.get('/alerts/history')
def get_alert_history():
    return {'status': 'success', 'anomalies': [storage.serialize(x) for x in storage.incident_logs.find(alert_query()).sort('timestamp', -1).limit(50)]}

@api.get('/alerts')
def get_soc_alerts(status: str | None = None, include_simulated: bool = False,
                   limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=50000)):
    query = alert_query(include_simulated)
    if status:
        if status not in {'Open', 'Investigating', 'False Positive', 'Closed'}:
            raise HTTPException(422, 'Unsupported incident status')
        query['status'] = status
    count = storage.incident_logs.count_documents(query)
    rows = storage.incident_logs.find(query).sort('timestamp', -1).skip(offset).limit(limit)
    return {'status': 'success', 'alerts': [storage.serialize(x) for x in rows],
            'total': count, 'limit': limit, 'offset': offset}

@api.patch('/alerts/{alert_id}')
def update_alert_status(alert_id: str, payload: UpdateAlertRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not ObjectId.is_valid(alert_id): raise HTTPException(400, 'Invalid incident ID')
    updates = {key: value for key, value in payload.model_dump(exclude_none=True).items() if key != 'note'}
    if payload.assignee is not None and payload.assignee != 'Unassigned':
        if not payload.assignee.isdecimal() or not db.query(User).filter(User.id == int(payload.assignee), User.is_active.is_(True)).first():
            raise HTTPException(422, 'Choose an active team member as assignee')
    if not updates and not payload.note: raise HTTPException(400, 'No changes supplied')
    now = storage.utcnow().isoformat()
    trail = {'timestamp': now, 'actor_id': user.id, 'changes': updates}
    query = {'$push': {'audit_history': trail}}
    if updates: query['$set'] = updates
    if payload.note: query['$push']['investigation_notes'] = {'timestamp': now, 'actor_id': user.id, 'note': payload.note}
    result = storage.incident_logs.update_one({'_id': ObjectId(alert_id)}, query)
    if not result.matched_count: raise HTTPException(404, 'Incident not found')
    return {'status': 'success', 'incident': storage.serialize(storage.incident_logs.find_one({'_id': ObjectId(alert_id)}))}

@api.post('/alerts/acknowledge-all')
def acknowledge_all_alerts(user: User = Depends(get_current_user)):
    result = storage.incident_logs.update_many(
        {**alert_query(), 'status': 'Open'},
        {'$set': {'status': 'Investigating'},
         '$push': {'audit_history': {'timestamp': storage.utcnow().isoformat(), 'actor_id': user.id, 'changes': {'status': 'Investigating'}}}})
    return {'status': 'success', 'modified_count': result.modified_count}

@api.get('/alerts/context/{source_ip}')
def get_ip_context(source_ip: str, limit: int = Query(100, ge=1, le=500)):
    query = {**alert_query(), 'source': source_ip}
    count = storage.incident_logs.count_documents(query)
    rows = [storage.serialize(x) for x in storage.incident_logs.find(query).sort('timestamp', -1).limit(limit)]
    return {'status': 'success', 'source_ip': source_ip, 'history_count': count, 'incidents': rows,
            'critical_incidents': storage.incident_logs.count_documents({**query, 'severity': 'Critical'}),
            'attack_types_seen': storage.incident_logs.distinct('type', query)}

@api.get('/network/stats')
def get_network_stats():
    query = alert_query()
    active = {**query, 'status': {'$in': ['Open', 'Investigating']}}
    critical = storage.incident_logs.count_documents({**active, 'severity': {'$in': ['Critical', 'High']}})
    # Explicit prioritization heuristic, not an attack probability.
    peak = next((score for severity, score in [('Critical', 100), ('High', 75), ('Medium', 50)]
                 if storage.incident_logs.count_documents({**active, 'severity': severity})), 0)
    return {'status': 'success', 'totalScanned': storage.packet_logs.count_documents({**query, 'analyzed': True}),
            'totalCaptured': storage.packet_logs.count_documents(query),
            'totalDeviations': storage.incident_logs.count_documents(query), 'criticalAnomalies': critical,
            'riskScore': peak, 'risk_method': 'Highest open-incident severity; not a probability',
            'sources': broker.snapshot(), 'unit': 'flows'}

@api.get('/network/status')
def network_status():
    return {'status': 'success', 'sources': broker.snapshot()}

@api.get('/alerts/trends')
def get_threat_trends(attack_type: str | None = None):
    query = alert_query()
    if attack_type and attack_type != 'All': query['type'] = attack_type
    pipeline = [
        {'$match': query},
        {'$group': {'_id': {'$dateToString': {'format': '%G-W%V', 'date': '$timestamp', 'timezone': 'UTC'}},
                    'total_attacks': {'$sum': 1},
                    'high_critical_attacks': {'$sum': {'$cond': [{'$in': ['$severity', ['Critical', 'High']]}, 1, 0]}}}},
        {'$sort': {'_id': -1}}, {'$limit': 52}, {'$sort': {'_id': 1}},
    ]
    rows = list(storage.incident_logs.aggregate(pipeline))
    return {'status': 'success', 'labels': [x['_id'] for x in rows],
            'total_data': [x['total_attacks'] for x in rows], 'critical_data': [x['high_critical_attacks'] for x in rows],
            'available_types': storage.incident_logs.distinct('type', alert_query())}

@api.get('/alerts/matrix')
def get_threat_matrix():
    rows = list(storage.incident_logs.aggregate([
        {'$match': alert_query()}, {'$group': {'_id': {'source': '$source', 'type': '$type'}, 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}}, {'$limit': 1000},
    ]))
    ips, types = Counter(), Counter()
    for row in rows:
        ips[row['_id']['source']] += row['count']
        types[row['_id']['type']] += row['count']
    assets = [key for key, _ in ips.most_common(3)]
    vectors = [key for key, _ in types.most_common(3)]
    counts = {(x['_id']['source'], x['_id']['type']): x['count'] for x in rows}
    return {'status': 'success', 'assets': assets, 'vectors': vectors, 'measure': 'Observed share, not future probability',
            'matrix': [[round(counts.get((ip, kind), 0) / ips[ip], 3) for kind in vectors] for ip in assets]}

@api.get('/alerts/forecast')
def get_threat_forecast():
    return {'status': 'unavailable', 'labels': [], 'data': [], 'message': 'Intrusion forecasting has not been validated'}

@api.get('/models/retrain-status')
def get_retraining_status():
    return {'is_active': False, 'current_step': 0, 'status_text': 'Retraining is not available', 'supported': False}

@api.post('/models/retrain')
def trigger_global_retraining(admin: User = Depends(require_admin)):
    raise HTTPException(501, 'Retraining requires a versioned training and validation pipeline')

@api.get('/models/telemetry')
def get_model_telemetry():
    models = []
    for dataset, name in [('cicids2017', 'Random Forest (CICIDS2017)'), ('unsw-nb15', 'XGBoost (UNSW-NB15)')]:
        loaded = detector.engines.get(dataset)
        models.append({'id': dataset, 'name': name, 'version': loaded.version if loaded else 'Unavailable',
                       'type': 'Supervised classification', 'accuracy': None,
                       'status': 'Loaded' if loaded else 'Offline', 'latency': 'Not measured', 'lastUpdated': 'Startup load'})
    return {'status': 'success', 'global_accuracy': 'Not verified', 'active_models_count': len(detector.engines),
            'inference_latency': 'Per-event timing', 'models': models}

@api.get('/users')
def get_all_users(db: Session = Depends(get_db)):
    return {'status': 'success', 'users': [{**user_payload(x), 'is_active': x.is_active} for x in db.query(User).all()]}

@api.post('/users/invite')
def invite_team_member(payload: InviteRequest, admin: User = Depends(require_admin)):
    raise HTTPException(501, 'Invitations are not available yet; users can register as analysts')

@api.put('/users/profile')
def update_user_profile(payload: ProfileUpdateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    if db.query(User).filter(User.email == email, User.id != user.id).first():
        raise HTTPException(409, 'Email is already registered')
    user.full_name, user.email = payload.full_name.strip(), email
    audit(db, user, 'PROFILE_UPDATED', user.username)
    db.commit()
    return {'status': 'success', 'user': user_payload(user)}

@api.put('/users/password')
def update_user_password(payload: PasswordUpdateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.hashed_password): raise HTTPException(400, 'Incorrect current password')
    user.hashed_password = hash_password(payload.new_password)
    audit(db, user, 'PASSWORD_CHANGED', user.username, 'Existing access tokens invalidated')
    db.commit()
    return {'status': 'success', 'message': 'Password changed. Sign in again.'}

@api.get('/users/sessions')
def get_user_sessions(request: Request, user: User = Depends(get_current_user)):
    return {'status': 'success', 'sessions': [{'id': 'current', 'device': request.headers.get('user-agent', 'Current browser'),
            'location': 'Not determined', 'ip': request.client.host if request.client else 'Unknown',
            'time': 'Current request', 'active': True}], 'message': 'Session inventory is not implemented'}

@api.put('/users/{target_user_id}')
def update_user_management(target_user_id: int, payload: UserUpdateRequest, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    # Lock active users so two administrators cannot simultaneously remove all admins.
    users = db.query(User).order_by(User.id).with_for_update().all()
    target = next((x for x in users if x.id == target_user_id), None)
    if not target: raise HTTPException(404, 'User not found')
    removes_admin = normalize_role(target.role) == 'administrator' and target.is_active and (not payload.is_active or payload.role != 'administrator')
    admins = sum(x.is_active and normalize_role(x.role) == 'administrator' for x in users)
    if removes_admin and (target.id == admin.id or admins <= 1):
        raise HTTPException(409, 'Cannot remove your own access or the final active administrator')
    target.role, target.is_active = payload.role, payload.is_active
    audit(db, admin, 'USER_MODIFIED', str(target.id), f'role={payload.role}; active={payload.is_active}')
    db.commit()
    return {'status': 'success', 'message': 'User updated'}

@api.get('/system/settings')
def get_system_settings(admin: User = Depends(require_admin)):
    return {'status': 'success', 'settings': {'tokenExpiryMinutes': settings.token_minutes,
            'monitoringSources': list(settings.monitoring_datasets), 'mfaEnabled': False, 'autoBanEnabled': False,
            'retrainingSupported': False, 'invitationsSupported': False, 'retentionEnforced': False},
            'editable': False}

@api.put('/system/settings')
def update_system_settings(admin: User = Depends(require_admin)):
    raise HTTPException(501, 'Runtime configuration changes are not supported')

@api.get('/system/devices')
def get_system_devices(db: Session = Depends(get_db)):
    devices = [{'id': 'api', 'name': 'NetShield API', 'ip': 'Application', 'mac': '-', 'type': 'API',
                'status': 'Online', 'load': 'Not measured'}]
    for key, name, probe in [('sql', 'Accounts database', lambda: db.execute(text('SELECT 1'))),
                              ('mongo', 'Incident database', lambda: storage.client.admin.command('ping'))]:
        try:
            probe()
            state = 'Online'
        except (SQLAlchemyError, PyMongoError):
            db.rollback()
            state = 'Unavailable'
        devices.append({'id': key, 'name': name, 'ip': 'Private service', 'mac': '-', 'type': 'Database', 'status': state, 'load': 'Not measured'})
    return {'status': 'success', 'devices': devices}

@api.get('/logs')
def get_unified_system_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    logs = [{'id': str(row.id), 'timestamp': row.timestamp.replace(tzinfo=row.timestamp.tzinfo or timezone.utc).isoformat(),
             'source': 'Audit', 'level': 'INFO', 'message': f'{row.action}: {row.target}'}
            for row in db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100)]
    return {'status': 'success', 'logs': logs}

def csv_cell(value):
    value = '' if value is None else str(value)
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value

@api.get('/alerts/export')
def export_alerts_csv(include_simulated: bool = False, limit: int = Query(1000, ge=1, le=10000),
                      user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = alert_query(include_simulated)
    count = storage.incident_logs.count_documents(query)
    if count > limit: raise HTTPException(422, f'{count} incidents exceed the export limit of {limit}; increase limit up to 10000')
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(['Timestamp UTC', 'Threat Vector', 'Source', 'Severity', 'Confidence', 'Assignee', 'Status', 'Simulated', 'Incident ID'])
    for raw in storage.incident_logs.find(query).sort('timestamp', -1).limit(limit):
        doc = storage.serialize(raw)
        writer.writerow([csv_cell(doc.get(key)) for key in ['timestamp', 'type', 'source', 'severity', 'confidence', 'assignee', 'status', 'simulated', 'id']])
    audit(db, user, 'EXPORT_INCIDENTS', 'CSV', f'{count} incidents')
    db.commit()
    return StreamingResponse(iter([stream.getvalue()]), media_type='text/csv',
                             headers={'Content-Disposition': 'attachment; filename=netshield-incidents.csv'})

app.include_router(api)
