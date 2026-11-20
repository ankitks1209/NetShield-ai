# NetShield AI

NetShield AI combines authenticated flow monitoring, supervised dataset classification, and persistent incident triage. The existing Apple-style glassmorphism interface is preserved.

This version repairs the security and ingestion foundation. It does **not** claim validated live intrusion classification, zero-day prediction, lossless capture, or production accuracy.

## Data paths

- **CICIDS2017 / UNSW-NB15 replay:** one collector per configured dataset processes every row once per API process. Viewers subscribe to results; opening or closing a browser does not start or stop collection.
- **Live Zeek:** reads standard JSON or TSV `conn.log`, preserves endpoint direction, UTC event time, duration in seconds, payload bytes, IP bytes, and packet counts. Complete-line checkpoints are saved after durable flow writes. Rotation and copy-truncation are handled; malformed and incomplete records are reported.
- **REST inference:** uses the same model input contract and persistent incident service as replay.
- **Simulations:** marked explicitly, excluded from operational metrics by default, and never sent to webhooks.

Live Zeek records currently carry an **UNKNOWN** verdict. The old four-field/zero-filled CICIDS vector was invalid and has been removed. A tested Zeek-specific feature/model pipeline is required before enabling live classification. Completed Zeek connection logs are flow records, not a per-packet feed: long-lived connections may be logged later than individual packets.

## Requirements and setup

Use Docker Compose v2, or Python with the backend requirements and a Node version supported by the checked-in Vite version. The backend Docker image uses Python 3.12; the frontend builder uses Node 20. Existing model files are trusted joblib artifacts and must be supplied locally; never load untrusted joblib/pickle files.

The following files are intentionally excluded from Git:

- `backend/rf_model_optimized.joblib` and `backend/label_encoder.joblib`
- `backend/xgboost_unsw_model.joblib` and `backend/label_encoder1.joblib`
- `ml/data/processed/cicids2017_clean.csv` and `ml/data/processed/unsw_nb15_clean.csv`
- Secret environment files, captures, virtual environments, and sensor logs.

A fresh clone needs these artifacts before starting the current Compose configuration. A reproducible training/export pipeline remains a separate milestone.

### Docker deployment

1. Copy `.env.example` to `.env`. Preserve any existing private configuration before replacing it.
2. Generate **different** random values for JWT_SECRET_KEY, POSTGRES_PASSWORD, and MONGO_PASSWORD. Use hex secrets so they can safely appear in connection URLs:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

3. Configure monitoring sources. Empty MONITORING_DATASETS disables collection; `cicids2017,unsw-nb15` enables both finite replays.
4. Validate and start:

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
```

5. Open [NetShield AI locally](http://localhost:5173). The application uses same-origin API and WebSocket proxies. Databases and the backend are private to the Compose network; no database ports are published.
6. Provision an administrator explicitly:

```bash
docker compose exec backend python bootstrap_admin.py --email admin@example.com --username admin --name "SOC Administrator"
```

The command prompts for a password without printing it. It creates or promotes the specified account and invalidates that account's previous access tokens. Public registration only grants analyst access.

The frontend is bound to localhost. For remote access, configure a TLS reverse proxy and explicit CORS_ORIGINS. Use a single backend worker: the collector/broadcast coordinator is process-local. Multiple replicas require a shared worker/broker and shared rate limiter.

PostgreSQL and MongoDB use named volumes. Changing initialization passwords does not update credentials in existing volumes. Back up existing data and migrate accounts deliberately; do not delete volumes to fix authentication. The current Compose Mongo application account is the initialization administrator; provision a database-scoped account before production deployment.

### Direct local development

Configure DATABASE_URL, MONGO_URI (or legacy MONGO_URL), JWT_SECRET_KEY, and explicit CORS_ORIGINS in your private environment. Settings load root `.env` and then `backend/.env` without overriding existing environment variables. Avoid conflicting MONGO_URL/MONGO_URI definitions.

```bash
python3 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements.txt
cd backend
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

In another terminal, from Frontend:

```bash
npm ci
npm run dev
```

Vite proxies /api and /ws to localhost:8000. VITE_API_BASE_URL is optional; if specified, it must point to the intended backend and its origin must be allowed. HTTPS pages derive wss:// automatically.

## Zeek sensor configuration

Capture traffic on a host/interface you administer. A Mac running Docker Desktop does not automatically expose its Wi-Fi traffic to a container. For network-wide visibility, deploy a sensor on a mirrored/SPAN port, TAP, or other authorized observation point.

Run Zeek on that sensor, writing to a dedicated log directory. For example, after choosing the actual capture interface and obtaining capture permissions:

```bash
mkdir -p sensor-logs
cd sensor-logs
# Substitute the actual authorized interface.
sudo zeek -i en0 /absolute/path/to/NetShield-ai/sensor/netshield.zeek
```

Standard Zeek TSV also works; JSON is not required. Set ZEEK_LOG_DIR to the **absolute directory**, not the individual file, and run:

```bash
docker compose -f docker-compose.yml -f compose.zeek.yml config --quiet
docker compose -f docker-compose.yml -f compose.zeek.yml up -d --build
```

For direct Python execution, set MONITORING_DATASETS=live_network, ZEEK_LOG_PATH to conn.log, and a unique SENSOR_ID. The reader starts at the beginning when there is no valid checkpoint; after restart it resumes from the last persisted complete line. It reads the new file from the beginning after rotation and drains the old descriptor first. Stable sensor/UID/event-time identifiers make replayed writes idempotent.

The supplied sensor policy enables JSON connection logs, `stats.log` every 10 seconds, and TCP-gap estimates in `capture_loss.log`. Both JSON and standard TSV are supported by the reader. The log directory must be readable by the backend runtime user.

Check the authenticated /api/network/status response for processed counts, last flow event time, malformed-line count, waiting/unavailable state, stale data, and future-clock detection. `sources.live_network.capture_health` contains per-peer capture counters and TCP-gap estimates, with separate freshness and error states. `pkts_dropped` is a local capture counter for the latest reporting interval; an absent field remains unmeasured. `percent_lost` is already a percentage, and is an estimate from TCP ACK gaps rather than a local NIC drop counter. An interval without TCP ACKs has insufficient evidence, even if Zeek logs a zero value. These meanings follow the [Zeek statistics schema](https://docs.zeek.org/en/v8.2.1/scripts/policy/misc/stats.zeek.html) and [capture-loss schema](https://docs.zeek.org/en/v8.2.1/scripts/policy/misc/capture-loss.zeek.html).

ZEEK_STALE_SECONDS defaults to 120. Current stats measurements keep a quiet sensor distinguishable from a stalled connection log; old or missing health measurements never imply lossless capture. Measurements and cursors are persisted together for health logs. On restart, the reader can drain an unread renamed log when its original inode is still available in the same directory; compressed/deleted rotations cannot be recovered automatically and produce an explicit possible-gap diagnostic. Keep uncompressed rotations until ingestion has caught up.

### Bounded capture verification

For a local 60-second observation on this Mac's `en0`, use a new/empty directory:

```bash
sudo /opt/homebrew/bin/python3 backend/capture_sensor.py \
  --interface en0 --duration 60 --zeek /opt/homebrew/bin/zeek \
  --output /tmp/netshield-live-check
```

The tool stops Zeek, waits for final connection records to flush, and writes `sensor-report.json` with aggregate flow/packet counts, capture telemetry, errors, and unread/incomplete-byte counts. It never asks for or stores a password; macOS sudo handles authorization in your terminal. On other installations, substitute the actual Python, Zeek, and interface paths. Ordinary Zeek logs may contain sensitive metadata and stay in the local output directory; the JSON report omits endpoint addresses and packet payloads. No raw PCAP is written.

To observe an already-running sensor without capture privileges or database credentials:

```bash
python3 backend/sensor_audit.py --log-dir /absolute/path/to/logs \
  --duration 60 --output /tmp/netshield-sensor-report.json
```

This defaults to newly appended records; add `--from-start` to include existing history. Keep log ingestion timing separate from actual NIC capture capacity. Offline PCAP tests establish parser/count correctness, not zero packet loss on a live network.

## Detection and incident behavior

All operational API routes require a valid token. Admin permissions are required for account administration, settings, audit views, and model operations. Suspension is enforced on every authenticated request, including periodic WebSocket revalidation. Password changes invalidate existing tokens. Login throttling is bounded and process-local.

WebSockets authenticate in their first frame before receiving telemetry; long-lived credentials are not included in URLs. The frontend connects only after authentication, clears access on logout, and reconnects with backoff. A slow subscriber receives an explicit resynchronization signal and reloads durable incidents.

Feature lengths, names, target exclusion, supported datasets, numeric conversion, and finite values are checked. Invalid features return 422; offline/failed inference returns 503, never BENIGN. The legacy UNSW model expects 194 encoded columns; a compatibility adapter reconstructs its documented one-hot input schema. It is not a reproduced or independently validated training pipeline.

Each anomalous result has a canonical server incident ID, actual model confidence, model version, and severity based on attack type. Priority is a documented incident-severity heuristic, not a future attack probability. Incidents support assignment to active users, validated status values, actor-attributed notes/history, and authenticated CSV exports. Simulations can be included explicitly with include_simulated=true. Export limits are explicit rather than silently truncating records; CSV formula cells are escaped.

Optional SECURITY_WEBHOOK_URL enables high/critical incident delivery. HTTPS is required outside localhost. Delivery state and bounded retries are persisted. Simulations never notify; replay only notifies when NOTIFY_REPLAY=true. Delivery is at least once: a crash after remote delivery but before recording success can cause a duplicate. The incident ID is included as an idempotency key.

MFA, invitation delivery, automatic firewall response, runtime settings changes, and online retraining remain unavailable. Their controls retain the existing design but cannot claim successful execution. Saved benchmark scores are labeled as legacy results rather than production accuracy.

## Verification

From the repository root:

```bash
backend/.venv/bin/python -m unittest discover -s backend/tests -v
cd Frontend
npm run lint
npm run build
```

If using the existing local backend/venv, substitute that interpreter path. Tests use isolated SQLite, an in-memory Mongo substitute, controlled models, and synthetic traffic. They never use production databases. When Zeek is installed, an integration test creates a synthetic two-packet PCAP, runs the real Zeek executable offline in JSON and TSV modes, and verifies equivalent normalized flow data. No test packets are sent over the network.

The existing local model artifacts load and produce sample predictions, but emit scikit-learn/XGBoost serialization-version warnings. Re-export/retrain models in a pinned, reproduced environment before treating their results as production validated.

Docker configuration was reviewed statically in this development environment; Docker itself was unavailable. Real PostgreSQL/Mongo deployment, sustained capture, packet-loss measurement, backup/restore, held-out ML evaluation, and cloud deployment remain to be validated.

## Next milestones

1. Reproduce training and held-out evaluation, preserve the UNSW official split, remove row identifiers as learning features, export preprocessing with each estimator, and publish per-class recall/F1, confusion matrices, false-positive rates, and artifact/runtime versions.
2. Train/evaluate against the exact Zeek feature contract before enabling live attack verdicts.
3. Complete live-interface sustained validation, retention enforcement, schema migrations, backup/restore verification, least-privilege database provisioning, and shared multi-instance coordination. Capture health ingestion is implemented; live capture capacity still needs measurement on the intended deployment.
4. Complete real invitations/MFA and controlled response integrations only with their full backend lifecycle.

The original audit is preserved in PROJECT_REVIEW.md. The pre-improvement recovery point is Git tag `pre-improvements-2026-11-01`.
