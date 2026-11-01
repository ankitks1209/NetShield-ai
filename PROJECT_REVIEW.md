# NetShield AI project review

Reviewed: 1 November 2026. Scope: repository source, frontend routes and state, backend endpoints, database models, preprocessing scripts, deployment files, locally available trained models and dataset headers, and the supplied 10-page project specification.

## Assessment

This is a substantial prototype with React screens, working password hashing and JWT issuance, SQL user/audit models, MongoDB incident APIs, locally loadable Random Forest and XGBoost artifacts, and a frontend that builds. However, the implementation only partially fulfills the specification's operational requirements. The current version should not be described as a reliable, continuously operating security monitoring product.

The main problems are authorization, inconsistent model inputs, the gap between stream detection and incident persistence, deployment configuration, and displays that present simulated or fixed values as measured facts. Resolve these before adding more screens or integrations. No application fixes were made during this review. The pre-existing modification to docker-compose.yml was preserved.

## What was verified

| Check | Result | Limits |
| --- | --- | --- |
| Extract and read all 10 PDF pages | Complete; architecture page rendered and inspected | Diagram integrations are distinguished from the explicit milestone outcomes |
| Frontend production build | Passed | Existing installed dependencies; not a clean container build |
| Frontend lint | Failed: 51 errors, 4 warnings across 35 checked files | 40 errors are unused variables; the rest include hook/state, purity, empty catch, and refresh rules |
| Python source parsing | Passed for all 13 backend/ML Python source files | Syntax validation does not prove runtime correctness |
| Local ML artifact loading | Both classifiers, both label encoders, and feature list loaded | Does not reproduce their original training or validate reported accuracy |
| Real first-row CICIDS inference using the stream's input construction | Succeeded | Single sample, not an accuracy evaluation |
| Real first-row UNSW inference using the stream's input construction | Failed with invalid raw string columns | Stream then labels such inference failures BENIGN |
| Isolated backend behavior checks | Confirmed authorization, error handling, replay, persistence, and fabricated-counter issues below | In-memory SQLite and fake MongoDB; no production database writes |
| Docker Compose execution | Not run: Docker executable unavailable | YAML and service configuration inspected statically |

The isolated checks exercised the actual FastAPI app through ASGI, with database dependencies substituted locally. Stream checks used temporary CSV fixtures and fake sockets. Model loading and sample inference were separately checked against the real local artifacts. No deployed cloud installation, live capture interface, browser layout, full held-out evaluation, notification delivery, or production database behavior was validated. Dependency vulnerability scanning and clean dependency installation were not performed.

## Comparison with the PDF

The PDF defines seven functional modules, four implementation milestones, and model/security/system performance measurements. Merely having a route or screen is insufficient to count the corresponding workflow as complete.

| PDF requirement | Current implementation | Assessment |
| --- | --- | --- |
| User management: login, RBAC, teams, audit | Login/password hashing/JWT and SQL audit records exist; role selection is public, suspension is not enforced, invitations are acknowledgments without invitation delivery | Partial; security blockers |
| Network monitoring: collection, protocols, visualization | CSV replay and Zeek log tailing exist; replay loses most rows; live source is not provisioned by Compose; protocol graph includes seed counts | Partial; unreliable pipeline |
| Anomaly detection: behavior analysis, classification | Two supervised classifiers load locally; CICIDS sample inference works; UNSW preprocessing and live feature construction are incorrect | Partial; live detection not validated |
| Intrusion prediction: probability, risk, forecasting | Class confidence is used as severity; network risk and forecast are formulas, with no validated forecasting model | Mostly demonstration logic |
| Alert management: alerts, priority, incidents, notifications | MongoDB incident CRUD and optional webhook code exist; stream detections do not create incidents or call notification dispatch | Partial; end-to-end gap |
| Analytics: traffic, threat reports, metrics, trends | Several screens and CSV exports exist; weekly aggregation exists; counters, health displays, and some graphs are synthetic; no external threat enrichment found | Partial |
| AI detection: training, classification, behavioral analysis | Trained local artifacts exist; only data exploration/cleaning scripts are tracked; retraining API does not train | Partial; not reproducible |
| Final testing, Docker/cloud deployment, documentation | Frontend builds; lint fails; test scripts do not verify correctness; Compose has blockers; README overstates behavior | Milestone 4 not demonstrated by this checkout |

The architecture diagram also lists SIEM/SOAR, threat feeds, reputation, enrichment, monitoring, and other infrastructure. These are useful future integrations, but building every box is not necessary for a credible first release. Complete the explicit end-to-end outcomes first. Neither TensorFlow nor Kubernetes is needed merely to add another technology name.

## Critical findings

### 1. Public registration grants administrator privileges

Evidence: [registration handler](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:181), [registration schema](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/schemas.py:4), and [registration UI](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/register.jsx:22).

The server stores the role supplied by an unauthenticated caller. In the isolated app, registering with the administrator role returned HTTP 200, logging in succeeded, and the resulting account accessed the admin audit endpoint with HTTP 200. Hiding the role selector in React would not fix this.

Fix: set the public registration role on the server to a single restricted role, or require invitations. Bootstrap the first administrator through a controlled setup command. Restrict later role changes to authorized admins and validate roles against an enum. Prevent accidental removal of the final active administrator.

Acceptance: caller-supplied privileged roles are rejected or ignored; a new public account cannot access any admin action.

### 2. Operational APIs and the traffic WebSocket lack authorization

Evidence: [alert mutation](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:471), [user listing](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:607), [settings mutation](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:702), and [WebSocket entry](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:55).

Anonymous isolated requests could list users, edit settings, patch an incident, acknowledge incidents in bulk, inject a simulated threat, and receive an invitation-success response. Other telemetry, export, retraining, and alert-read routes also lack an authentication dependency. React route protection does not secure backend endpoints.

Fix: define a server-side permission matrix. Require authentication for operational reads and streams, analyst permissions for authorized incident updates, and admin permissions for settings, invitations, and model operations. Authenticate the WebSocket handshake, enforce allowed origins, and limit connections. If supporting multiple organizations, scope every query and stream by organization.

Acceptance: anonymous requests fail with 401; authenticated users without the required role receive 403; unauthorized streams are refused before telemetry is sent. Update the frontend API client to send credentials consistently when the backend is secured.

### 3. Signing material and a credential-bearing database fallback are embedded in source

Evidence: [JWT signing configuration](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/auth_utils.py:18), [JWT verification configuration](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:140), and [MongoDB configuration](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/mongodb.py:8).

The JWT key is a fixed string in two modules, despite a JWT_SECRET_KEY entry existing in the backend environment file. MongoDB silently falls back to a cloud URI containing a username and password. This review did not check whether those database credentials remain valid.

Fix: remove source defaults for secrets, use one validated settings object, and fail startup when required secrets are absent. Rotate the committed signing material and any exposed database credentials. Use least-privilege database accounts. Inspect repository history and any already distributed images for previous exposure.

Acceptance: startup rejects missing secrets; changing the environment key changes the signing key; no credential-bearing connection string remains in source or image layers.

### 4. Inference failures are reported as BENIGN

Evidence: [CSV prediction exception handler](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:125).

A deliberately failing model produced a packet labeled BENIGN with is_anomaly=false in the isolated stream test. The real UNSW input construction also failed. This converts a broken detector into a reassuring verdict.

Fix: represent inference outcome separately from security verdict. Use explicit states such as analyzed, unavailable, and invalid_features, and allow the verdict to be unknown. Record and surface model errors; do not manufacture a clean verdict. Include model version and preprocessing version in every result.

Acceptance: model failure or invalid input produces an unknown/unavailable state and a visible degraded-service indicator, never a BENIGN classification.

## High-priority correctness and deployment findings

### 5. CSV replay processes only the last row in each 200-row chunk

Evidence: [replay loop](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:104).

Prediction, logging, and sending are outside the inner row loop. A 201-row fixture with feature values 0 through 200 emitted only 199 and 200. For full chunks, 199 of every 200 rows are skipped.

Fix: place preprocessing, inference, persistence, and emission inside the row loop. Separate configurable replay pacing from ingestion. Include event IDs and preserve original timestamps where available.

Acceptance: a finite replay processes every input row exactly once before restarting or completing, with explicit replay-cycle behavior.

### 6. UNSW inference does not reproduce the trained feature schema

Evidence: [UNSW stream inference](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:112) and [manual input padding](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:340).

The actual XGBoost artifact expects 194 features, including one-hot protocol/service/state features. The processed CSV contains raw proto, service, state, attack_cat, and label columns. The stream drops only the CICIDS column Label and passes the UNSW columns unchanged. Real sample inference failed on those string columns. Loading model_features.joblib does not transform the data; the stream never uses it. The fallback manual dimension of 42 also disagrees with the actual artifact. The UI manual tester always sends 78 zeros without passing the selected dataset.

Fix: persist and use the fitted preprocessing transformer with the estimator, ideally as one versioned pipeline. Exclude all target columns, define named input fields and units, encode categories identically to training, and assert the final column order. Reject arbitrary feature lengths instead of truncating or padding them silently.

Acceptance: the same named raw sample produces matching transformed features and predictions in the training/evaluation, REST, replay, and live inference paths.

### 7. Live Zeek features have incorrect meanings and units

Evidence: [live feature construction](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:69).

The code supplies destination port, duration, origin bytes, and response bytes, then fills 74 fields with zero. In the real Random Forest artifact, feature positions 2 and 3 are Total Fwd Packets and Total Backward Packets, not byte counts. Zeek duration is used without conversion to the training data's expected duration unit. Many CICIDS packet statistics cannot be reconstructed from this four-field mapping.

Fix: either collect flow statistics that match the trained CICIDS schema, or train and evaluate a model on the Zeek features that are actually available. Define a feature contract with names, direction, units, aggregation windows, and missing-value rules. Do not describe zero-filled vectors as validated live classification.

Acceptance: recorded capture fixtures yield independently checked feature values and held-out live-style traffic has measured detection and false-positive rates.

### 8. Stream detections never become persistent incidents or external notifications

Evidence: [live stream persistence](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:89), [replay persistence](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:130), [REST alert path](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:282), and [browser-created alert](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/context/TrafficContext.jsx:124).

Both WebSocket branches call only log_packet_to_db. That helper always stores analyzed=false and threat_flag=pending even after classification. Two anomalous stream frames in the isolated check created zero incident records. The browser creates a temporary random alert ID, labels every stream anomaly Critical, and supplies a fixed 99.7% confidence. Persistent history, exports, incident triage, and optional webhooks therefore do not share the same stream results.

Fix: use one server-side detection service for every input source. Persist the classified event and incident, then publish the canonical incident ID, actual confidence, severity, and event time. Route notifications from a persisted incident event with deduplication and delivery tracking. Keep replay/simulation incidents explicitly marked and excluded from live statistics by default.

Acceptance: one attack creates one incident that survives refresh, can be assigned and closed, appears in exports, and produces a tracked notification; the UI displays the same values as the server.

### 9. Monitoring is tied to browser connections

Evidence: [WebSocket handler](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:55).

Every connection runs its own CSV reader or Zeek tail and its own inference/database writes. With no connected browser, this pipeline does not analyze incoming flows. Multiple viewers duplicate work and telemetry. The browser's TrafficProvider mounts even on public pages and remains mounted after logout. There is no reconnect/backoff strategy or safe handling of server error messages before treating them as packet data.

Fix: run ingestion and inference in an independent worker, persist results once, and broadcast them to authenticated subscribers. Start UI subscriptions after authentication, stop them on logout, clear user-specific cached state, and reconnect with a cursor and bounded backoff. Handle log rotation, file truncation, capture restarts, and disconnected clients explicitly.

Acceptance: monitoring continues with zero viewers; adding viewers does not multiply ingestion or incident counts; reconnection resumes without losing or duplicating incidents.

### 10. Current Compose configuration has several independent blockers

Evidence: [Compose configuration](/Users/golukakarot/Developer/Projects/NetShield-ai/docker-compose.yml:21), [frontend Dockerfile](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/Dockerfile:1), and [backend Dockerfile](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/Dockerfile:1).

| Problem | Consequence | Correction |
| --- | --- | --- |
| mongo_data is referenced but no top-level volumes declaration exists | Invalid Compose project | Declare the named volume |
| MongoDB uses the implicit default network; backend uses netshield-network | Backend cannot resolve/reach the local Mongo service through that service network | Attach both to the intended private network |
| Frontend build path is ./frontend; tracked directory is Frontend | Fails on case-sensitive Linux filesystems | Use the exact tracked directory name |
| Frontend maps 3000:3000; nginx listens on 80 | Published port does not reach nginx | Map the desired host port to container port 80 |
| Dataset paths are /ml/data/processed; backend image copies only backend and no dataset mount exists | Replay closes without data | Mount/configure dataset paths explicitly |
| Zeek conn.log path has no capture service or mounted host log directory | Live mode cannot find its source | Provision a sensor and read-only log mount with documented JSON configuration |
| PostgreSQL has no explicit managed data volume | Persistence across container replacement is not intentionally configured | Declare a volume and document backups/restoration |
| Database ports are published; PostgreSQL credentials are fixed; local Mongo has no authentication configured | Unsafe default exposure if reachable | Keep databases private, configure credentials/authentication, and publish only required application ports |
| No .dockerignore and backend COPY . . | Backend environment file, virtualenv, capture, and logs enter the image context; potentially secrets enter image layers | Add explicit ignore rules; copy only runtime files and managed model artifacts |

The backend directory is approximately 2.1 GB in this checkout and contains a roughly 1.78 GB capture. Git ignore rules do not exclude files from Docker contexts. The Mongo startup parameter also needs validation against the chosen image; it was not runtime-tested here.

Acceptance: docker compose config succeeds and a documented clean Linux checkout starts a usable UI/API with healthy databases, available model artifacts, and an explicitly selected replay or live source. Container recreation preserves intended records.

### 11. Suspended users retain access; missing tokens raise a server error

Evidence: [token dependency](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:144), [login handler](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:199), and [suspension update](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:771).

Neither login nor get_current_user checks is_active. The isolated suspended administrator could log in and use an existing token, both with HTTP 200. A request without a token reached token.replace on None and produced HTTP 500 instead of 401. Password changes do not invalidate existing tokens. Role checks use multiple inconsistent spellings and frontend substring matching.

Fix: reject missing/invalid tokens immediately, validate the subject, enforce active status on every authenticated request, normalize roles, and implement an explicit token/session revocation policy. Add server-side password validation and login rate limiting.

Acceptance: suspension revokes access immediately; malformed/missing credentials never cause a server error; password-change/session behavior matches the documented policy.

## Product truthfulness and ML evidence

### 12. Operational measurements and security claims are partly synthetic

Evidence: [network statistics](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:517), [forecast](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:593), [model telemetry](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:663), [device monitor data](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:689), [dashboard assertions](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/dashboard.jsx:132), and [protocol seed counts](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/components/ProtocolBreakdown.jsx:18).

An empty incident store produced 112 scanned packets and risk 12. The empty-store forecast still returned historical-looking values and rising projected attacks. Model latency strings and infrastructure load/online statuses are fixed. The protocol graph begins with TCP=14, UDP=8, HTTP/HTTPS=6, even before receiving data. Dashboard text states Protected, Zero Critical Breaches, and System Secure & Operational without checking dependencies or detections. Traffic chart values mix bytes, durations, and packet counts, sometimes falling back to random numbers, while the dashboard labels the series packets/sec.

Fix: compute counters and rates from server-side time windows with explicit units and source scope. Count flows separately from packets. Show no-data, stale, unavailable, and degraded states honestly. Start protocol counts at zero, keep application protocols separate from transport protocols, and show measured service health and freshness. Label illustrative forecasts as demonstrations or remove them until evaluated. Confidence is not a confidence interval or a forecast of future intrusion. Define severity/risk using attack type, evidence, asset importance, and calibrated confidence; a higher class probability alone does not establish greater impact.

### 13. Retraining, invitations, MFA, firewall response, and settings are incomplete workflows

Evidence: [retraining implementation](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:629), [invitation endpoint](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:715), [MFA modal](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/profile.jsx:262), [firewall button](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/ThreatDetection.jsx:464), and [in-memory settings](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:702).

Retraining only sleeps and updates progress text: the isolated check completed with zero model fit calls. Invitations neither persist an expiring invitation nor send one; they only log an action attributed to user 1. The MFA modal always says 2FA is active and its disable button only closes the dialog. The firewall button displays a browser alert. Settings update an in-memory dictionary; MFA, retention, sensitivity, interface selection, token lifetime, and auto-ban are not wired to corresponding enforcement. Settings disappear on restart and diverge across processes.

Fix: disable or clearly mark incomplete actions. Implement persistent validated settings with actual consumers. Build expiring, single-use invitations with acceptance and delivery status. Implement real MFA before claiming it is active. Treat any future firewall integration as an audited, permission-controlled action with allowlists and reversal. Keep training offline initially; only add a model operations UI after there are real jobs, evaluation gates, versioning, and rollback.

### 14. Training and evaluation cannot be reproduced from the tracked project

Evidence: [preprocessing script](/Users/golukakarot/Developer/Projects/NetShield-ai/ml/PreprocessData.py:36), [saved metrics](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/unsw_metrics.json:1), [ignored model artifacts](/Users/golukakarot/Developer/Projects/NetShield-ai/.gitignore:40), and [ML documentation claims](/Users/golukakarot/Developer/Projects/NetShield-ai/README.md:92).

Only data exploration and cleaning scripts are tracked; no training notebooks/scripts or evaluation job were found. All joblib artifacts and processed datasets are ignored without a reproducible training/download procedure. The UNSW cleaning script merges the original training and testing files, losing the explicit split in the generated file. The trained XGBoost feature list includes the dataset row id. These are risks for biased evaluation and poor generalization, not proof that the saved metrics were obtained with leakage.

The saved UNSW report lists recall of 0.16 for Analysis, 0.14 for Backdoor, and 0.29 for DoS. If those numbers are valid for the intended test distribution, the detector misses most examples in those classes despite 86.69% overall accuracy. The local Random Forest artifact has 14 output classes while its label encoder contains 15: encoded class 13, the SQL injection label, is absent from the classifier's classes. This artifact therefore cannot output that particular label; document the missing class and investigate its training support. No held-out predictions, class supports, confusion matrix, split manifest, or training run IDs were found to verify the reported scores. The active Model Performance page displays per-class F1, but no actual confusion matrix; a separate unused component multiplies already-percent metrics by 100.

Fix: preserve the official UNSW holdout; fit preprocessing only on training data; exclude identifiers and labels from input; and evaluate with explicit split provenance. For CICIDS, use documented day/session or otherwise defensible separation and check duplicates. Save preprocessing, estimator, class mapping, feature schema, dataset checksums, random seed, dependency versions, and evaluation outputs per model version. Report per-class recall, macro/weighted F1, confusion matrix, false-positive rate, and inference latency distribution. Add calibrated uncertainty/abstention where justified. Supervised attack classification alone does not establish detection of unseen or zero-day attacks.

## Additional engineering findings

| Finding and evidence | Improvement |
| --- | --- |
| Hardcoded HTTP/WS cloud address throughout [API client](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/services/api.js:2) and pages | Use one environment-driven client or a same-origin reverse proxy; derive wss on HTTPS; handle auth/401, response validation, timeouts, and cancellation centrally. Local deployments should use local services. |
| Duplicate CORS middleware in [main.py](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:42), including a wildcard policy | Use one explicit origin policy that matches deployment. Remove token-response console logging in login. |
| [Prediction route](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:299) returns HTTP 200 for exceptions, including model offline | Use typed schemas, finite numeric checks, explicit dimensions, supported dataset enums, 422 for invalid inputs, and 503 for unavailable models. Do not expose raw internal exceptions. |
| [Async WebSocket](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/traffic.py:67) performs synchronous inference, file/CSV work and Mongo calls; [notification coroutine](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:234) uses blocking urllib | Move ingestion/inference to bounded workers and database writes to a controlled path. Instrument queue depth, dropped events, processing lag, and notification retry state. Current sleeps cap each stream's output and are not evidence of high-volume capacity. |
| Models are loaded independently in main.py and traffic.py; paths depend on working directory | Share a lifecycle-managed model service; resolve asset paths from configuration or module location; verify checksums and schema compatibility. |
| [Alert creation](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/mongodb.py:53) uses assigned_to, while updates/UI/export use assignee | Use one incident schema with stable user IDs, enum status, actor-attributed notes, and validated transitions. Audit incident changes, assignment, simulations, exports, and administrative actions. |
| [Alert updates in React](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/Alerts.jsx:57) optimistically change state without checking response.ok | Verify success and roll back or reconcile on failure. Show actionable error feedback. Avoid false-success UI on 401/403/500 responses. |
| [ThreatDetection](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/src/pages/ThreatDetection.jsx:71) fetches core incident data only on mount; IP timeline uses only the latest 10 local alerts | Subscribe to canonical incident changes; fetch paginated server-side IP history and enrichment. Do not label the local subset as complete history. |
| [Incident timestamps](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:453) serialize naive datetimes without UTC offset; helper sometimes discards timestamps; [trend grouping](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:545) uses week number only | Preserve aware UTC event and ingestion times and serialize with Z/+00:00. Group trends by ISO year and week or actual date buckets; add date/source filters. Preserve full timestamps in exports. |
| [Exports](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:783) silently cap at 1,000; alert reads cap at 100; source context/matrix can read unbounded history | Add bounded pagination, date ranges, counts, indexes, safe CSV cell handling, and documented export limits. Aggregate large matrices in MongoDB. |
| No MongoDB index/retention setup or SQL migrations found; tables are created at import | Introduce migrations and explicit indexes for timestamp/status/source queries; enforce retention with TTL or scheduled jobs, and document restore procedures. Do not call the audit log immutable without storage/access controls that enforce it. |
| [Mongo helpers](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/mongodb.py:65) swallow failures; [audit helper](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:173) catches commit errors without rollback | Distinguish unavailable storage from empty data; make persistence failures observable, recover transactions correctly, and use an outbox/retry strategy where durable notification delivery matters. |
| [Health endpoint](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/main.py:123) is not dependency readiness | Separate liveness from readiness; report database, model, sensor freshness, worker lag, and notification delivery status. |
| [Frontend entry](/Users/golukakarot/Developer/Projects/NetShield-ai/Frontend/index.html:1) uses title frontend and references an absent favicon; dashboard uses a fixed sidebar | Add product metadata and accessible navigation. Verify desktop/mobile layouts, keyboard operation, modal focus trapping/Escape, contrast, and reduced-motion behavior in a browser. These visual/accessibility checks were not executed in this review. |
| Duplicate/unused ModelPerformance, sidebar/header, placeholder reports/user pages, duplicate retrain-status route, and network-background resize listeners without cleanup | Remove unused implementations, share components, normalize naming, clean event listeners, and split main.py into routers/services without changing behavior first. Fix lint before establishing CI gates. |
| Production frontend JS bundle is approximately 735 KB minified, 222 KB gzip | Use route-based code splitting and load charts where needed after correctness fixes. This is an optimization opportunity, not the principal blocker. |

## Tests and documentation that need replacement

[test_api.py](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/test_api.py:6) targets /predict, while the real endpoint is /api/predict. It prints output, has no assertions or request timeout, and imports requests, which is not directly declared in backend requirements. It is a manual connectivity script rather than a regression suite.

[system_benchmark.py](/Users/golukakarot/Developer/Projects/NetShield-ai/backend/system_benchmark.py:35) submits 10 features to a model that expects 78, does not check the prediction result, and can report low latency for error responses. Its hardcoded millisecond targets are not validated by this script. Fast failure is not successful inference performance.

[README.md](/Users/golukakarot/Developer/Projects/NetShield-ai/README.md:1) contains an unclosed project-tree code fence, a non-copyable Markdown-wrapped git clone URL, stale frontend ports, a models/ directory description inconsistent with the loader, and training notebook claims unsupported by tracked files. Claims of zero-lag alerting, no dropped telemetry, secure containerization, and achieved quantitative goals lack reproducible evidence. The PDF's metrics section calls for measurement; it does not provide evidence that these goals have already been met.

Replace the claims with measured results and known limits. Add a sanitized .env.example, model/dataset acquisition and license notes, supported Python/Node versions, exact setup steps, sensor configuration, port/URL table, architecture/data dictionary, permissions table, demo/live distinction, troubleshooting, tests, backup/restore instructions, and a reproducible demonstration procedure. Keep a clean-install CI job using the lockfile and pinned backend dependencies.

## Recommended implementation order

### Phase 1: Make access and failure states correct

1. Fix public role assignment and apply a permission matrix to every endpoint and WebSocket.
2. Externalize and rotate exposed secrets; enforce suspension and correct 401/403 handling.
3. Remove BENIGN-on-error behavior and synthetic operational claims. Mark incomplete actions unavailable.
4. Make Compose internally consistent, add .dockerignore, and document model/dataset/sensor inputs.

Exit check: a clean environment starts, anonymous users cannot operate it, suspended accounts lose access, and detector/storage failures are visible.

### Phase 2: Finish one reliable vertical workflow

Use the existing CICIDS replay path first, since local sample inference already works. Correct row processing, then centralize detection and incident creation. Persist one canonical incident, publish it, triage it, record an audit entry, export it, and deliver a test notification through a controlled test sink. Keep simulations labeled and isolated.

Exit check: benign fixture -> no incident; attack fixture -> one durable incident; refresh/reconnect -> same ID and values; assignment/close -> persisted and audited; export -> same record. Test with zero, one, and two viewers.

### Phase 3: Make the ML claims defensible

Add reproducible training/evaluation, fix the UNSW transformer, remove row IDs from learning inputs, preserve holdouts, and replace the live Zeek mapping with a validated feature contract. Publish a model card for each version. Evaluate rare attack classes and false-positive rates explicitly. Treat future forecasting and unknown-attack detection as separate capabilities with their own validation.

Exit check: predictions agree across entry points, reported metrics can be regenerated, and held-out capture-style inputs meet documented operating targets.

### Phase 4: Improve operation and product usability

Run ingestion independently of viewers; add bounded queues/broadcasting, source health, indexes, retention, migrations, backup/restore, monitoring, and CI. Centralize the frontend API client, add pagination/filtering and dependable error handling, then verify responsive and accessible UI behavior. Implement genuine invitations/MFA only with complete backend lifecycle support.

Exit check: clean deployment and restore succeed; a documented sustained/concurrent test reports throughput, loss, p50/p95/p99 processing and alert latency, memory, CPU, and database behavior; the interface accurately displays degraded/stale states.

## Minimum acceptance suite for a credible release

- Authentication: anonymous access, analyst/admin permissions, privileged registration attempts, malformed/expired tokens, suspension, and session invalidation.
- Inference: valid CICIDS and UNSW fixtures, named feature order, categories, target exclusion, NaN/Inf, wrong dimensions, offline models, and consistent results across entry points.
- Streaming: every replay row processed, no duplicate ingestion with two viewers, monitoring with zero viewers, bounded queues, reconnect/cursor behavior, and log rotation.
- Incidents: one canonical persisted incident per detection policy, simulation separation, deduplication, actual confidence/severity, assignment, state transition, notes/actor, audit record, export, and notification retry.
- Reliability: database unavailable, notification failure, disk/log growth, model unavailable, container restart, backup restoration, and readiness reporting.
- ML evaluation: reproducible held-out metrics, per-class support/recall/F1, false-positive rate, confusion matrix, baseline comparison, and versioned artifacts.
- User experience: no-data/degraded/stale states, failed mutations, accessible dialogs, mobile navigation, and end-to-end analyst workflows.

The most valuable next milestone is a demonstrably correct capture/replay -> feature extraction -> inference -> persistent incident -> analyst triage workflow. Completing that chain will improve the project's credibility more than adding more dashboard panels.
