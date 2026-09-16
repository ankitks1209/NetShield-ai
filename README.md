# NetShield AI: Real-Time Network Anomaly Detection & Threat Monitoring System

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![React](https://img.shields.io/badge/React-18.x-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-teal.svg)
![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)

NetShield AI is a containerized, AI-powered cybersecurity platform designed to continuously monitor live network traffic, identify suspicious behavior, predict potential intrusions, and generate real-time threat alerts.

Built as a dual-engine machine learning system, it leverages an asynchronous WebSocket pipeline to stream packets from a live network monitor directly through an inference engine to a React-based command center, achieving sub-second threat visualization and incident logging.

---

## System Architecture

NetShield AI utilizes a decoupled microservices architecture deployed via Docker Compose. This ensures high throughput and prevents state collisions between data persistence and real-time inference. The system follows a clear pipeline from network ingestion to user visualization:

1. **Traffic Collection:** A live network sniffer (Zeek) captures raw traffic from the network interface and standardizes disparate packet schemas into a unified JSON stream.
2. **Traffic Preprocessing & Feature Extraction:** The pipeline cleans the data, handles missing values, and extracts crucial statistical and flow-based features required for machine learning analysis.
3. **Anomaly Detection & Intrusion Prediction (AI/ML Models):** An asynchronous FastAPI backend routes packets through a dual-classification system:
   * **Random Forest:** Provides robust baseline anomaly detection for generalized threats.
   * **XGBoost:** Delivers high-performance gradient boosting to catch subtle, complex threat signatures and assign a Threat Risk Score.
4. **Alert & Response:** The system instantly generates automated threat alerts based on attack severity and confidence scores.
5. **Data & Storage Layer:** 
   * **MongoDB:** A high-throughput NoSQL database dedicated to logging all detected session anomalies and raw packet telemetry.
   * **PostgreSQL:** Serves as the relational anchor for Role-Based Access Control (RBAC) and immutable system audit trails.
6. **Web/Application Portal:** A Vite-powered React dashboard connects directly to the backend via WebSockets. It maps live packet throughput and threat logs instantly without UI lag or polling overhead.

---

## Machine Learning Methodology & Datasets

To ensure reliable intrusion prediction, the AI modules were trained and validated against industry-standard cybersecurity datasets:
* **CICIDS2017:** Utilized for training the model to recognize modern attack vectors including Brute Force, DoS, Web Attacks, and Infiltration.
* **UNSW-NB15:** Utilized for analyzing hybrid synthetic and real modern normal activities alongside contemporary synthesized attack behaviors.

The models evaluate real-time features against these learned baselines to output a classification verdict (Benign vs. specific Threat type) alongside a confidence interval.

---

## Key Features

* **Real-Time Live Streaming:** WebSocket integration bypasses legacy REST API polling, feeding live network packets to the UI with minimal latency.
* **Monotonic State Management:** Advanced React state logic prevents UI jitter and backward-jumping counters during rapid packet influxes.
* **Timezone Consistency:** Built-in ISO UTC parsing ensures threat logs display accurately in local browser timezones across geographic deployments.
* **Dynamic Data Mapping:** A universal metric extraction protocol ensures charts animate smoothly regardless of whether the incoming data originates from static training datasets or live Zeek JSON feeds.
* **Secure Containerization:** Fully orchestrated using Docker and Docker Compose for seamless cloud deployment and environment parity.

---

## Technology Stack

| Category | Technologies |
| :--- | :--- |
| **Frontend** | React.js, Vite, Tailwind CSS, Chart.js, Framer Motion |
| **Backend** | Python, FastAPI, WebSockets, JWT Authentication |
| **Databases** | MongoDB (NoSQL Persistence), PostgreSQL (SQL Audit) |
| **AI / Machine Learning** | Scikit-learn, XGBoost, Pandas, NumPy |
| **DevOps & Cloud** | Docker, Docker Compose, AWS EC2 |
| **Network Monitoring** | Zeek (Packet Capture), Wireshark |

---

## Project Structure

```text
NetShield-ai/
├── Frontend/               # React.js UI, Tailwind CSS, Vite configuration
│   ├── src/
│   │   ├── components/     # Reusable UI widgets and charts
│   │   ├── context/        # React Context API for global state and WebSockets
│   │   └── pages/          # Dashboard, Network Traffic, Anomaly Detection views
│   └── Dockerfile          # Frontend container configuration
├── backend/                # FastAPI application, Python ML inference logic
│   ├── main.py             # API routing and WebSocket stream handlers
│   ├── models/             # Pickled Random Forest and XGBoost model files
│   ├── mongodb.py          # NoSQL database connection and schemas
│   └── Dockerfile          # Backend container configuration
├── ml/                     # Original Jupyter notebooks for dataset training
├── docker-compose.yml      # Orchestration file for all microservices
└── README.md               # Project documentation

---

## Installation & Deployment

The system is fully containerized, making deployment straightforward on a local machine or a cloud instance (e.g., AWS EC2 Ubuntu).

### Prerequisites

* Docker and Docker Compose installed on the host machine.
* Ensure network ports `80`, `5173`, `8000`, `5432`, and `27017` are available.

### Quick Start Guide

1. **Clone the Repository:**
```bash
git clone [https://github.com/ankitks1209/NetShield-ai.git](https://github.com/ankitks1209/NetShield-ai.git)
cd NetShield-ai

```


2. **Environment Configuration:**
Create a `.env` file in the root directory to define database credentials, JWT secrets, and environment-specific variables.
3. **Build and Spin Up Containers:**
Run the orchestration command to pull the required images and build the custom frontend/backend network stack:
```bash
docker compose up -d --build

```


4. **Verify Services:**
Check that all primary containers are running successfully:
```bash
docker compose ps

```


5. **Access the Dashboard:**
Open your browser and navigate to:
* **Local Deployment:** `http://localhost:5173`
* **Cloud Deployment:** `http://35.154.0.127:5173`



---

## Performance & Quantitative Goals

The NetShield AI platform successfully achieves the targeted quantitative goals established for enterprise network security monitoring:

* **Accurate Threat Detection:** Reliable identification of unusual network behavior and anomaly classification.
* **Alert Generation Latency:** Zero-lag generation of threat alerts immediately upon AI classification via the WebSocket pipeline.
* **High-Volume Stability:** The decoupled microservice architecture successfully supports continuous monitoring without dropping packet telemetry or locking the persistence databases.

