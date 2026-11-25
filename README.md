# Q-Shield: Post-Quantum Cryptography (PQC) Readiness & Hybrid Proxy

**Q-Shield** is an end-to-end Post-Quantum Cryptography (PQC) readiness, compliance, and hybrid transport suite built to protect systems against the *"Harvest Now, Decrypt Later"* threat. It combines static Abstract Syntax Tree (AST) code auditing, live TLS 1.3 endpoint probing, Cryptographic Bill of Materials (CBOM) reporting, an asynchronous **X25519 + ML-KEM-768** hybrid proxy authenticated with **ML-DSA-65**, automated CI/CD enforcement, and an interactive web workbench.

---

## Core Capabilities

1. **Hybrid Post-Quantum Proxy (`proxy/`)**
   - Combines classical **X25519** ECDH with NIST-standardized **ML-KEM-768** (FIPS 203) and derives session keys via **HKDF-SHA256**.
   - Authenticates server key bundles using **ML-DSA-65** (FIPS 204) post-quantum digital signatures to prevent spoofing.
   - Encrypts application frames with **AES-256-GCM** over an `asyncio` TCP tunnel and records exact wire-size overhead per packet.

2. **AST Codebase Auditor & Automated Fix-It Generator (`scanner/ast_auditor.py`)**
   - Walks Python Abstract Syntax Trees (`ast`) to detect quantum-vulnerable algorithms and weak primitives (`RSA-1024`, `RSA-2048`, `ECDSA`, `MD5`, `SHA-1`) without regex false positives.
   - Generates drop-in hybrid PQC refactoring snippets for each finding and supports `--fail-on-high` in CI/CD pipelines.

3. **Live HTTPS / TLS PQC Prober (`scanner/tls_prober.py`)**
   - Inspects remote HTTPS endpoints to check TLS version negotiation, cipher suites, and certificate details.

4. **CBOM Generator & Risk Scoring (`scanner/cbom_generator.py`)**
   - Calculates a **Quantum Risk Score (0–100)** and exports structured **JSON** and **CSV** Cryptographic Bill of Materials reports.

5. **Web Portal, REST API & Streamlit Dashboard (`frontend/`, `dashboard/`)**
   - **Two-Page Web Portal (`frontend/`):** Served via Flask (`frontend/api.py`) with a **Project Overview** landing page and a 3-tab **Security Workbench** (Code & TLS Scanner, Hybrid PQC Proxy, and Benchmarks) built with HTML5, CSS3, and Vanilla ES6+ JavaScript.
   - **Interactive Dashboard (`dashboard/app.py`):** Streamlit + Plotly console for scanning, live proxy sessions, and performance charts.

---

## Cryptographic Stack & Wire Footprint

| Security Role | Algorithm | Standard | Typical Footprint |
| :--- | :--- | :--- | :--- |
| Classical Key Exchange | **X25519** (ECDH) | RFC 7748 | 32 B public key |
| Post-Quantum KEM | **ML-KEM-768** | NIST FIPS 203 | 1,184 B pub / 1,088 B ciphertext |
| Post-Quantum Signature | **ML-DSA-65** | NIST FIPS 204 | 1,952 B pub / 3,309 B signature |
| Symmetric AEAD & KDF | **AES-256-GCM** + **HKDF-SHA256** | NIST SP 800-38D / RFC 5869 | 12 B nonce + 16 B tag per frame |

### Benchmark Reference (500 Handshakes)

| Metric | Classical (`X25519 + Ed25519`) | Hybrid PQC (`X25519 + ML-KEM-768 + ML-DSA-65`) |
| :--- | :---: | :---: |
| **Average Latency** | ~0.86 ms | ~5.06 ms (+4.20 ms) |
| **Handshake Wire Size** | 160 bytes | 7,597 bytes |
| **Quantum Resistance** | Vulnerable to Shor's algorithm | NIST Level 3 post-quantum protection |

---

## Repository Structure

```text
Q-Shield/
├── .github/
│   └── workflows/
│       └── pqc-check.yml       # Automated GitHub Actions PQC security gate
├── benchmarks/
│   └── run_benchmarks.py       # Classical vs. Hybrid PQC latency & wire benchmarks
├── dashboard/
│   └── app.py                  # Streamlit + Plotly readiness dashboard
├── frontend/
│   ├── api.py                  # Flask REST API & static asset server
│   ├── index.html              # Project Overview & 3-tab Security Workbench
│   ├── styles.css              # Clean flat light-mode stylesheet
│   └── app.js                  # ES6+ client state, fetch handlers & CBOM exports
├── proxy/
│   ├── hybrid_crypto.py        # X25519, ML-KEM-768, ML-DSA-65 & AES-256-GCM core
│   ├── server_proxy.py         # Asyncio hybrid PQC server gateway
│   └── client_proxy.py         # Asyncio hybrid PQC client & packet logger
├── samples/
│   └── vulnerable_bank_app.py  # Sample legacy crypto application for testing
├── scanner/
│   ├── ast_auditor.py          # AST vulnerability scanner & PQC fix suggestions
│   ├── tls_prober.py           # Live TLS endpoint inspector
│   └── cbom_generator.py       # Quantum risk score & JSON/CSV CBOM exporter
├── Dockerfile                  # Container build definition
├── .dockerignore               # Build context exclusions
├── requirements.txt            # Python dependencies
└── README.md
```

---

## Quickstart & Deployment

### 1. Local Setup (PowerShell)

```powershell
git clone [https://github.com/nishant2344/Q-Shield.git](https://github.com/nishant2344/Q-Shield.git)
cd Q-Shield

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Run the Web Portal, Streamlit App, or CLI Tools

```powershell
# Two-page Web Portal + REST API ([http://127.0.0.1:5000](http://127.0.0.1:5000))
python frontend/api.py

# Streamlit Dashboard (http://localhost:8501)
streamlit run dashboard/app.py

# AST Gate, TLS Prober, Hybrid Proxy Demo & Benchmarks
python scanner/ast_auditor.py samples/vulnerable_bank_app.py --fail-on-high
python scanner/tls_prober.py cloudflare.com
python proxy/client_proxy.py
python benchmarks/run_benchmarks.py 500
```

### 3. Docker & Cloud Deployment

```powershell
docker build -t q-shield:latest .
docker run --rm -p 5000:5000 q-shield:latest
```

The repository includes a `Dockerfile` and `.github/workflows/pqc-check.yml` so it can be built into a container image on platforms such as Railway or Render while automatically running AST security checks on pushes and pull requests to `main`.
