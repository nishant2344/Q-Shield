# 🛡️ Q-Shield: Post-Quantum Cryptography (PQC) Readiness Scanner & Hybrid Proxy

**Q-Shield** is an end-to-end cryptographic migration and DevSecOps toolkit designed to detect quantum-vulnerable cryptography in source code and live TLS endpoints, enforce PQC compliance in CI/CD pipelines, and tunnel application traffic through a quantum-resistant hybrid proxy.

---

## 🚀 Key Capabilities

1. **Hybrid Post-Quantum Proxy (`proxy/`)**
   - Combines classical **X25519** ECDH with NIST-standardized **ML-KEM-768** (FIPS 203) via **HKDF-SHA256**.
   - Authenticates server key bundles using **ML-DSA-65** (FIPS 204) post-quantum digital signatures.
   - Encrypts application payloads with **AES-256-GCM** and tracks exact wire-size overhead in bytes.

2. **AST Codebase Auditor & Automated "Fix-It" Generator (`scanner/ast_auditor.py`)**
   - Parses Python Abstract Syntax Trees (`ast`) to detect quantum-vulnerable primitives (`RSA-1024`, `RSA-2048`, `ECDSA`, `MD5`, `SHA-1`).
   - Generates drop-in hybrid PQC refactoring snippets for every finding.
   - Includes a `--fail-on-high` CLI flag to block vulnerable pull requests in CI/CD.

3. **Live HTTPS / TLS PQC Prober (`scanner/tls_prober.py`)**
   - Inspects external HTTPS endpoints over `ssl`/`socket` to verify TLS 1.3 readiness, cipher suites, and certificate metadata.

4. **Cryptographic Bill of Materials (`scanner/cbom_generator.py`)**
   - Computes a **Quantum Risk Score (0–100)** and exports machine-readable **JSON** and **CSV** CBOM reports.

5. **Interactive Command Center (`dashboard/app.py`)**
   - Built with **Streamlit** and **Plotly** for live code/TLS scanning, real-time wire-size packet inspection, and performance benchmarking.

---

## 📊 Cryptographic Wire-Size & Latency Profile

Measured across 500 full handshakes (`benchmarks/run_benchmarks.py`):

| Metric | Classical (`X25519 + Ed25519`) | Hybrid PQC (`X25519 + ML-KEM-768 + ML-DSA-65`) |
| :--- | :---: | :---: |
| **Avg Handshake Latency** | ~0.86 ms | ~5.06 ms (+4.20 ms) |
| **Total Handshake Wire Size** | 160 bytes | 7,597 bytes |
| **Quantum Resistance** | Vulnerable to Shor's Algorithm | **NIST Level 3 Quantum-Safe** |

### Hybrid Handshake Breakdown (Raw Binary)
- **X25519 Public Keys:** 32 bytes (Server) + 32 bytes (Client)
- **ML-KEM-768 Public Key:** 1,184 bytes
- **ML-KEM-768 Ciphertext:** 1,088 bytes
- **ML-DSA-65 Public Key:** 1,952 bytes
- **ML-DSA-65 Signature:** 3,309 bytes

---

## 🗂️ Project Structure

```text
q-shield/
├── benchmarks/
│   └── run_benchmarks.py       # Classical vs. Hybrid PQC latency & wire-size benchmarks
├── dashboard/
│   └── app.py                  # Interactive Streamlit dashboard
├── proxy/
│   ├── hybrid_crypto.py        # X25519 + ML-KEM-768 + ML-DSA-65 + AES-256-GCM core
│   ├── server_proxy.py         # Asyncio PQC gateway server
│   └── client_proxy.py         # Asyncio PQC client & packet overhead logger
├── samples/
│   └── vulnerable_bank_app.py  # Intentional legacy crypto sample for scanner testing
├── scanner/
│   ├── ast_auditor.py          # Python AST scanner + Fix-It generator + CI gate
│   ├── tls_prober.py           # Live TLS 1.3 / cipher suite endpoint prober
│   └── cbom_generator.py       # Quantum Risk Score & JSON/CSV CBOM exporter
└── requirements.txt
```

---

## ⚡ Quickstart (Windows PowerShell)

```powershell
# 1. Clone the repository
git clone [https://github.com/nishant2344/q-shield.git](https://github.com/nishant2344/q-shield.git)
cd q-shield

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the interactive dashboard
streamlit run dashboard/app.py
```

### CLI Usage Examples

```powershell
# Scan a file and fail if HIGH/CRITICAL quantum vulnerabilities exist
python scanner/ast_auditor.py samples/vulnerable_bank_app.py --fail-on-high

# Probe a live HTTPS endpoint
python scanner/tls_prober.py cloudflare.com

# Run end-to-end encrypted proxy demo
python proxy/client_proxy.py

# Run 500-iteration performance benchmark
python benchmarks/run_benchmarks.py 500
```