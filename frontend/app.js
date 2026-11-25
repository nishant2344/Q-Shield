document.addEventListener("DOMContentLoaded", () => {
  let latestCbomJson = "";
  let latestCbomCsv = "";

  // Escape HTML characters before inserting text into the DOM
  const escapeHtml = (value) =>
    String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  // Trigger client-side file download via Blob API
  const triggerDownload = (content, filename, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  // =========================================================
  // 1. MULTI-PAGE VIEW & 3-TAB ROUTER
  // =========================================================
  const navLinks = document.querySelectorAll(".nav-link");
  const views = document.querySelectorAll(".view");
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");

  const switchView = (viewName) => {
    navLinks.forEach((link) => {
      link.classList.toggle("active", link.dataset.view === viewName);
    });
    views.forEach((view) => {
      view.classList.toggle("active", view.id === `view-${viewName}`);
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const switchTab = (tabName) => {
    tabs.forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.tab === tabName);
    });
    panels.forEach((panel) => {
      panel.classList.toggle("active", panel.id === `panel-${tabName}`);
    });
  };

  navLinks.forEach((link) => {
    link.addEventListener("click", () => switchView(link.dataset.view));
  });

  document.getElementById("nav-brand").addEventListener("click", () => switchView("home"));
  document.getElementById("btn-enter-workbench").addEventListener("click", () => switchView("workbench"));
  document.getElementById("btn-back-home").addEventListener("click", () => switchView("home"));

  document.querySelectorAll("[data-jump-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      switchView("workbench");
      switchTab(btn.dataset.jumpTab);
    });
  });

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });

  // =========================================================
  // 2. TAB 1A: PYTHON AST CODE AUDITOR & CBOM DOWNLOAD
  // =========================================================
  const codeEditor = document.getElementById("code-editor");
  const btnLoadSample = document.getElementById("btn-load-sample");
  const btnRunScan = document.getElementById("btn-run-scan");
  const cbomButtons = document.getElementById("cbom-buttons");
  const scanOutput = document.getElementById("scan-output");

  const SAMPLE_VULNERABLE_CODE = `import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def process_bank_transaction():
    weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    vuln_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vuln_ecdsa = ec.generate_private_key(ec.SECP256R1())
    broken_md5 = hashlib.md5(b"transfer:5000").hexdigest()
    weak_sha1 = hashlib.sha1(b"transfer:5000").hexdigest()
    return weak_rsa, vuln_rsa, vuln_ecdsa, broken_md5, weak_sha1`;

  btnLoadSample.addEventListener("click", () => {
    codeEditor.value = SAMPLE_VULNERABLE_CODE;
  });

  btnRunScan.addEventListener("click", async () => {
    btnRunScan.disabled = true;
    btnRunScan.textContent = "Scanning...";
    scanOutput.innerHTML = `<div class="placeholder-box">Parsing Python Abstract Syntax Tree...</div>`;

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "code", code: codeEditor.value }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Code scan failed.");

      latestCbomJson = data.cbom_json;
      latestCbomCsv = data.cbom_csv;
      cbomButtons.classList.remove("hidden");

      const findingsMarkup =
        data.findings.length === 0
          ? `<div class="success-box">No quantum-vulnerable cryptography found in this snippet.</div>`
          : data.findings
              .map(
                (item) => `
              <div class="result-item">
                <div class="result-item-head">
                  <span class="result-title">Line ${item.line} &mdash; ${escapeHtml(item.algorithm)}</span>
                  <span class="badge-sev sev-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>
                </div>
                <p class="result-desc">${escapeHtml(item.reason)}</p>
                <div class="code-fix">${escapeHtml(item.fix_snippet)}</div>
              </div>`
              )
              .join("");

      scanOutput.innerHTML = `
        <div class="summary-strip">
          <div class="summary-metric">
            <span class="metric-label">Quantum Risk Score</span>
            <span class="metric-value">${data.score} / 100</span>
          </div>
          <div class="summary-metric">
            <span class="metric-label">Risk Rating</span>
            <span class="metric-value">${escapeHtml(data.risk_level)}</span>
          </div>
          <div class="summary-metric">
            <span class="metric-label">Issues Detected</span>
            <span class="metric-value">${data.total_findings}</span>
          </div>
        </div>
        ${findingsMarkup}
      `;
    } catch (err) {
      cbomButtons.classList.add("hidden");
      scanOutput.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btnRunScan.disabled = false;
      btnRunScan.textContent = "Scan Code";
    }
  });

  document.getElementById("btn-dl-json").addEventListener("click", () => {
    if (latestCbomJson) triggerDownload(latestCbomJson, "qshield_cbom.json", "application/json");
  });

  document.getElementById("btn-dl-csv").addEventListener("click", () => {
    if (latestCbomCsv) triggerDownload(latestCbomCsv, "qshield_cbom.csv", "text/csv");
  });

  // =========================================================
  // 3. TAB 1B: LIVE HTTPS / TLS PROBER
  // =========================================================
  const tlsHostInput = document.getElementById("tls-host");
  const btnRunTls = document.getElementById("btn-run-tls");
  const tlsOutput = document.getElementById("tls-output");

  document.querySelectorAll(".preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      tlsHostInput.value = btn.dataset.host;
      btnRunTls.click();
    });
  });

  btnRunTls.addEventListener("click", async () => {
    const hostname = tlsHostInput.value.trim();
    if (!hostname) return;

    btnRunTls.disabled = true;
    btnRunTls.textContent = "Probing...";
    tlsOutput.innerHTML = `<div class="placeholder-box">Connecting to ${escapeHtml(hostname)}:443...</div>`;

    try {
      const res = await fetch("/api/tls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "TLS probe failed.");

      tlsOutput.innerHTML = `
        <div class="result-item">
          <div class="result-item-head">
            <span class="result-title">${escapeHtml(data.hostname)}:${data.port}</span>
            <span class="badge-sev sev-${escapeHtml(data.risk_level)}">RISK: ${escapeHtml(data.risk_level)}</span>
          </div>
          <p class="result-desc" style="margin-bottom:0.8rem;">${escapeHtml(data.pqc_readiness)}</p>

          <div class="kv-grid">
            <div class="kv-cell">
              <span class="kv-key">Protocol Version</span>
              <span class="kv-val">${escapeHtml(data.tls_version)}</span>
            </div>
            <div class="kv-cell">
              <span class="kv-key">Cipher Suite</span>
              <span class="kv-val">${escapeHtml(data.cipher_name)} (${data.cipher_bits}-bit)</span>
            </div>
            <div class="kv-cell">
              <span class="kv-key">Certificate Issuer</span>
              <span class="kv-val">${escapeHtml(data.cert_issuer)}</span>
            </div>
            <div class="kv-cell">
              <span class="kv-key">Certificate Expiry</span>
              <span class="kv-val">${escapeHtml(data.cert_expiry)}</span>
            </div>
          </div>

          <div class="success-box">
            <strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}
          </div>
        </div>
      `;
    } catch (err) {
      tlsOutput.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btnRunTls.disabled = false;
      btnRunTls.textContent = "Probe";
    }
  });

  // =========================================================
  // 4. TAB 2: ASYNCIO HYBRID PQC PROXY
  // =========================================================
  const btnRunProxy = document.getElementById("btn-run-proxy");
  const proxyMessages = document.getElementById("proxy-messages");
  const proxyOutput = document.getElementById("proxy-output");

  btnRunProxy.addEventListener("click", async () => {
    const messages = proxyMessages.value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    if (messages.length === 0) return;

    btnRunProxy.disabled = true;
    btnRunProxy.textContent = "Running Tunnel...";
    proxyOutput.innerHTML = `<div class="placeholder-box">Establishing X25519 + ML-KEM-768 hybrid tunnel...</div>`;

    try {
      const res = await fetch("/api/proxy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Proxy execution failed.");

      const wireComponents = [
        { name: "X25519 Public Key (Classical)", bytes: data.x25519_pub_bytes },
        { name: "ML-KEM-768 Public Key (NIST FIPS 203)", bytes: data.mlkem768_pub_bytes },
        { name: "ML-KEM-768 Ciphertext (NIST FIPS 203)", bytes: data.mlkem768_ct_bytes },
        { name: "ML-DSA-65 Public Key (NIST FIPS 204)", bytes: data.mldsa65_pub_bytes },
        { name: "ML-DSA-65 Signature (NIST FIPS 204)", bytes: data.mldsa65_sig_bytes },
      ];
      const maxVal = Math.max(...wireComponents.map((c) => c.bytes));

      const barsHtml = wireComponents
        .map((comp) => {
          const widthPct = Math.max(3, Math.round((comp.bytes / maxVal) * 100));
          return `
            <div class="bar-item">
              <div class="bar-header">
                <span>${comp.name}</span>
                <strong>${comp.bytes.toLocaleString()} bytes</strong>
              </div>
              <div class="bar-bg">
                <div class="bar-progress" style="width: ${widthPct}%;"></div>
              </div>
            </div>`;
        })
        .join("");

      const packetRows = data.packets
        .map(
          (pkt, idx) => `
          <tr>
            <td>#${idx + 1}</td>
            <td><code>${escapeHtml(pkt.message)}</code></td>
            <td>${pkt.plaintext_bytes} B</td>
            <td>${pkt.encrypted_wire_bytes} B</td>
            <td>+${pkt.overhead_bytes} B</td>
            <td>${escapeHtml(pkt.server_ack)}</td>
          </tr>`
        )
        .join("");

      proxyOutput.innerHTML = `
        <div class="summary-strip">
          <div class="summary-metric">
            <span class="metric-label">Handshake Latency</span>
            <span class="metric-value">${data.handshake_ms} ms</span>
          </div>
          <div class="summary-metric">
            <span class="metric-label">Raw Crypto Wire Size</span>
            <span class="metric-value">${data.crypto_wire_bytes.toLocaleString()} B</span>
          </div>
          <div class="summary-metric">
            <span class="metric-label">TCP Framed Handshake</span>
            <span class="metric-value">${data.framed_handshake_bytes.toLocaleString()} B</span>
          </div>
        </div>

        <div class="bar-section">
          <h4>Hybrid Handshake Wire-Size Breakdown</h4>
          ${barsHtml}
        </div>

        <div class="table-box">
          <table class="clean-table">
            <thead>
              <tr>
                <th>Packet</th>
                <th>Application Payload</th>
                <th>Plaintext</th>
                <th>Encrypted Wire</th>
                <th>AEAD Overhead</th>
                <th>Server Acknowledgement</th>
              </tr>
            </thead>
            <tbody>${packetRows}</tbody>
          </table>
        </div>
      `;
    } catch (err) {
      proxyOutput.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btnRunProxy.disabled = false;
      btnRunProxy.textContent = "Send Encrypted Traffic";
    }
  });

  // =========================================================
  // 5. TAB 3: CLASSICAL VS HYBRID BENCHMARKS
  // =========================================================
  const benchSlider = document.getElementById("bench-iters");
  const iterVal = document.getElementById("iter-val");
  const btnRunBench = document.getElementById("btn-run-bench");
  const benchOutput = document.getElementById("bench-output");

  benchSlider.addEventListener("input", () => {
    iterVal.textContent = benchSlider.value;
  });

  btnRunBench.addEventListener("click", async () => {
    const iterations = Number(benchSlider.value);
    btnRunBench.disabled = true;
    btnRunBench.textContent = "Running...";
    benchOutput.innerHTML = `<div class="placeholder-box">Benchmarking ${iterations} handshakes per mode...</div>`;

    try {
      const res = await fetch("/api/benchmark", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iterations }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || "Benchmark failed.");

      const [classical, hybrid] = data.results;
      const maxLat = Math.max(classical.avg_latency_ms, hybrid.avg_latency_ms);
      const maxWire = Math.max(classical.wire_bytes, hybrid.wire_bytes);

      benchOutput.innerHTML = `
        <div class="grid-2" style="margin-bottom: 1rem;">
          <div class="bar-section" style="margin-bottom:0;">
            <h4>Average Handshake Latency (ms)</h4>
            <div class="bar-item">
              <div class="bar-header"><span>Classical (X25519 + Ed25519)</span><strong>${classical.avg_latency_ms} ms</strong></div>
              <div class="bar-bg"><div class="bar-progress" style="width: ${Math.max(4, (classical.avg_latency_ms / maxLat) * 100)}%;"></div></div>
            </div>
            <div class="bar-item">
              <div class="bar-header"><span>Hybrid PQC (ML-KEM-768 + ML-DSA-65)</span><strong>${hybrid.avg_latency_ms} ms</strong></div>
              <div class="bar-bg"><div class="bar-progress" style="width: 100%;"></div></div>
            </div>
          </div>

          <div class="bar-section" style="margin-bottom:0;">
            <h4>Total Handshake Wire Size (Bytes)</h4>
            <div class="bar-item">
              <div class="bar-header"><span>Classical (X25519 + Ed25519)</span><strong>${classical.wire_bytes} B</strong></div>
              <div class="bar-bg"><div class="bar-progress" style="width: ${Math.max(3, (classical.wire_bytes / maxWire) * 100)}%;"></div></div>
            </div>
            <div class="bar-item">
              <div class="bar-header"><span>Hybrid PQC (ML-KEM-768 + ML-DSA-65)</span><strong>${hybrid.wire_bytes.toLocaleString()} B</strong></div>
              <div class="bar-bg"><div class="bar-progress" style="width: 100%;"></div></div>
            </div>
          </div>
        </div>

        <div class="table-box">
          <table class="clean-table">
            <thead>
              <tr>
                <th>Cryptographic Mode</th>
                <th>Iterations</th>
                <th>Avg Latency</th>
                <th>Throughput</th>
                <th>Handshake Wire</th>
              </tr>
            </thead>
            <tbody>
              ${data.results
                .map(
                  (row) => `
                <tr>
                  <td>${escapeHtml(row.mode)}</td>
                  <td>${row.iterations}</td>
                  <td>${row.avg_latency_ms} ms</td>
                  <td>${row.handshakes_per_sec} ops/sec</td>
                  <td>${row.wire_bytes.toLocaleString()} bytes</td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      benchOutput.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btnRunBench.disabled = false;
      btnRunBench.textContent = "Run Benchmark";
    }
  });
});