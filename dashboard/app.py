import asyncio
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Ensure root project imports work cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from benchmarks.run_benchmarks import run_benchmark_suite
from proxy.client_proxy import send_hybrid_traffic
from proxy.server_proxy import HybridServerProxy
from scanner.ast_auditor import scan_path
from scanner.cbom_generator import (
    calculate_quantum_risk_score,
    export_cbom_csv,
    export_cbom_json,
)
from scanner.tls_prober import probe_tls

st.set_page_config(
    page_title="Q-Shield | PQC Readiness & Hybrid Proxy",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Q-Shield: Post-Quantum Cryptography Readiness & Hybrid Proxy")
st.caption("NIST FIPS 203 (ML-KEM-768) • NIST FIPS 204 (ML-DSA-65) • X25519 Hybrid Tunnel")

tab1, tab2, tab3 = st.tabs(
    [
        "🔍 1. Codebase & TLS Scanner",
        "🔐 2. Live Hybrid Proxy & Packet Inspector",
        "📊 3. Classical vs. Hybrid Benchmarks",
    ]
)

# ==========================================
# TAB 1: CODEBASE & TLS SCANNER
# ==========================================
with tab1:
    col_code, col_tls = st.columns([1.3, 1])

    with col_code:
        st.subheader("AST Codebase Cryptographic Auditor")
        target_path = st.text_input(
            "File or Folder Path to Scan",
            value="samples/vulnerable_bank_app.py",
        )

        if st.button("Scan Codebase", type="primary"):
            full_target = ROOT_DIR / target_path
            if not full_target.exists():
                st.error(f"Path not found: {target_path}")
            else:
                findings = scan_path(full_target)
                score, risk_level = calculate_quantum_risk_score(findings)

                m1, m2, m3 = st.columns(3)
                m1.metric("Quantum Risk Score", f"{score} / 100")
                m2.metric("Risk Level", risk_level)
                m3.metric("Vulnerabilities Found", len(findings))

                if findings:
                    df = pd.DataFrame(
                        [
                            {
                                "File": Path(f.file).name,
                                "Line": f.line,
                                "Algorithm": f.algorithm,
                                "Severity": f.severity,
                                "Reason": f.reason,
                            }
                            for f in findings
                        ]
                    )
                    st.dataframe(df, use_container_width=True)

                    dl1, dl2 = st.columns(2)
                    dl1.download_button(
                        "⬇️ Download CBOM (JSON)",
                        data=export_cbom_json(target_path, findings),
                        file_name="qshield_cbom.json",
                        mime="application/json",
                    )
                    dl2.download_button(
                        "⬇️ Download CBOM (CSV)",
                        data=export_cbom_csv(findings),
                        file_name="qshield_cbom.csv",
                        mime="text/csv",
                    )

                    st.markdown("#### Automated 'Fix-It' PQC Refactoring Suggestions")
                    for idx, f in enumerate(findings, 1):
                        with st.expander(f"#{idx} [{f.severity}] {f.algorithm} (Line {f.line})"):
                            st.write(f.reason)
                            st.code(f.fix_snippet, language="python")
                else:
                    st.success("No quantum-vulnerable cryptography detected!")

    with col_tls:
        st.subheader("Live HTTPS / TLS PQC Prober")
        hostname = st.text_input("Target Domain / URL", value="cloudflare.com")

        if st.button("Probe TLS Endpoint"):
            with st.spinner(f"Connecting to {hostname}:443..."):
                try:
                    res = probe_tls(hostname)
                    st.metric("TLS Protocol", res.tls_version)
                    st.metric("PQC Risk Level", res.risk_level)
                    st.info(f"**Status:** {res.pqc_readiness}")
                    st.write(f"**Cipher Suite:** `{res.cipher_name}` ({res.cipher_bits}-bit)")
                    st.write(f"**Issuer:** {res.cert_issuer}")
                    st.write(f"**Expires:** {res.cert_expiry}")
                    st.success(f"**Recommendation:** {res.recommendation}")
                except Exception as exc:
                    st.error(f"TLS Probe failed: {exc}")


# ==========================================
# TAB 2: LIVE HYBRID PROXY & PACKET INSPECTOR
# ==========================================
async def _run_live_proxy_session(messages: list[str]) -> dict:
    proxy_srv = HybridServerProxy(host="127.0.0.1", port=0)
    server = await asyncio.start_server(proxy_srv.handle_client, "127.0.0.1", 0)
    assigned_port = server.sockets[0].getsockname()[1]

    async with server:
        return await send_hybrid_traffic(messages, host="127.0.0.1", port=assigned_port)


with tab2:
    st.subheader("Live X25519 + ML-KEM-768 + ML-DSA-65 Encrypted Tunnel")
    raw_msgs = st.text_area(
        "Application Payloads to Tunnel (one per line)",
        value="POST /api/v1/transfer HTTP/1.1 | Amount: $25,000\nGET /api/v1/vault/keys HTTP/1.1 | Auth: Bearer qshield_token",
        height=100,
    )

    if st.button("Launch Tunnel & Inspect Wire Sizes", type="primary"):
        msg_list = [line.strip() for line in raw_msgs.splitlines() if line.strip()]
        if not msg_list:
            st.warning("Enter at least one message to send.")
        else:
            report = asyncio.run(_run_live_proxy_session(msg_list))

            c1, c2, c3 = st.columns(3)
            c1.metric("Handshake Latency", f"{report['handshake_ms']} ms")
            c2.metric("Raw PQC Crypto Wire", f"{report['crypto_wire_bytes']} B")
            c3.metric("Framed TCP Handshake", f"{report['framed_handshake_bytes']} B")

            wire_df = pd.DataFrame(
                [
                    {"Component": "X25519 Public Key (Classical)", "Bytes": report["x25519_pub_bytes"]},
                    {"Component": "ML-KEM-768 Public Key (PQC)", "Bytes": report["mlkem768_pub_bytes"]},
                    {"Component": "ML-KEM-768 Ciphertext (PQC)", "Bytes": report["mlkem768_ct_bytes"]},
                    {"Component": "ML-DSA-65 Public Key (PQC)", "Bytes": report["mldsa65_pub_bytes"]},
                    {"Component": "ML-DSA-65 Signature (PQC)", "Bytes": report["mldsa65_sig_bytes"]},
                ]
            )
            fig_wire = px.bar(
                wire_df,
                x="Component",
                y="Bytes",
                color="Component",
                text="Bytes",
                title="Hybrid Handshake Wire-Size Breakdown (Bytes)",
            )
            fig_wire.update_layout(showlegend=False)
            st.plotly_chart(fig_wire, use_container_width=True)

            st.markdown("#### AES-256-GCM Encrypted Packet Inspector")
            pkt_df = pd.DataFrame(report["packets"])
            st.dataframe(pkt_df, use_container_width=True)


# ==========================================
# TAB 3: BENCHMARK CHARTS
# ==========================================
with tab3:
    st.subheader("Classical vs. Hybrid Post-Quantum Performance")
    iters = st.slider("Benchmark Iterations", min_value=100, max_value=1000, value=500, step=100)

    if st.button("Run Benchmark Suite", type="primary"):
        with st.spinner(f"Running {iters} full handshakes per mode..."):
            bench_results = run_benchmark_suite(iters)
            bench_df = pd.DataFrame(bench_results)

            st.dataframe(bench_df, use_container_width=True)

            b1, b2 = st.columns(2)
            with b1:
                fig_lat = px.bar(
                    bench_df,
                    x="mode",
                    y="avg_latency_ms",
                    color="mode",
                    text="avg_latency_ms",
                    title="Average Handshake Latency (ms)",
                )
                fig_lat.update_layout(showlegend=False)
                st.plotly_chart(fig_lat, use_container_width=True)

            with b2:
                fig_size = px.bar(
                    bench_df,
                    x="mode",
                    y="wire_bytes",
                    color="mode",
                    text="wire_bytes",
                    title="Total Handshake Wire Size (Bytes)",
                )
                fig_size.update_layout(showlegend=False)
                st.plotly_chart(fig_size, use_container_width=True)