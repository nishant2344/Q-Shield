import ast
import asyncio
import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from benchmarks.run_benchmarks import run_benchmark_suite
from proxy.client_proxy import send_hybrid_traffic
from proxy.server_proxy import HybridServerProxy
from scanner.ast_auditor import CryptoASTVisitor, scan_path
from scanner.cbom_generator import (
    calculate_quantum_risk_score,
    export_cbom_csv,
    export_cbom_json,
)
from scanner.tls_prober import probe_tls

app = Flask(__name__, static_folder=str(FRONTEND_DIR))


@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def serve_static(filename: str):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "code")

    try:
        if mode == "path":
            rel_path = data.get("target", "samples/vulnerable_bank_app.py")
            full_path = ROOT_DIR / rel_path
            if not full_path.exists():
                return jsonify({"error": f"Path not found: {rel_path}"}), 404
            findings = scan_path(full_path)
            target_label = rel_path
        else:
            source_code = data.get("code", "")
            tree = ast.parse(source_code, filename="live_editor.py")
            visitor = CryptoASTVisitor("live_editor.py")
            visitor.visit(tree)
            findings = visitor.findings
            target_label = "live_editor.py"

        score, risk_level = calculate_quantum_risk_score(findings)
        return jsonify(
            {
                "target": target_label,
                "score": score,
                "risk_level": risk_level,
                "total_findings": len(findings),
                "findings": [f.to_dict() for f in findings],
                "cbom_json": export_cbom_json(target_label, findings),
                "cbom_csv": export_cbom_csv(findings),
            }
        )
    except SyntaxError as exc:
        return jsonify({"error": f"Python Syntax Error on line {exc.lineno}: {exc.msg}"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/tls", methods=["POST"])
def api_tls():
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "cloudflare.com").strip()
    try:
        result = probe_tls(hostname)
        return jsonify(result.to_dict())
    except Exception as exc:
        return jsonify({"error": f"TLS probe failed for {hostname}: {exc}"}), 400


async def _run_proxy_tunnel(messages: list[str]) -> dict:
    proxy_srv = HybridServerProxy(host="127.0.0.1", port=0)
    server = await asyncio.start_server(proxy_srv.handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        return await send_hybrid_traffic(messages, host="127.0.0.1", port=port)


@app.route("/api/proxy", methods=["POST"])
def api_proxy():
    data = request.get_json(silent=True) or {}
    messages = data.get("messages", [])
    if not messages:
        return jsonify({"error": "Provide at least one payload message."}), 400
    try:
        report = asyncio.run(_run_proxy_tunnel(messages))
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/benchmark", methods=["POST"])
def api_benchmark():
    data = request.get_json(silent=True) or {}
    iterations = int(data.get("iterations", 300))
    iterations = max(50, min(iterations, 1000))
    try:
        results = run_benchmark_suite(iterations)
        return jsonify({"iterations": iterations, "results": results})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    print("[Q-Shield Web Portal] Running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)