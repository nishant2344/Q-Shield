import sys
import time
from pathlib import Path

# Allow running directly via `python benchmarks/run_benchmarks.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from proxy.hybrid_crypto import HybridNode, derive_hybrid_key


def benchmark_classical(iterations: int = 500) -> dict:
    """Benchmark Classical X25519 Key Exchange + Ed25519 Signature."""
    t0 = time.perf_counter()
    wire_bytes = 0

    for _ in range(iterations):
        # Server keygen + sign
        srv_x_priv = x25519.X25519PrivateKey.generate()
        srv_x_pub = srv_x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        srv_ed_priv = ed25519.Ed25519PrivateKey.generate()
        srv_ed_pub = srv_ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        sig = srv_ed_priv.sign(srv_x_pub)

        # Client verify + exchange
        ed25519.Ed25519PublicKey.from_public_bytes(srv_ed_pub).verify(sig, srv_x_pub)
        cli_x_priv = x25519.X25519PrivateKey.generate()
        cli_x_pub = cli_x_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        c_secret = cli_x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(srv_x_pub))
        s_secret = srv_x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(cli_x_pub))
        derive_hybrid_key(c_secret, s_secret)

        wire_bytes = len(srv_x_pub) + len(srv_ed_pub) + len(sig) + len(cli_x_pub)

    total_ms = (time.perf_counter() - t0) * 1000
    avg_ms = total_ms / iterations
    return {
        "mode": "Classical (X25519 + Ed25519)",
        "iterations": iterations,
        "total_ms": round(total_ms, 2),
        "avg_latency_ms": round(avg_ms, 4),
        "handshakes_per_sec": round(1000 / avg_ms, 1),
        "wire_bytes": wire_bytes,
    }


def benchmark_hybrid_pqc(iterations: int = 500) -> dict:
    """Benchmark Hybrid X25519 + ML-KEM-768 Key Exchange + ML-DSA-65 Signature."""
    t0 = time.perf_counter()
    wire_bytes = 0

    for _ in range(iterations):
        server = HybridNode()
        client = HybridNode()

        bundle = server.get_public_bundle()
        _, cli_x_pub, kem_ct, wire_report = client.client_handshake(bundle)
        server.server_handshake(cli_x_pub, kem_ct)

        wire_bytes = wire_report.total_handshake_bytes + len(cli_x_pub)

    total_ms = (time.perf_counter() - t0) * 1000
    avg_ms = total_ms / iterations
    return {
        "mode": "Hybrid PQC (X25519 + ML-KEM-768 + ML-DSA-65)",
        "iterations": iterations,
        "total_ms": round(total_ms, 2),
        "avg_latency_ms": round(avg_ms, 4),
        "handshakes_per_sec": round(1000 / avg_ms, 1),
        "wire_bytes": wire_bytes,
    }


def run_benchmark_suite(iterations: int = 500) -> list[dict]:
    return [
        benchmark_classical(iterations),
        benchmark_hybrid_pqc(iterations),
    ]


if __name__ == "__main__":
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    print(f"Running Q-Shield Cryptographic Benchmarks ({iters} iterations)...\n")
    results = run_benchmark_suite(iters)

    for r in results:
        print(f"Mode:               {r['mode']}")
        print(f"  Avg Latency:      {r['avg_latency_ms']} ms / handshake")
        print(f"  Throughput:       {r['handshakes_per_sec']} handshakes/sec")
        print(f"  Handshake Wire:   {r['wire_bytes']} bytes\n")

    lat_diff = round(results[1]["avg_latency_ms"] - results[0]["avg_latency_ms"], 4)
    size_ratio = round(results[1]["wire_bytes"] / results[0]["wire_bytes"], 1)
    print(f"Summary: Hybrid PQC adds +{lat_diff} ms latency and {size_ratio}x wire size for full quantum safety.")