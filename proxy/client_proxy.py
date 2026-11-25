import asyncio
import sys
import time
from pathlib import Path

# Allow running directly via `python proxy/client_proxy.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxy.hybrid_crypto import HybridNode, decrypt_aes_gcm, encrypt_aes_gcm
from proxy.server_proxy import HybridServerProxy, recv_frame, send_frame


async def send_hybrid_traffic(
    messages: list[str], host: str = "127.0.0.1", port: int = 9443
) -> dict:
    """Connect to HybridServerProxy, complete PQC handshake, and send encrypted messages."""
    client = HybridNode()
    t0 = time.perf_counter()

    reader, writer = await asyncio.open_connection(host, port)
    try:
        # Step 1: Receive Server's signed Hybrid Public Bundle
        server_hello, hello_bytes = await recv_frame(reader)
        if not server_hello:
            raise ConnectionError("Server closed connection before handshake.")

        server_bundle = {k: bytes.fromhex(v) for k, v in server_hello.items()}

        # Step 2: Verify ML-DSA-65 signature + compute X25519 & ML-KEM-768 secrets
        session_key, client_x_pub, kem_ct, wire_report = client.client_handshake(server_bundle)

        reply_bytes = await send_frame(
            writer,
            {
                "client_x_pub": client_x_pub.hex(),
                "kem_ciphertext": kem_ct.hex(),
            },
        )
        handshake_ms = (time.perf_counter() - t0) * 1000

        packets = []
        for msg in messages:
            raw_msg = msg.encode("utf-8")
            nonce, ct = encrypt_aes_gcm(session_key, raw_msg)
            wire_sent = await send_frame(
                writer,
                {"nonce": nonce.hex(), "ciphertext": ct.hex()},
            )

            ack_frame, _ = await recv_frame(reader)
            ack_text = ""
            if ack_frame:
                ack_plain = decrypt_aes_gcm(
                    session_key,
                    bytes.fromhex(ack_frame["nonce"]),
                    bytes.fromhex(ack_frame["ciphertext"]),
                )
                ack_text = ack_plain.decode("utf-8")

            packets.append(
                {
                    "message": msg,
                    "plaintext_bytes": len(raw_msg),
                    "encrypted_wire_bytes": wire_sent,
                    "overhead_bytes": wire_sent - len(raw_msg),
                    "server_ack": ack_text,
                }
            )

        return {
            "handshake_ms": round(handshake_ms, 2),
            "crypto_wire_bytes": wire_report.total_handshake_bytes,
            "framed_handshake_bytes": hello_bytes + reply_bytes,
            "x25519_pub_bytes": wire_report.x25519_pub_bytes,
            "mlkem768_pub_bytes": wire_report.mlkem768_pub_bytes,
            "mlkem768_ct_bytes": wire_report.mlkem768_ct_bytes,
            "mldsa65_pub_bytes": wire_report.mldsa65_pub_bytes,
            "mldsa65_sig_bytes": wire_report.mldsa65_sig_bytes,
            "packets": packets,
        }
    finally:
        writer.close()
        await writer.wait_closed()


async def demo_end_to_end():
    """Spin up local server + client together to verify end-to-end encrypted tunneling."""
    server_proxy = HybridServerProxy(host="127.0.0.1", port=9443)
    server = await asyncio.start_server(server_proxy.handle_client, "127.0.0.1", 9443)

    async with server:
        sample_messages = [
            "POST /api/v1/transfer HTTP/1.1 | Amount: $25,000",
            "GET /api/v1/vault/keys HTTP/1.1 | Auth: Bearer qshield_token",
        ]
        report = await send_hybrid_traffic(sample_messages)

        print("\n--- Q-Shield Hybrid Proxy Session Report ---")
        print(f"Handshake Latency:    {report['handshake_ms']} ms")
        print(f"Raw PQC Crypto Wire:  {report['crypto_wire_bytes']} bytes")
        print(f"Framed TCP Handshake: {report['framed_handshake_bytes']} bytes")
        for idx, pkt in enumerate(report["packets"], 1):
            print(
                f"Packet #{idx}: {pkt['plaintext_bytes']}B plain -> "
                f"{pkt['encrypted_wire_bytes']}B wire (+{pkt['overhead_bytes']}B) | {pkt['server_ack']}"
            )


if __name__ == "__main__":
    asyncio.run(demo_end_to_end())