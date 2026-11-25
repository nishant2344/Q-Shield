import asyncio
import json
import struct
import sys
from pathlib import Path

# Allow running directly via `python proxy/server_proxy.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxy.hybrid_crypto import HybridNode, decrypt_aes_gcm, encrypt_aes_gcm


async def send_frame(writer: asyncio.StreamWriter, payload: dict) -> int:
    """Send a 4-byte length-prefixed JSON frame and return total bytes written."""
    raw = json.dumps(payload).encode("utf-8")
    header = struct.pack("!I", len(raw))
    writer.write(header + raw)
    await writer.drain()
    return 4 + len(raw)


async def recv_frame(reader: asyncio.StreamReader) -> tuple[dict | None, int]:
    """Read a 4-byte length-prefixed JSON frame and return (payload, total_bytes)."""
    try:
        header = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None, 0
    (length,) = struct.unpack("!I", header)
    raw = await reader.readexactly(length)
    return json.loads(raw.decode("utf-8")), 4 + length


class HybridServerProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 9443):
        self.host = host
        self.port = port
        self.node = HybridNode()
        self.packet_logs: list[dict] = []

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        print(f"[Server] Connection opened from {peer}")

        try:
            # Step 1: Send signed Hybrid Public Bundle (X25519 + ML-KEM-768 + ML-DSA-65)
            bundle = self.node.get_public_bundle()
            server_hello = {k: v.hex() for k, v in bundle.items()}
            hello_bytes = await send_frame(writer, server_hello)

            # Step 2: Receive Client Key Share + ML-KEM-768 Ciphertext
            client_reply, reply_bytes = await recv_frame(reader)
            if not client_reply:
                return

            client_x_pub = bytes.fromhex(client_reply["client_x_pub"])
            kem_ct = bytes.fromhex(client_reply["kem_ciphertext"])
            session_key = self.node.server_handshake(client_x_pub, kem_ct)

            handshake_total = hello_bytes + reply_bytes
            print(f"[Server] Hybrid PQC Handshake complete | Total Wire: {handshake_total} bytes")

            # Step 3: Tunnel encrypted AES-256-GCM application traffic
            while True:
                frame, wire_bytes = await recv_frame(reader)
                if frame is None:
                    break

                nonce = bytes.fromhex(frame["nonce"])
                ciphertext = bytes.fromhex(frame["ciphertext"])
                plaintext = decrypt_aes_gcm(session_key, nonce, ciphertext)

                overhead = wire_bytes - len(plaintext)
                log_entry = {
                    "direction": "Client -> Server",
                    "plaintext_bytes": len(plaintext),
                    "wire_bytes": wire_bytes,
                    "overhead_bytes": overhead,
                    "preview": plaintext.decode("utf-8", errors="replace"),
                }
                self.packet_logs.append(log_entry)
                print(
                    f"[Server] Decrypted {len(plaintext)}B payload "
                    f"(Wire: {wire_bytes}B, Overhead: +{overhead}B): {log_entry['preview']}"
                )

                # Send encrypted acknowledgement back to client
                ack_plain = f"ACK ({len(plaintext)}B received via Q-Shield)".encode("utf-8")
                ack_nonce, ack_ct = encrypt_aes_gcm(session_key, ack_plain)
                await send_frame(
                    writer,
                    {"nonce": ack_nonce.hex(), "ciphertext": ack_ct.hex()},
                )
        finally:
            writer.close()
            await writer.wait_closed()
            print(f"[Server] Connection closed for {peer}")

    async def serve_forever(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"[Q-Shield Server Proxy] Listening on {self.host}:{self.port} (Hybrid PQC Ready)")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    proxy = HybridServerProxy()
    try:
        asyncio.run(proxy.serve_forever())
    except KeyboardInterrupt:
        print("\n[Server] Stopped.")