import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import x25519, mlkem, mldsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class WireSizeReport:
    x25519_pub_bytes: int
    mlkem768_pub_bytes: int
    mlkem768_ct_bytes: int
    mldsa65_pub_bytes: int
    mldsa65_sig_bytes: int

    @property
    def total_handshake_bytes(self) -> int:
        return (
            self.x25519_pub_bytes
            + self.mlkem768_pub_bytes
            + self.mlkem768_ct_bytes
            + self.mldsa65_pub_bytes
            + self.mldsa65_sig_bytes
        )


def derive_hybrid_key(classical_secret: bytes, pq_secret: bytes) -> bytes:
    """Combine X25519 + ML-KEM-768 shared secrets via HKDF-SHA256."""
    combined = classical_secret + pq_secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"q-shield-hybrid-v1",
    ).derive(combined)


class HybridNode:
    """Represents a client or server endpoint with X25519, ML-KEM-768, and ML-DSA-65 keys."""

    def __init__(self):
        self.x25519_priv = x25519.X25519PrivateKey.generate()
        self.x25519_pub = self.x25519_priv.public_key()

        self.mlkem_priv = mlkem.MLKEM768PrivateKey.generate()
        self.mlkem_pub = self.mlkem_priv.public_key()

        self.mldsa_priv = mldsa.MLDSA65PrivateKey.generate()
        self.mldsa_pub = self.mldsa_priv.public_key()

    def get_public_bundle(self) -> dict[str, bytes]:
        """Serialize public keys + sign them with ML-DSA-65 for authentication."""
        x_bytes = self.x25519_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        kem_bytes = self.mlkem_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        dsa_bytes = self.mldsa_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        signature = self.mldsa_priv.sign(x_bytes + kem_bytes)
        return {
            "x25519_pub": x_bytes,
            "mlkem_pub": kem_bytes,
            "mldsa_pub": dsa_bytes,
            "signature": signature,
        }

    def client_handshake(self, server_bundle: dict[str, bytes]) -> tuple[bytes, bytes, bytes, WireSizeReport]:
        """Verify server's ML-DSA-65 signature, perform X25519 + ML-KEM-768, and derive AES-256 key."""
        peer_dsa = mldsa.MLDSA65PublicKey.from_public_bytes(server_bundle["mldsa_pub"])
        peer_dsa.verify(
            server_bundle["signature"],
            server_bundle["x25519_pub"] + server_bundle["mlkem_pub"],
        )

        peer_x25519 = x25519.X25519PublicKey.from_public_bytes(server_bundle["x25519_pub"])
        classical_secret = self.x25519_priv.exchange(peer_x25519)

        peer_mlkem = mlkem.MLKEM768PublicKey.from_public_bytes(server_bundle["mlkem_pub"])
        pq_secret, kem_ciphertext = peer_mlkem.encapsulate()

        session_key = derive_hybrid_key(classical_secret, pq_secret)
        client_x_bytes = self.x25519_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        report = WireSizeReport(
            x25519_pub_bytes=len(server_bundle["x25519_pub"]),
            mlkem768_pub_bytes=len(server_bundle["mlkem_pub"]),
            mlkem768_ct_bytes=len(kem_ciphertext),
            mldsa65_pub_bytes=len(server_bundle["mldsa_pub"]),
            mldsa65_sig_bytes=len(server_bundle["signature"]),
        )
        return session_key, client_x_bytes, kem_ciphertext, report

    def server_handshake(self, client_x_bytes: bytes, kem_ciphertext: bytes) -> bytes:
        """Complete X25519 + ML-KEM-768 decapsulation and derive matching AES-256 key."""
        peer_x25519 = x25519.X25519PublicKey.from_public_bytes(client_x_bytes)
        classical_secret = self.x25519_priv.exchange(peer_x25519)
        pq_secret = self.mlkem_priv.decapsulate(kem_ciphertext)
        return derive_hybrid_key(classical_secret, pq_secret)


def encrypt_aes_gcm(session_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_aes_gcm(session_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(session_key).decrypt(nonce, ciphertext, None)


if __name__ == "__main__":
    server = HybridNode()
    client = HybridNode()

    bundle = server.get_public_bundle()
    client_key, client_x_pub, kem_ct, wire = client.client_handshake(bundle)
    server_key = server.server_handshake(client_x_pub, kem_ct)

    assert client_key == server_key, "Session keys do not match!"

    msg = b"Q-Shield Hybrid PQC Channel Active!"
    nonce, ct = encrypt_aes_gcm(client_key, msg)
    decrypted = decrypt_aes_gcm(server_key, nonce, ct)
    assert decrypted == msg, "Decryption failed!"

    print("Handshake & AES-256-GCM Encryption: SUCCESS")
    print(f"X25519 Public Key:     {wire.x25519_pub_bytes} bytes")
    print(f"ML-KEM-768 Public Key: {wire.mlkem768_pub_bytes} bytes")
    print(f"ML-KEM-768 Ciphertext: {wire.mlkem768_ct_bytes} bytes")
    print(f"ML-DSA-65 Public Key:  {wire.mldsa65_pub_bytes} bytes")
    print(f"ML-DSA-65 Signature:   {wire.mldsa65_sig_bytes} bytes")
    print(f"Total Handshake Wire:  {wire.total_handshake_bytes} bytes")