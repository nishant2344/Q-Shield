import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes


def generate_legacy_rsa_1024():
    """CRITICAL: Weak classical RSA-1024 key (broken classically & by Shor's algorithm)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def generate_legacy_rsa_2048():
    """HIGH: Quantum-vulnerable RSA-2048 key (Harvest Now, Decrypt Later risk)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_legacy_ecdsa():
    """HIGH: Quantum-vulnerable ECDSA signing key."""
    return ec.generate_private_key(ec.SECP256R1())


def hash_transaction_md5(tx_data: bytes) -> str:
    """CRITICAL: Broken MD5 hash function."""
    return hashlib.md5(tx_data).hexdigest()


def hash_transaction_sha1(tx_data: bytes) -> str:
    """HIGH: Deprecated SHA-1 hash function."""
    return hashlib.sha1(tx_data).hexdigest()


if __name__ == "__main__":
    generate_legacy_rsa_1024()
    generate_legacy_rsa_2048()
    generate_legacy_ecdsa()
    print("MD5:", hash_transaction_md5(b"transfer:5000"))
    print("SHA1:", hash_transaction_sha1(b"transfer:5000"))
    print("Sample vulnerable banking app executed successfully.")