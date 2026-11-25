import ssl
import socket
import sys
from dataclasses import dataclass, asdict
from urllib.parse import urlparse


@dataclass
class TLSProbeResult:
    hostname: str
    port: int
    tls_version: str
    cipher_name: str
    cipher_bits: int
    cert_issuer: str
    cert_expiry: str
    pqc_readiness: str
    risk_level: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def clean_hostname(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def probe_tls(target: str, port: int = 443, timeout: float = 5.0) -> TLSProbeResult:
    hostname = clean_hostname(target)
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_version = ssock.version() or "Unknown"
            cipher_name, _, cipher_bits = ssock.cipher() or ("Unknown", "", 0)
            cert = ssock.getpeercert() or {}

            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            cert_issuer = issuer_dict.get("organizationName", "Unknown")
            cert_expiry = cert.get("notAfter", "Unknown")

            if tls_version == "TLSv1.3":
                pqc_readiness = "TLS 1.3 Ready (Supports Hybrid PQC Key Exchange)"
                risk_level = "LOW"
                recommendation = "Verify server enables X25519MLKEM768 hybrid group in TLS 1.3."
            elif tls_version == "TLSv1.2":
                pqc_readiness = "Legacy TLS 1.2 (Not PQC-Ready)"
                risk_level = "HIGH"
                recommendation = "Upgrade endpoint to TLS 1.3 with hybrid ML-KEM-768 key exchange."
            else:
                pqc_readiness = f"Deprecated {tls_version} (Vulnerable)"
                risk_level = "CRITICAL"
                recommendation = "Immediately disable legacy TLS and migrate to TLS 1.3."

            return TLSProbeResult(
                hostname=hostname,
                port=port,
                tls_version=tls_version,
                cipher_name=cipher_name,
                cipher_bits=cipher_bits,
                cert_issuer=cert_issuer,
                cert_expiry=cert_expiry,
                pqc_readiness=pqc_readiness,
                risk_level=risk_level,
                recommendation=recommendation,
            )


if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare.com"
    result = probe_tls(target_host)
    print(f"Target:         {result.hostname}:{result.port}")
    print(f"TLS Version:    {result.tls_version}")
    print(f"Cipher Suite:   {result.cipher_name} ({result.cipher_bits}-bit)")
    print(f"Cert Issuer:    {result.cert_issuer}")
    print(f"Cert Expiry:    {result.cert_expiry}")
    print(f"PQC Readiness:  {result.pqc_readiness}")
    print(f"Risk Level:     {result.risk_level}")
    print(f"Recommendation: {result.recommendation}")