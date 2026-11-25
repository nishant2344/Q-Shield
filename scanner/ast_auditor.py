import ast
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, asdict


FIX_SNIPPETS = {
    "RSA": (
        "# Replace RSA with Hybrid X25519 + ML-KEM-768 (NIST FIPS 203)\n"
        "from cryptography.hazmat.primitives.asymmetric import x25519, mlkem\n"
        "x_priv = x25519.X25519PrivateKey.generate()\n"
        "pq_priv = mlkem.MLKEM768PrivateKey.generate()"
    ),
    "ECDSA": (
        "# Replace ECDSA with ML-DSA-65 (NIST FIPS 204)\n"
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "sig_priv = mldsa.MLDSA65PrivateKey.generate()\n"
        "signature = sig_priv.sign(b'message')"
    ),
    "MD5": (
        "# Replace broken MD5 with SHA-256 or SHA3-256\n"
        "import hashlib\n"
        "digest = hashlib.sha3_256(data).hexdigest()"
    ),
    "SHA-1": (
        "# Replace deprecated SHA-1 with SHA-256 or SHA3-256\n"
        "import hashlib\n"
        "digest = hashlib.sha256(data).hexdigest()"
    ),
}


@dataclass
class CryptoFinding:
    file: str
    line: int
    algorithm: str
    severity: str
    reason: str
    fix_snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[CryptoFinding] = []

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)

        if func_name.endswith("rsa.generate_private_key"):
            key_size = self._get_keyword_int(node, "key_size")
            if key_size and key_size < 2048:
                self.findings.append(
                    CryptoFinding(
                        file=self.filepath,
                        line=node.lineno,
                        algorithm=f"RSA-{key_size}",
                        severity="CRITICAL",
                        reason="Weak classical RSA key; broken classically and by Shor's algorithm.",
                        fix_snippet=FIX_SNIPPETS["RSA"],
                    )
                )
            else:
                algo = f"RSA-{key_size}" if key_size else "RSA"
                self.findings.append(
                    CryptoFinding(
                        file=self.filepath,
                        line=node.lineno,
                        algorithm=algo,
                        severity="HIGH",
                        reason="Quantum-vulnerable RSA key (Harvest Now, Decrypt Later risk).",
                        fix_snippet=FIX_SNIPPETS["RSA"],
                    )
                )

        elif func_name.endswith("ec.generate_private_key"):
            self.findings.append(
                CryptoFinding(
                    file=self.filepath,
                    line=node.lineno,
                    algorithm="ECDSA",
                    severity="HIGH",
                    reason="Quantum-vulnerable elliptic curve signing (broken by Shor's algorithm).",
                    fix_snippet=FIX_SNIPPETS["ECDSA"],
                )
            )

        elif func_name.endswith("hashlib.md5"):
            self.findings.append(
                CryptoFinding(
                    file=self.filepath,
                    line=node.lineno,
                    algorithm="MD5",
                    severity="CRITICAL",
                    reason="Cryptographically broken hash function (collision attacks).",
                    fix_snippet=FIX_SNIPPETS["MD5"],
                )
            )

        elif func_name.endswith("hashlib.sha1"):
            self.findings.append(
                CryptoFinding(
                    file=self.filepath,
                    line=node.lineno,
                    algorithm="SHA-1",
                    severity="HIGH",
                    reason="Deprecated hash function vulnerable to collision attacks.",
                    fix_snippet=FIX_SNIPPETS["SHA-1"],
                )
            )

        self.generic_visit(node)

    @staticmethod
    def _get_call_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Attribute) and isinstance(func_node.value, ast.Name):
            return f"{func_node.value.id}.{func_node.attr}"
        if isinstance(func_node, ast.Name):
            return func_node.id
        return ""

    @staticmethod
    def _get_keyword_int(node: ast.Call, kw_name: str) -> int | None:
        for kw in node.keywords:
            if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return kw.value.value
        return None


def scan_file(filepath: str | Path) -> list[CryptoFinding]:
    path = Path(filepath)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    visitor = CryptoASTVisitor(str(path))
    visitor.visit(tree)
    return visitor.findings


def scan_path(target: str | Path) -> list[CryptoFinding]:
    path = Path(target)
    if path.is_file():
        return scan_file(path)
    findings: list[CryptoFinding] = []
    for py_file in path.rglob("*.py"):
        if "venv" in py_file.parts:
            continue
        findings.extend(scan_file(py_file))
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Q-Shield PQC AST Codebase Auditor")
    parser.add_argument("target", help="Python file or directory to scan")
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with code 1 if HIGH or CRITICAL findings exist (for CI/CD)",
    )
    args = parser.parse_args()

    results = scan_path(args.target)
    if not results:
        print("No quantum-vulnerable cryptography detected.")
        sys.exit(0)

    print(f"Found {len(results)} cryptographic issue(s):\n")
    for f in results:
        print(f"[{f.severity}] {f.file}:{f.line} -> {f.algorithm}")
        print(f"  Reason: {f.reason}")
        print(f"  Suggested Fix:\n    " + f.fix_snippet.replace("\n", "\n    ") + "\n")

    if args.fail_on_high and any(f.severity in ("HIGH", "CRITICAL") for f in results):
        print("CI/CD Gate FAILED: High/Critical quantum-vulnerable crypto detected.")
        sys.exit(1)