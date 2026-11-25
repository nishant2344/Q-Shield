import csv
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running directly via `python scanner/cbom_generator.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.ast_auditor import CryptoFinding, scan_path


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}


def calculate_quantum_risk_score(findings: list[CryptoFinding]) -> tuple[int, str]:
    """Return (score 0-100, risk_level) based on detected vulnerabilities."""
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 5) for f in findings)
    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def generate_cbom_dict(target: str, findings: list[CryptoFinding]) -> dict:
    score, level = calculate_quantum_risk_score(findings)
    return {
        "cbom_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "total_findings": len(findings),
            "quantum_risk_score": score,
            "risk_level": level,
        },
        "components": [f.to_dict() for f in findings],
    }


def export_cbom_json(target: str, findings: list[CryptoFinding]) -> str:
    return json.dumps(generate_cbom_dict(target, findings), indent=2)


def export_cbom_csv(findings: list[CryptoFinding]) -> str:
    output = io.StringIO()
    fieldnames = ["file", "line", "algorithm", "severity", "reason"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow(
            {
                "file": f.file,
                "line": f.line,
                "algorithm": f.algorithm,
                "severity": f.severity,
                "reason": f.reason,
            }
        )
    return output.getvalue()


if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else "samples/vulnerable_bank_app.py"
    findings = scan_path(target_path)
    score, level = calculate_quantum_risk_score(findings)

    print(f"Target:             {target_path}")
    print(f"Total Findings:     {len(findings)}")
    print(f"Quantum Risk Score: {score}/100 ({level})")
    print("\n--- CBOM JSON Preview ---")
    print(export_cbom_json(target_path, findings))