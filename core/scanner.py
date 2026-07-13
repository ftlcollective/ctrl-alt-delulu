"""
Part 01 — Core Scanner
Owner: Sumaira

Forks/wraps the Semgrep OSS CLI, runs it on a target codebase, and outputs
clean raw JSON findings. This is the foundation Part 02 (AI Explanation Layer)
builds on top of.
"""

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SemgrepNotFoundError(RuntimeError):
    """Raised when the semgrep CLI isn't installed / on PATH."""


@dataclass
class Finding:
    """A single, cleaned-up Semgrep finding."""
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata,
        }


def _check_semgrep_installed() -> str:
    """Return the path to the semgrep binary or raise if it's missing."""
    path = shutil.which("semgrep")
    if not path:
        raise SemgrepNotFoundError(
            "semgrep is not installed or not on PATH. Install it with:\n"
            "  pip install semgrep"
        )
    return path


def run_scan(
    target_path: str,
    config: str = "auto",
    timeout: int = 120,
) -> dict[str, Any]:
    """
    Run Semgrep on `target_path` and return the raw parsed JSON output.

    Args:
        target_path: file or directory to scan.
        config: semgrep ruleset config. "auto" pulls Semgrep's default
                registry rules based on detected languages. You can also
                pass a specific ruleset, e.g. "p/security-audit" or "p/owasp-top-ten".
        timeout: max seconds semgrep is allowed to run.

    Returns:
        The raw JSON dict exactly as Semgrep produces it (has "results",
        "errors", "paths", etc). Use `parse_findings()` to turn this into
        clean Finding objects for the AI layer.
    """
    _check_semgrep_installed()

    target = Path(target_path)
    if not target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target_path}")

    cmd = [
        "semgrep",
        "scan",
        "--config", config,
        "--json",
        "--quiet",
        "--no-git-ignore",
        str(target),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"Semgrep scan timed out after {timeout}s") from e

    if not proc.stdout.strip():
        raise RuntimeError(
            f"Semgrep produced no output. stderr:\n{proc.stderr}"
        )

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Could not parse semgrep output as JSON: {e}\nRaw stdout:\n{proc.stdout[:2000]}"
        ) from e


def _read_snippet(file_path: str, start_line: int, end_line: int) -> str:
    """
    Read the actual source lines for a finding directly from disk.

    Newer versions of the Semgrep OSS CLI gate the `extra.lines` field
    behind a free `semgrep login` (it returns the literal string
    "requires login" instead of code when you're not authenticated), so
    we read the snippet ourselves instead of trusting that field.
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
        start = max(start_line - 1, 0)
        end = min(end_line, len(lines))
        return "".join(lines[start:end]).strip()
    except (OSError, IOError):
        return ""


def parse_findings(raw_json: dict[str, Any]) -> list[Finding]:
    """Convert raw Semgrep JSON output into a clean list of Finding objects."""
    findings: list[Finding] = []

    for result in raw_json.get("results", []):
        extra = result.get("extra", {})
        start = result.get("start", {})
        end = result.get("end", {})
        file_path = result.get("path", "unknown-file")
        start_line = start.get("line", 0)
        end_line = end.get("line", 0)

        snippet = extra.get("lines", "").strip()
        if not snippet or snippet == "requires login":
            snippet = _read_snippet(file_path, start_line, end_line)

        findings.append(
            Finding(
                rule_id=result.get("check_id", "unknown-rule"),
                message=extra.get("message", "").strip(),
                severity=extra.get("severity", "INFO"),
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                code_snippet=snippet,
                metadata=extra.get("metadata", {}),
            )
        )

    return findings


def scan(target_path: str, config: str = "auto") -> list[Finding]:
    """Convenience wrapper: run_scan() + parse_findings() in one call."""
    raw = run_scan(target_path, config=config)
    return parse_findings(raw)


def scan_into_state(
    target_path: str,
    config: str = "auto",
    state_path: str = "scan-state.json",
) -> list[Finding]:
    """
    Run the scan and write results directly into the shared scan-state.json
    (created once by init_scan_state.py). This is the entry point Part 01
    should use so Part 02/03/06 can all read from the same file.
    """
    import state as scan_state  # local import: core/ isn't a package, just a folder on sys.path

    findings = scan(target_path, config=config)
    state = scan_state.load_state(state_path)
    scan_state.add_findings(state, findings, project_path=str(Path(target_path).resolve()))
    scan_state.save_state(state, state_path)
    return findings


def save_findings(findings: list[Finding], out_path: str) -> None:
    """Save a list of Finding objects to a JSON file (for Part 02 to consume)."""
    with open(out_path, "w") as f:
        json.dump([finding.to_dict() for finding in findings], f, indent=2)


if __name__ == "__main__":
    # Quick manual test: python scanner.py <path-to-scan>
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning {target} ...")
    results = scan(target)
    print(f"Found {len(results)} issue(s).\n")
    for f in results:
        print(f"[{f.severity}] {f.rule_id} — {f.file_path}:{f.start_line}")
        print(f"  {f.message}\n")

    save_findings(results, "findings.json")
    print("Raw findings saved to findings.json")
