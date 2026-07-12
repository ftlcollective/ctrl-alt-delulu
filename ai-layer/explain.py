"""
Part 02 — AI Explanation Layer
Owner: Sumaira

Takes raw Semgrep findings (from Part 01 / core/scanner.py) and turns each
one into a beginner-friendly explanation: what's wrong, why it matters,
and exactly how to fix it. This is the team's key differentiator.

Provider: NVIDIA NIM (free, OpenAI-compatible) by default.
    export AI_PROVIDER="nvidia"          # default, no need to set explicitly
    export NVIDIA_API_KEY="nvapi-..."    # get one free at https://build.nvidia.com
    export NVIDIA_MODEL="meta/llama-3.3-70b-instruct"   # optional override

To use Anthropic (Claude) instead:
    export AI_PROVIDER="anthropic"
    export ANTHROPIC_API_KEY="your-key-here"
"""

import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Protocol

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NVIDIA_MODEL = "meta/llama-3.3-70b-instruct"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = """You are a friendly senior developer helping a beginner \
understand a security vulnerability found by a static analysis scanner \
(Semgrep). You will be given one raw finding as JSON.

Respond with ONLY a JSON object (no markdown fences, no preamble, no \
extra commentary before or after) with exactly these keys:
  "plain_summary": one or two plain-English sentences explaining what the \
    problem actually is, avoiding jargon. Assume the reader is a junior dev.
  "why_it_matters": one or two sentences on the real-world risk/impact if \
    this isn't fixed.
  "how_to_fix": a short, concrete, step-by-step explanation of how to fix \
    this specific issue (2-4 sentences or a short numbered list as a string).
  "severity_plain": one of "Low", "Medium", "High", "Critical" — your own \
    beginner-friendly read of severity (doesn't have to match the scanner's \
    raw severity label exactly).

Be specific to the code snippet given. Do not be generic."""


@dataclass
class Explanation:
    rule_id: str
    file_path: str
    start_line: int
    plain_summary: str
    why_it_matters: str
    how_to_fix: str
    severity_plain: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AIClient(Protocol):
    """Minimal interface both providers below implement."""
    def complete(self, system_prompt: str, user_prompt: str) -> str: ...


class NvidiaClient:
    """NVIDIA NIM — free, OpenAI-compatible. Default provider."""

    def __init__(self, api_key: str, model: str = DEFAULT_NVIDIA_MODEL):
        import openai  # imported lazily so anthropic-only setups don't need it
        self.model = model
        self._client = openai.OpenAI(base_url=NVIDIA_BASE_URL, api_key=api_key)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            max_tokens=500,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content.strip()


class AnthropicClient:
    """Claude via the Anthropic API — alternate provider."""

    def __init__(self, api_key: str, model: str = DEFAULT_ANTHROPIC_MODEL):
        import anthropic  # imported lazily so nvidia-only setups don't need it
        self.model = model
        self._client = anthropic.Anthropic(api_key=api_key)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=500,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(b.text for b in response.content if b.type == "text").strip()


def _get_client() -> AIClient:
    provider = os.environ.get("AI_PROVIDER", "nvidia").lower()

    if provider == "nvidia":
        api_key = os.environ.get("NVIDIA_API_KEY")
        if not api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY is not set. Get a free key at https://build.nvidia.com "
                '(Get API Key on any model), then run:\n'
                '  export NVIDIA_API_KEY="nvapi-..."'
            )
        model = os.environ.get("NVIDIA_MODEL", DEFAULT_NVIDIA_MODEL)
        return NvidiaClient(api_key, model=model)

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Run:\n"
                '  export ANTHROPIC_API_KEY="your-key-here"'
            )
        model = os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)
        return AnthropicClient(api_key, model=model)

    raise RuntimeError(f"Unknown AI_PROVIDER '{provider}'. Use 'nvidia' or 'anthropic'.")


def _clean_json_text(raw_text: str) -> str:
    """Models sometimes wrap JSON in code fences despite instructions — strip defensively."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    return text


def explain_finding(finding: dict[str, Any], client: AIClient | None = None) -> Explanation:
    """Call the AI API to explain a single raw finding dict."""
    client = client or _get_client()

    user_payload = {
        "rule_id": finding.get("rule_id"),
        "message": finding.get("message"),
        "severity": finding.get("severity"),
        "file_path": finding.get("file_path"),
        "code_snippet": finding.get("code_snippet"),
        "cwe": finding.get("metadata", {}).get("cwe"),
    }

    raw_text = client.complete(SYSTEM_PROMPT, json.dumps(user_payload, indent=2))
    parsed = json.loads(_clean_json_text(raw_text))

    return Explanation(
        rule_id=finding.get("rule_id", "unknown-rule"),
        file_path=finding.get("file_path", "unknown-file"),
        start_line=finding.get("start_line", 0),
        plain_summary=parsed["plain_summary"],
        why_it_matters=parsed["why_it_matters"],
        how_to_fix=parsed["how_to_fix"],
        severity_plain=parsed["severity_plain"],
    )


def explain_findings(findings: list[dict[str, Any]]) -> list[Explanation]:
    """Explain a whole list of raw findings (e.g. loaded from findings.json)."""
    client = _get_client()
    explanations = []
    total = len(findings)
    for i, finding in enumerate(findings, start=1):
        rule = finding.get("rule_id", "unknown-rule")
        print(f"  [{i}/{total}] Explaining {rule} ...", flush=True)
        try:
            explanations.append(explain_finding(finding, client=client))
        except Exception as e:
            print(f"  ! Skipped {finding.get('rule_id')}: {e}", file=sys.stderr)
    return explanations


def save_explanations(explanations: list[Explanation], out_path: str) -> None:
    with open(out_path, "w") as f:
        json.dump([e.to_dict() for e in explanations], f, indent=2)


def print_explanation(exp: Explanation) -> None:
    print(f"\n{'=' * 60}")
    print(f"📍 {exp.file_path}:{exp.start_line}  [{exp.rule_id}]")
    print(f"   Severity: {exp.severity_plain}")
    print(f"\n   What's wrong:\n   {exp.plain_summary}")
    print(f"\n   Why it matters:\n   {exp.why_it_matters}")
    print(f"\n   How to fix it:\n   {exp.how_to_fix}")


if __name__ == "__main__":
    # Usage: python explain.py <path-to-findings.json>
    findings_path = sys.argv[1] if len(sys.argv) > 1 else "findings.json"

    if not Path(findings_path).exists():
        print(f"Could not find {findings_path}. Run core/scanner.py first.")
        sys.exit(1)

    with open(findings_path) as f:
        raw_findings = json.load(f)

    provider = os.environ.get("AI_PROVIDER", "nvidia")
    print(f"Explaining {len(raw_findings)} finding(s) via {provider} ...")
    explanations = explain_findings(raw_findings)

    for exp in explanations:
        print_explanation(exp)

    save_explanations(explanations, "explanations.json")
    print(f"\n\nSaved {len(explanations)} explanation(s) to explanations.json")
