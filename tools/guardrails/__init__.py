"""가드레일 SSOT 도구: (A) §3 → guardrails.yaml → capability manifest."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "docs" / "design-decision.md"
REGISTRY_PATH = REPO_ROOT / "guardrails.yaml"
MANIFEST_PATH = REPO_ROOT / "manifest" / "capability_manifest.json"
