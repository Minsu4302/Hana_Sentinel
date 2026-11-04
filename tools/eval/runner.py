"""층 B 러너 — 동결 데이터셋의 Envelope를 실제 ②③④(`sentinel.pipeline.entry.analyze`)로 통과시켜 채점한다. `make eval`.

프로세스 안에서만 돈다(HTTP·소켓 없음 — `tools_no_external_send`). ①(토큰)은 전송 경계라 건너뛴다. 규칙 엔진을 직접 부르지
않는다 — ②③을 건너뛰는 경로가 된다. 라벨은 이쪽(tools)만 읽는다.

보고 머리(J9):
- pipeline_mode·model_id·prompt_version·ruleset_version은 결과의 analysis_meta에서만 읽는다. 러너 상수로 채우지 않는다.
  일부 거부면 남은 메타로 읽고, 메타끼리 다르면 거부한다. 전부 거부되면 메타가 없으므로 보고서를 내지 않는다.
- split: split_scheme이 있는 데이터셋은 인자가 필수이고 그 split만 채점한다. 없으면 null이고(S v1) 인자를 주면 거부한다.

결정론: 보고서에는 finding_id를 남기지 않는다(서버가 uuid4로 부여) — 같은 입력이면 같은 보고다.
범위: S v1 위의 결과는 측정이 아니라 동작 확인이다((A) §6.2 — S v1은 규칙에 대해 오염된 스모크 집합).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import ValidationError

from sentinel.manifest_snapshot import load_manifest_snapshot
from sentinel.output_schema import AnalysisResult
from sentinel.pipeline import entry, sanitization_check, schema_gate
from tools.dataset.labelfile import LabelFile
from tools.eval.harness import DatasetRejected, PredictionRun, RunMeta, load_dataset, score

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET: Final = REPO_ROOT / "datasets" / "S" / "v1"
DEFAULT_OUT_DIR: Final = REPO_ROOT / "reports" / "eval"  # gitignore — 커밋하지 않는다

Prediction = AnalysisResult | Literal["output_rejected"]


class RunRejected(Exception):
    """보고서를 내지 않는다(사유 코드만)."""


def selected_split(label_file: LabelFile, split: str | None) -> str | None:
    if label_file.split_scheme is None:
        if split is not None:
            raise RunRejected("split_differs_from_dataset")
        return None
    if split is None:
        raise RunRejected("split_required")
    if not any(label.split == split for label in label_file.labels):
        raise RunRejected("split_differs_from_dataset")
    return split


def predictions(raws: Iterable[bytes], manifest_snapshot: dict[str, Any]) -> dict[UUID, Prediction]:
    results: dict[UUID, Prediction] = {}
    for raw in raws:
        try:
            response = entry.analyze(raw, manifest_snapshot)
        except (schema_gate.SchemaRejected, sanitization_check.SanitizationRejected):
            raise RunRejected("input_rejected") from None
        ref = UUID(json.loads(raw)["transactions"][0]["meta"]["transaction_id"])
        if response.analysis_status == "output_rejected":
            results[ref] = "output_rejected"
        elif response.analysis_status == "completed" and response.result.analyzed_refs == (ref,):
            results[ref] = response.result
        else:
            raise RunRejected("unexpected_response")
    return results


def _run_meta(results: dict[UUID, Prediction], split: str | None) -> RunMeta:
    metas = [r.analysis_meta for r in results.values() if r != "output_rejected"]
    if not metas:
        raise RunRejected("all_output_rejected")
    return RunMeta(split=split, pipeline_mode=metas[0].pipeline_mode, model_id=metas[0].model_id,
                   prompt_version=metas[0].prompt_version, ruleset_version=metas[0].ruleset_version)


def run(dataset: Path, manifest_snapshot: dict[str, Any], split: str | None = None) -> dict[str, Any]:
    dataset = Path(dataset)
    label_file, _txs = load_dataset(dataset)
    chosen = selected_split(label_file, split)
    refs = {str(label.transaction_ref) for label in label_file.labels if chosen is None or label.split == chosen}
    paths = [p for p in sorted((dataset / "envelopes").glob("*.json")) if p.stem in refs]
    results = predictions((p.read_bytes() for p in paths), manifest_snapshot)
    run_meta = _run_meta(results, chosen)
    try:
        prediction_run = PredictionRun(run_meta=run_meta, results=results)
    except ValidationError:
        raise RunRejected("analysis_meta_disagrees") from None
    report = score(dataset, prediction_run)
    return {**report, "matches": sorted(ref for _finding_id, ref in report["matches"])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="동결 데이터셋을 실제 ②③④로 통과시켜 채점한다")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--split", choices=("dev", "test"))
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args(argv)
    try:
        report = run(args.dataset, load_manifest_snapshot(), args.split)
    except (RunRejected, DatasetRejected) as exc:
        print(f"eval 거부: {exc}", file=sys.stderr)
        return 1
    args.out_dir.mkdir(parents=True, exist_ok=True)
    suffix = f".{report['header']['split']}" if report["header"]["split"] else ""
    path = args.out_dir / f"{report['header']['dataset_id']}{suffix}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"header": report["header"], "strict": {k: report["J1"]["strict"][k] for k in ("tp", "fp", "fn")},
                      "J2": report["J2"]["fn_from_rejected"], "J3": report["J3"]}, ensure_ascii=False, indent=2))
    print(f"보고서: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
