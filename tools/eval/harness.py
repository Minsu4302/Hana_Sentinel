"""평가 하네스 — 동결 데이터셋 + 예측 실행 → 채점 보고. (A) §6.1 판정 단위·매칭, §6.2 라벨 상태, §6.3 지표. `eval_harness`.

범위(정직 표기): 이 하네스가 보장하는 것은 '채점 로직이 정답을 아는 입력에서 정확하고, 최대 매칭을 보장하며, 결정론적'이라는
데까지다(층 A — 손으로 만든 예측 픽스처로 검증). 실제 출력의 채점(층 B)은 러너(`tools.eval.runner`)가 `PredictionRun`으로
넘긴다 — 지금은 rule_only 경로뿐이고, LLM 경로의 층 B는 LLM 결선 이후다.

절차:
1. 데이터: 동결 회귀 검사(버전·엔진 ②③·모드)와 라벨 무결성을 통과한 데이터셋만 채점한다(`tools.dataset`).
2. 예측: 트랜잭션마다 AnalysisResult 또는 "output_rejected". advisory_signals는 채점하지 않는다(탐지가 아님).
   Finding의 CNA 집합 = evidence마다 `canonical_address`(라벨 anchor도 같은 함수 — §6.1 매칭 단위).
3. 중복 처리(§2.4): (category, CNA 집합)이 정확히 같은 Finding은 하나로 병합 — 정렬 키가 가장 앞선 예측을 남긴다.
4. 매칭(§6.1): 매칭 가능 = p.category ∈ V.categories ∧ p.CNA ∩ V.anchors ≠ ∅. 사전순 최소 최대 매칭 — 예측을 정렬 순서로
   보며 매칭 가능한 라벨을 정렬 순서로 시도하고, 그 쌍을 확정한 뒤에도 전체 매칭 수가 최대로 남을 때만 확정한다(증가
   경로로 크기 확인). 탐욕 매칭이 아니다. CNA 순서는 `cna_sort_key`.
5. 지표(§6.3): J1 엄격 P/R(category별 + 전체 micro) + 보조(위치만) P/R + category 혼동 행렬 / J2 output_rejected의 라벨은
   전부 FN + 거부율 / J3 verified_clean 중 finding ≥ 1 비율(hard negative 부분집합 따로) / J4 not_run / J5 보류 / J6 produced_by별
   / J7 Wilson 95% / J8 반폭 > 0.15면 점추정 없음 / J9 보고 머리(rule_only의 model_id·prompt_version은 JSON null 그대로, pipeline_mode 병기). unlabeled 트랜잭션에만 걸린 매칭 안 된 예측은 FP가 아니라
   미판정으로 따로 센다. 매칭 후 남은 중복 예측(매칭된 라벨에 붙을 수 있었던 예측)은 FP이고 중복률로도 보고한다.
한계: finding_id는 서버가 uuid4로 부여하므로 같은 모델 재실행 간 동점 승자가 바뀔 수 있다 — 동점에서는 TP 수가 같아 지표
값과 J7 회귀 판정은 바뀌지 않고 '어느 예측이 TP로 표시되는가'만 달라진다.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from sentinel.canonical_address import CNA, canonical_address, cna_sort_key
from sentinel.output_schema import LLM_FAILURE_REASONS, AnalysisMeta, AnalysisResult, PipelineMode, producer_versions_consistent
from sentinel.pipeline import schema_gate
from sentinel.schema import Transaction
from tools.dataset.freeze import engine_regression_problems, mode_problems, version_freeze_problems
from tools.dataset.labelfile import Label, LabelFile, anchor_problems
from tools.eval.frozen_rulesets import FROZEN_MODELS, FROZEN_PROMPTS, FROZEN_RULESETS

CATEGORIES = ("access_control", "info_exposure", "reflected_injection_indicator", "security_misconfig")
WILSON_Z = 1.959963984540054  # 95%
MAX_HALF_WIDTH = 0.15         # J8 초기 임계값(설정값 — 정본이되 불변식 아님)
OUT_OF_FREEZE_ORDER = "동결 순서 밖 — 측정 아님"


class ServingConditions(BaseModel):
    """J9 서빙 조건. 동결 대상이 아니라 측정 조건 기록이다 — 속도 차이로 생긴 timeout 차이를 모델 차이로 오독하지 않게 한다."""
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    server_version: str
    threads: int
    context: int
    parallel: int
    cpu: str


class RunMeta(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    split: Literal["dev", "test"] | None  # 데이터셋 기록. 기록이 없으면 null(S v1)
    pipeline_mode: PipelineMode
    model_id: str | None
    prompt_version: str | None
    ruleset_version: str
    serving_conditions: ServingConditions | None = None

    @model_validator(mode="after")
    def _versions_match_mode(self) -> Self:
        if not producer_versions_consistent(self.pipeline_mode, self.model_id, self.prompt_version):
            raise ValueError("rule_only ⇔ model_id·prompt_version null")
        if self.pipeline_mode == "rule_only" and self.serving_conditions is not None:
            raise ValueError("rule_only에는 서빙 조건이 없다")
        return self


def _same_producer(run_meta: RunMeta, meta: AnalysisMeta) -> bool:
    return ((run_meta.pipeline_mode, run_meta.model_id, run_meta.prompt_version, run_meta.ruleset_version)
            == (meta.pipeline_mode, meta.model_id, meta.prompt_version, meta.ruleset_version))


class PredictionRun(BaseModel):
    """예측 입력 인터페이스. 층 A는 손으로 만든 픽스처, 층 B는 러너가 만든 실제 생산 출력이 이 자리에 들어온다.
    보고 머리는 결과의 analysis_meta와 같아야 한다 — 머리가 결과를 다르게 말하는 실행은 채점하지 않는다."""
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    run_meta: RunMeta
    results: dict[UUID, AnalysisResult | Literal["output_rejected"]]

    @model_validator(mode="after")
    def _header_matches_results(self) -> Self:
        for r in self.results.values():
            if r == "output_rejected":
                continue
            if not _same_producer(self.run_meta, r.analysis_meta):
                raise ValueError("보고 머리와 결과의 analysis_meta가 다름")
        return self


class DatasetRejected(Exception):
    """채점하지 않는다 — 동결 회귀·라벨 무결성 실패(사유 코드만)."""


@dataclass(frozen=True)
class _Pred:
    finding_id: UUID
    category: str
    cnas: frozenset
    produced_by: str
    status: str = "unverified"
    flagged: bool = False  # evidence 중 하나라도 환각 리터럴 플래그

    @property
    def key(self) -> tuple:  # (category, CNA 집합의 최소 CNA, finding_id)
        return (self.category, cna_sort_key(min(self.cnas, key=cna_sort_key)), str(self.finding_id))


@dataclass(frozen=True, eq=False)  # 라벨마다 하나 — 정체성으로 비교(라벨 모델은 해시 불가)
class _Truth:
    label: Label
    anchors: frozenset

    @property
    def key(self) -> tuple:  # (transaction_ref, 정렬한 categories, anchor CNA 집합의 최소 CNA)
        return (str(self.label.transaction_ref), tuple(sorted(self.label.categories)),
                cna_sort_key(min(self.anchors, key=cna_sort_key)))


# ── 데이터 ─────────────────────────────────────────────────────────

def load_dataset(dataset: Path) -> tuple[LabelFile, dict[UUID, Transaction]]:
    dataset = Path(dataset)
    problems = version_freeze_problems(dataset) + engine_regression_problems(dataset) + mode_problems(dataset)
    if problems:
        raise DatasetRejected(" ".join(sorted(problems)))
    label_file = LabelFile.model_validate_json((dataset / "labels.json").read_bytes())
    txs = {}
    for data in sorted(p.read_bytes() for p in (dataset / "envelopes").glob("*.json")):
        tx = schema_gate.parse_envelope(data).transactions[0]
        txs[tx.meta.transaction_id] = tx
    if problems := anchor_problems(label_file, txs):
        raise DatasetRejected(" ".join(problems))
    return label_file, txs


# ── 매칭 ─────────────────────────────────────────────────────────

def _max_matching_size(preds: list, adj: dict, banned_labels: frozenset) -> int:
    match: dict = {}  # label → pred

    def augment(p, seen: set) -> bool:
        for v in adj[p]:
            if v in banned_labels or v in seen:
                continue
            seen.add(v)
            if v not in match or augment(match[v], seen):
                match[v] = p
                return True
        return False
    return sum(augment(p, set()) for p in preds)


def lexicographic_maximum_matching(preds: list, truths: list, matchable) -> dict:
    """사전순 최소 최대 매칭((A) §6.1). preds·truths는 정렬 키로 정렬된 목록. 반환: pred → truth."""
    adj = {p: [v for v in truths if matchable(p, v)] for p in preds}
    target = _max_matching_size(preds, adj, frozenset())
    chosen: dict = {}
    used: set = set()
    for i, p in enumerate(preds):
        for v in adj[p]:
            if v in used:
                continue
            rest = _max_matching_size(preds[i + 1:], adj, frozenset(used | {v}))
            if len(chosen) + 1 + rest == target:  # 이 쌍을 확정해도 최대가 유지될 때만
                chosen[p] = v
                used.add(v)
                break
    return chosen


def _strict(p: _Pred, v: _Truth) -> bool:
    return p.category in v.label.categories and bool(p.cnas & v.anchors)


def _location_only(p: _Pred, v: _Truth) -> bool:
    return bool(p.cnas & v.anchors)


# ── 지표 ─────────────────────────────────────────────────────────

def wilson(successes: int, n: int) -> dict[str, Any]:
    """J7 Wilson 95% 구간 + J8 표본 판정. 반폭 > 0.15면 점추정값을 내지 않는다."""
    if n == 0:
        return {"value": None, "n": 0, "interval": None, "note": "표본 없음(n=0)"}
    p = successes / n
    denom = 1 + WILSON_Z ** 2 / n
    center = (p + WILSON_Z ** 2 / (2 * n)) / denom
    half = WILSON_Z * math.sqrt(p * (1 - p) / n + WILSON_Z ** 2 / (4 * n * n)) / denom
    interval = [round(center - half, 6), round(center + half, 6)]
    if half > MAX_HALF_WIDTH:
        return {"value": None, "n": n, "interval": interval, "note": f"표본 부족(n={n})"}
    return {"value": round(p, 6), "n": n, "interval": interval, "note": None}


def _pr(tp: int, fp: int, fn: int) -> dict[str, Any]:
    return {"tp": tp, "fp": fp, "fn": fn, "precision": wilson(tp, tp + fp), "recall": wilson(tp, tp + fn)}


def _llm_rates(outcomes: dict[UUID, str | None]) -> dict[str, Any]:
    """J2: LLM 거부율·실패율(사유별)."""
    counts = Counter(outcomes.values())
    return {"rejected": wilson(counts["rejected"], len(outcomes)),
            "failed": {reason: wilson(counts[f"failed:{reason}"], len(outcomes)) for reason in LLM_FAILURE_REASONS}}


ENV_FAILURES: Final = ("failed:unavailable", "failed:oversize", "failed:audit_write")
FLAGGED_NOTE: Final = "치환 횟수의 대리 지표 — 정확한 치환 횟수는 결과에 없다"


def _selection(outcomes: dict[UUID, str | None], preds: list, strict: dict, fps: list, llm_only: list,
               elapsed: list[int]) -> dict[str, Any]:
    """§6.2 모델 선별 기준의 재료(dev — 측정 아님). 실패 합은 ok가 아닌 LLM 결과 전부다: truncated·timeout·unparseable·rejected와
    재실행 뒤에도 남은 환경 실패(unavailable·oversize·audit_write)."""
    judged = {ref: outcome for ref, outcome in outcomes.items() if outcome is not None}  # output_rejected는 규칙 쪽 — LLM 실패가 아니다
    failed = Counter(outcome for outcome in judged.values() if outcome != "ok")
    llm_fp = sum(1 for p in fps if p.produced_by == "llm")
    needs_review = [p for p in preds if p.status == "needs_review"]
    return {"failure": {"count": sum(failed.values()), "rate": wilson(sum(failed.values()), len(judged)),
                        "by_outcome": dict(sorted(failed.items())),
                        "environment_left": sum(n for outcome, n in failed.items() if outcome in ENV_FAILURES)},
            "llm_only_tp": len(llm_only), "llm_fp": llm_fp, "net_gain": len(llm_only) - llm_fp,
            "needs_review": {"count": len(needs_review), "tp": sum(1 for p in needs_review if p in strict),
                             "fp": sum(1 for p in needs_review if p in fps)},
            "flagged_findings": {"count": sum(1 for p in preds if p.flagged), "note": FLAGGED_NOTE},
            "elapsed_ms": {"median": statistics.median(elapsed) if elapsed else None, "max": max(elapsed, default=None)}}


def _clean_rates(clean: list[Label], hard: list[Label], flagged: set, success: set) -> dict[str, Any]:
    """J3의 LLM 성공 부분집합."""
    clean_ok = [x for x in clean if x.transaction_ref in success]
    hard_ok = [x for x in hard if x.transaction_ref in success]
    return {"verified_clean": wilson(sum(1 for x in clean_ok if x.transaction_ref in flagged), len(clean_ok)),
            "hard_negative": wilson(sum(1 for x in hard_ok if x.transaction_ref in flagged), len(hard_ok))}


def _scored_labels(label_file: LabelFile, run: PredictionRun) -> list[Label]:
    """split_scheme이 있으면 split 인자가 필수이고 그 split만 채점한다. 결과도 그 split의 트랜잭션과 같아야 한다."""
    if label_file.split_scheme is None:
        return label_file.labels
    if run.run_meta.split is None:
        raise DatasetRejected("split_required")
    labels = [label for label in label_file.labels if label.split == run.run_meta.split]
    if {label.transaction_ref for label in labels} != set(run.results):
        raise DatasetRejected("results_differ_from_split")
    return labels


def freeze_order(label_file: LabelFile, run_meta: RunMeta) -> str | None:
    """test split이 데이터셋 기록과 다른 ruleset으로 돌았으면 측정이 아니다((A) §6.2 (b))."""
    recorded = label_file.frozen_against
    if run_meta.split != "test":
        return None
    same = (run_meta.ruleset_version == recorded.ruleset_version
            and FROZEN_RULESETS.get(run_meta.ruleset_version) == recorded.ruleset_hash)
    llm_frozen = (run_meta.pipeline_mode != "rule_llm"
                  or (run_meta.prompt_version in FROZEN_PROMPTS and run_meta.model_id in FROZEN_MODELS))
    return None if same and llm_frozen else OUT_OF_FREEZE_ORDER


def score(dataset: Path, run: PredictionRun) -> dict[str, Any]:
    label_file, txs = load_dataset(dataset)
    labels = _scored_labels(label_file, run)
    by_ref = {label.transaction_ref: label for label in labels}  # 한 트랜잭션의 복수 라벨은 모두 labeled_positive — 상태만 읽는다
    rejected = sorted((ref for ref, r in run.results.items() if r == "output_rejected"), key=str)
    raw_preds = [_Pred(f.finding_id, f.category, frozenset(canonical_address(txs[e.transaction_ref], e.pointer)
                                                          for e in f.evidence), f.produced_by, f.status,
                       any(e.anomaly_flags for e in f.evidence))
                 for r in run.results.values() if r != "output_rejected" for f in r.findings]
    groups: dict[tuple, list[_Pred]] = {}
    for p in raw_preds:  # 중복 처리(§2.4): (category, CNA 집합) 정확 일치만 병합
        groups.setdefault((p.category, p.cnas), []).append(p)
    preds = sorted((min(g, key=lambda q: q.key) for g in groups.values()), key=lambda q: q.key)
    truths = sorted((_Truth(label, frozenset(canonical_address(txs[label.transaction_ref], a) for a in label.anchors))
                     for label in labels if label.label_status == "labeled_positive"), key=lambda v: v.key)

    strict = lexicographic_maximum_matching(preds, truths, _strict)
    location = lexicographic_maximum_matching(preds, truths, _location_only)
    matched_truths = set(strict.values())

    def status_of(p: _Pred) -> set[str]:
        return {by_ref[c.transaction_ref].label_status for c in p.cnas if c.transaction_ref in by_ref}

    unmatched = [p for p in preds if p not in strict]
    undetermined = [p for p in unmatched if status_of(p) == {"unlabeled"}]
    fps = [p for p in unmatched if p not in undetermined]
    duplicates = [p for p in fps if any(_strict(p, v) for v in matched_truths)]
    fns = [v for v in truths if v not in matched_truths]

    per_category = {}
    for c in CATEGORIES:
        per_category[c] = _pr(sum(1 for p in strict if p.category == c), sum(1 for p in fps if p.category == c),
                              sum(1 for v in fns if c in v.label.categories))
    confusion = Counter(("+".join(sorted(v.label.categories)), p.category) for p, v in location.items())

    clean = [label for label in labels if label.label_status == "verified_clean"]
    label_counts = Counter(v.label.transaction_ref for v in truths)
    outcomes = {ref: None if r == "output_rejected" else r.analysis_meta.llm_outcome for ref, r in run.results.items()}
    rule_llm = run.run_meta.pipeline_mode == "rule_llm"
    success = {ref for ref, outcome in outcomes.items() if outcome == "ok"}
    flagged = {c.transaction_ref for p in preds for c in p.cnas}
    hard = [label for label in clean if label.hard_negative]
    produced = sorted({p.produced_by for p in preds})
    llm_only = [v for p, v in strict.items() if p.produced_by == "llm"
                and not any(_strict(q, v) for q in preds if q.produced_by != "llm")]

    return {
        "header": {"dataset_id": label_file.dataset_id, "set": "S", "split": run.run_meta.split,
                   "split_note": "분할 없음" if run.run_meta.split is None else None,
                   "dataset_versions": label_file.frozen_against.model_dump(mode="json", exclude={"masking_modes"}),
                   "pipeline_mode": run.run_meta.pipeline_mode, "model_id": run.run_meta.model_id,
                   "prompt_version": run.run_meta.prompt_version,
                   "ruleset_version": run.run_meta.ruleset_version,
                   "serving_conditions": (None if run.run_meta.serving_conditions is None
                                          else run.run_meta.serving_conditions.model_dump(mode="json")),
                   "freeze_order": freeze_order(label_file, run.run_meta)},
        "J1": {"strict": _pr(len(strict), len(fps), len(fns)), "per_category": per_category,
               "location_only": _pr(len(location), len(preds) - len(location) - len(undetermined),
                                    len(truths) - len(set(location.values()))),
               "confusion": sorted([*k, n] for k, n in confusion.items()),
               "multi_label_transactions": sum(1 for n in label_counts.values() if n > 1)},
        "duplicates": {"merged_exact": len(raw_preds) - len(preds), "left_over_fp": len(duplicates),
                       "rate": wilson(len(duplicates), len(preds))},
        "undetermined": len(undetermined),
        "J2": {"output_rejected": [str(r) for r in rejected],
               "fn_from_rejected": sum(1 for v in fns if v.label.transaction_ref in set(rejected)),
               "rejection_rate": wilson(len(rejected), len(run.results)),
               "llm": _llm_rates(outcomes) if rule_llm else None},
        "J3": {"verified_clean": wilson(sum(1 for x in clean if x.transaction_ref in flagged), len(clean)),
               "hard_negative": wilson(sum(1 for x in hard if x.transaction_ref in flagged), len(hard)),
               "llm_success": _clean_rates(clean, hard, flagged, success) if rule_llm else None},
        "J4": "not_run",                        # corroboration_check 미구현 — 숫자 없음
        "J5": "보류(unverifiable — 1인 단계)",   # 정답을 아는 사람이 잰 시간은 거짓 보장
        "J6": {"by_produced_by": {pb: _pr(sum(1 for p in strict if p.produced_by == pb),
                                          sum(1 for p in fps if p.produced_by == pb),
                                          len(truths) - sum(1 for p in strict if p.produced_by == pb))
                                  for pb in produced},
               "llm_only_tp": len(llm_only),
               "llm_success": _pr(sum(1 for v in strict.values() if v.label.transaction_ref in success),
                                  sum(1 for p in fps if {c.transaction_ref for c in p.cnas} & success),
                                  sum(1 for v in fns if v.label.transaction_ref in success)) if rule_llm else None},
        "selection": _selection(outcomes, preds, strict, fps, llm_only,
                                [r.analysis_meta.elapsed_ms for r in run.results.values() if r != "output_rejected"]) if rule_llm else None,
        "J7": {"method": "wilson95", "version_comparison": "비교할 실행 없음(단일 실행)"},
        "matches": sorted([str(p.finding_id), str(v.label.transaction_ref)] for p, v in strict.items()),
    }
