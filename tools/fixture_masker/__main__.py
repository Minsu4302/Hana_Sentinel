"""CLI. 출력은 사유 코드와 개수뿐이다 — 경로·값·트레이스백을 쓰지 않는다(원본 조각이 실릴 수 있다)."""
from __future__ import annotations

import argparse
import sys

from tools.fixture_masker.masker import MaskerRejected, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fixture_masker", description="원본(레포 밖) → 마스킹된 Envelope")
    parser.add_argument("raw_path")
    parser.add_argument("out_dir")
    args = parser.parse_args(argv)
    try:
        count = run(args.raw_path, args.out_dir)
    except MaskerRejected as exc:
        print(f"fixture_masker rejected: {exc.code}", file=sys.stderr)
        return 2
    except Exception:  # 예상 밖 오류도 유형 이름조차 쓰지 않는다(메시지·트레이스백에 원본 조각 가능)
        print("fixture_masker failed: internal_error", file=sys.stderr)
        return 3
    print(f"fixture_masker masked transactions={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
