"""java_jar_contents — 배포 jar 검사((A) §3.1). '위조 거부'로 증명한다.

실제 jar(make verify의 Java 단계 산출물)를 검사하고, 그 jar를 임시 폴더에서 한 군데씩 고쳐 만든 위조본이 정확한 코드로
거부되는지 본다. 재현 가능 빌드는 레포 밖 임시 복사본 두 곳에서 `gradlew --offline jar`를 돌려 세 jar(실제·복사본 2)의
해시가 같은지로 본다. 변이 확인은 변이본 로드 표지를 먼저 확인한다.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sentinel import sanitization_policy
from tools import java_build
from tools import java_jar as jj
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / "burp-extension"


def _gradle_home() -> Path:
    home = os.environ.get("GRADLE_USER_HOME")
    assert home, "GRADLE_USER_HOME 없음 — jar 검사는 의존성 캐시의 고정 gson jar가 필요하다(건너뛰지 않는다)"
    return Path(home)


def _check(jar: Path) -> set[str]:
    return {v.code for v in jj.violations(jar, PROJECT, jj.pinned_gson_jar(PROJECT, _gradle_home()),
                                          sanitization_policy.POLICY_PATH)}


# ─────────────────────────────── 실제 jar
def test_real_jar_passes_every_check():
    assert jj.violations(jj.built_jar(PROJECT), PROJECT, jj.pinned_gson_jar(PROJECT, _gradle_home()),
                         sanitization_policy.POLICY_PATH) == []


def test_real_jar_has_no_error_prone_no_harness_and_no_gson_meta_inf():
    names = zipfile.ZipFile(jj.built_jar(PROJECT)).namelist()
    assert not [n for n in names if "errorprone" in n.lower()]
    assert not [n for n in names if "ParityHarness" in n or "RawEnvelopeJson" in n]
    assert not [n for n in names if n.startswith("META-INF/") and n not in
                ("META-INF/", "META-INF/MANIFEST.MF", "META-INF/licenses/", "META-INF/licenses/gson-LICENSE.txt")]
    assert jj.POLICY_ENTRY in names


def test_jar_is_built_by_the_default_jar_task_only():
    build = (PROJECT / "build.gradle").read_text(encoding="utf-8")
    assert "duplicatesStrategy = DuplicatesStrategy.FAIL" in build
    assert "preserveFileTimestamps = false" in build and "reproducibleFileOrder = true" in build
    assert "include 'com/google/gson/**'" in build


# ─────────────────────────────── 위조 픽스처
def _rewrite(src: Path, dst: Path, *, add: dict[str, bytes] | None = None, replace: dict[str, bytes] | None = None,
             drop: tuple[str, ...] = (), stamp: dict[str, tuple] | None = None, duplicate: str | None = None) -> Path:
    """jar를 항목 단위로 다시 쓴다(고친 곳 말고는 이름·순서·시각·압축 방식 그대로)."""
    add, replace, stamp = add or {}, replace or {}, stamp or {}
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            data = replace.get(info.filename, zin.read(info.filename))
            new = zipfile.ZipInfo(info.filename, date_time=stamp.get(info.filename, info.date_time))
            new.compress_type = info.compress_type
            zout.writestr(new, data)
            if info.filename == duplicate:
                zout.writestr(zipfile.ZipInfo(info.filename, date_time=info.date_time), data)
        for name, data in add.items():
            zout.writestr(zipfile.ZipInfo(name, date_time=jj.FIXED_TIME), data)
    return dst


GSON_CLASS = "com/google/gson/Gson.class"
FIXTURES = {
    "extra_entry": (dict(add={"sentinel/burp/notes.txt": b"dummy"}), "entry_not_allowed"),
    "error_prone_entry": (dict(add={"com/google/errorprone/annotations/InlineMe.class": b"\xca\xfe\xba\xbe"}),
                          "error_prone_entry"),
    "harness_class_included": (dict(add={"sentinel/burp/transport/masker/ParityHarness.class": b"\xca\xfe\xba\xbe"}),
                               "entry_not_allowed"),
    "policy_tampered": (dict(replace={jj.POLICY_ENTRY: b'{"policy_version":"dummy","header_rules":[]}'}), "policy_mismatch"),
    "gson_entry_tampered": (dict(replace={GSON_CLASS: b"\xca\xfe\xba\xbe dummy"}), "gson_entry_mismatch"),
    "timestamp_not_fixed": (dict(stamp={GSON_CLASS: (2026, 11, 25, 9, 30, 0)}), "timestamp_not_fixed"),
    "license_tampered": (dict(replace={"META-INF/licenses/gson-LICENSE.txt": b"dummy license"}), "license_mismatch"),
    "gson_entry_removed": (dict(drop=(GSON_CLASS,)), "gson_entry_missing"),
    "duplicate_entry": (dict(duplicate=jj.POLICY_ENTRY), "duplicate_entry"),
}


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_jar_fixture_is_rejected(tmp_path, name):
    kwargs, expected = FIXTURES[name]
    if name == "duplicate_entry":
        import warnings
        warnings.simplefilter("ignore", UserWarning)  # zipfile의 중복 이름 경고 — 위조가 의도다
    forged = _rewrite(jj.built_jar(PROJECT), tmp_path / "forged.jar", **kwargs)
    assert expected in _check(forged), name


def test_unchanged_rewrite_passes_as_control(tmp_path):
    """대조: 위조 장치로 아무것도 바꾸지 않고 다시 쓴 jar는 통과한다 — 거부가 장치 탓이 아님을 보인다."""
    assert _check(_rewrite(jj.built_jar(PROJECT), tmp_path / "same.jar")) == set()


def test_missing_jar_or_license_folder_is_an_error_not_a_pass(tmp_path):
    with pytest.raises(ValueError):
        jj.built_jar(tmp_path)
    project = tmp_path / "burp-extension"
    shutil.copytree(PROJECT, project, ignore=shutil.ignore_patterns("build", ".gradle"))
    shutil.rmtree(project / "licenses")
    codes = {v.code for v in jj.violations(jj.built_jar(PROJECT), project, jj.pinned_gson_jar(PROJECT, _gradle_home()),
                                           sanitization_policy.POLICY_PATH)}
    assert {"license_missing", "entry_not_allowed"} <= codes


# ─────────────────────────────── 재현 가능 빌드: 같은 입력 → 같은 jar 해시
def _build_copy(root: Path) -> Path:
    project = root / "burp-extension"
    shutil.copytree(PROJECT, project, ignore=shutil.ignore_patterns("build", ".gradle"))
    (root / "src" / "sentinel").mkdir(parents=True)
    shutil.copyfile(sanitization_policy.POLICY_PATH, root / "src" / "sentinel" / "sanitization_policy.json")
    env = dict(os.environ)
    assert java_build.preflight(env, project) == [], "Java 단계 사전 점검 실패(JDK 21·배포판 캐시·wrapper 고정값)"
    gradlew = project / ("gradlew.bat" if os.name == "nt" else "gradlew")
    r = subprocess.run([str(gradlew), "--offline", "--no-daemon", "--console=plain", "jar"], cwd=project, env=env,
                       capture_output=True, timeout=600)
    assert r.returncode == 0, "임시 복사본의 오프라인 jar 빌드 실패"
    return jj.built_jar(project)


def test_two_builds_from_the_same_input_give_the_same_jar(tmp_path):
    a = _build_copy(tmp_path / "a")
    b = _build_copy(tmp_path / "b")
    assert jj.sha256(a) == jj.sha256(b) == jj.sha256(jj.built_jar(PROJECT))


# ─────────────────────────────── 변이 확인(변이본 로드 표지 확인 후 결과 해석)
STAMP = "java_jar_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_java_jar_contents.py::"
MUTATIONS = {
    # 변이 4: jar 허용 집합 검사 끔 → 여분 항목 픽스처가 실패해야 한다
    "jar_allowlist_off": ("tools.java_jar", "            elif not _allowed_file(n, roots, licenses):\n",
                          "            elif False:\n", [_T + "test_jar_fixture_is_rejected[extra_entry]"]),
    "gson_bytes_check_off": ("tools.java_jar", "            if z.read(n) != g.read(n):\n", "            if False:\n",
                             [_T + "test_jar_fixture_is_rejected[gson_entry_tampered]"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_jar_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    module, old, new, nodes = MUTATIONS[name]
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", module.replace(".", "/") + ".py", old, new)
    env = {**os.environ, "PYTHONUTF8": "1",
           "PYTHONPATH": os.pathsep.join([str(tmp_path / "mut"), str(REPO_ROOT / "src"), str(REPO_ROOT)])}
    env.pop("PYTEST_ADDOPTS", None)
    r = subprocess.run([sys.executable, "-c", _DRIVER.replace("{STAMP}", STAMP), module, *nodes],
                       cwd=REPO_ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=600)
    out = r.stdout + r.stderr
    assert_loaded_from(out, STAMP, mutant)
    assert r.returncode == 1, f"변이 {name}가 살아남음\n{out}"
    for node in nodes:
        assert f"FAILED {node}" in out, f"{node}가 변이본에서 실패하지 않음\n{out}"
