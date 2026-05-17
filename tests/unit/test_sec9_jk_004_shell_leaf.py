"""SEC9-JK-004 — download-pipe-to-interpreter inside a Jenkinsfile shell sink.

Pins the structural-reader-backed predicate so the rule fires on the
shapes SEC9-JK-001 cannot reach (non-shell interpreter pipes,
``bash <(curl ...)`` process substitution, PowerShell
``iex(IWR ...)``) and does NOT fire when the same substring
appears in unrelated string literals or when the script body
contains a safe ``curl ... -o file`` + ``sha256sum --check`` +
``bash file`` sequence.

The module is gated on the optional ``[jenkins-structural]`` extra
the same way ``tests/unit/test_jenkinsfile_walker.py`` is — when
``tree_sitter_groovy`` isn't installed, the tests skip cleanly and
the rule simply does not fire on user files either (default-install
behaviour, by design).
"""

from __future__ import annotations

from pathlib import Path

import pytest


pytest.importorskip("tree_sitter_groovy")


from taintly.engine import scan_file  # noqa: E402
from taintly.models import Platform  # noqa: E402
from taintly.rules.registry import load_rules_for_platform  # noqa: E402


@pytest.fixture(scope="module")
def jenkins_rules():
    return load_rules_for_platform(Platform.JENKINS)


def _write(tmp_path: Path, content: str) -> Path:
    target = tmp_path / "Jenkinsfile"
    target.write_text(content, encoding="utf-8")
    return target


def _ids(findings):
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Positive cases — the four walker-only shapes the rule unlocks.
# ---------------------------------------------------------------------------


def test_fires_on_curl_pipe_python3(tmp_path, jenkins_rules):
    """Non-shell interpreter pipe — SEC9-JK-001's ``\\|\\s*(ba)?sh``
    regex stops at the shell-only suffix, so this is walker-only."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh 'curl -fsSL https://x.com/i.py | python3'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_bash_process_substitution(tmp_path, jenkins_rules):
    """``bash <(curl ...)`` has no ``|`` token between curl and bash,
    so the SEC9-JK-001 regex misses it; walker-backed predicate
    catches the process-substitution shape."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh 'bash <(curl -fsSL https://x.com/i.sh)'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_powershell_iex_invoke_webrequest(tmp_path, jenkins_rules):
    """Windows-agent equivalent of curl|bash: PowerShell
    ``iex(Invoke-WebRequest ...)`` runs the downloaded body."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent { label 'windows' }\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        powershell 'iex(Invoke-WebRequest -Uri "
        "https://x.com/s.ps1).Content'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_iwr_pipe_iex(tmp_path, jenkins_rules):
    """Alt arrangement: ``IWR ... | iex`` — same threat shape as
    ``iex(IWR ...)``."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent { label 'windows' }\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        powershell 'iwr -useb https://x.com/s.ps1 | iex'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_multiline_triple_quoted_curl_pipe_bash(tmp_path, jenkins_rules):
    """The line-scoped SEC9-JK-001 regex sees ``sh \"\"\"`` on the
    opener line and a separate ``curl ... | bash`` line; the per-line
    regex can never combine them.  The structural reader presents
    the full body as a single string so the predicate sees it."""
    triple = '"' * 3
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        f"        sh {triple}\n"
        "            echo start\n"
        "            curl -fsSL https://x.com/i.sh | bash\n"
        "            echo done\n"
        f"        {triple}\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


# ---------------------------------------------------------------------------
# Negative cases — the FP shapes the structural-reader scoping rules out.
# ---------------------------------------------------------------------------


def test_does_not_fire_on_safe_fetch_verify_execute(tmp_path, jenkins_rules):
    """Safe pattern: download to file, sha256sum --check, then bash
    file.  No ``curl ... | interpreter``, no process substitution.
    Must not fire."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh '''\n"
        "            curl -fsSL https://x.com/i.sh -o i.sh\n"
        "            echo 'abc i.sh' | sha256sum --check\n"
        "            bash i.sh\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_two_step_wget_then_bash(tmp_path, jenkins_rules):
    """May-18 audit on apache/cassandra ``.jenkins/Jenkinsfile``:

        sh '''
            wget -q ${agentScriptsUrl}/docker_agent_cleaner.sh
            bash docker_agent_cleaner.sh ${maxBuildHours}
        '''

    Download on line A, ``bash <file>`` on line B (not piped), no
    checksum verification — the classic two-step LOTP supply-chain
    shape that motivated the SEC9-JK family.  SEC9-JK-001 needs the
    pipe on one line; SEC9-JK-003 needs wget + filename on the same
    line as ``sh``; neither sees the two commands on different lines
    inside one triple-quoted body.  SEC9-JK-004 owns the structural
    cross-line view.
    """
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('clean') {\n"
        "      steps {\n"
        "        sh '''\n"
        "            wget -q https://example.com/agent_scripts/cleaner.sh\n"
        "            bash cleaner.sh 6\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_fires_on_two_step_curl_then_python(tmp_path, jenkins_rules):
    """Same two-step shape with Python instead of bash — interpreter
    diversity matters because the cassandra fixture also downloads
    ``docker_image_pruner.py``."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh '''\n"
        "            curl -fsSL https://e.com/setup.py -o setup.py\n"
        "            python setup.py install\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" in _ids(scan_file(str(f), jenkins_rules))


def test_does_not_fire_on_two_step_with_sha256_verify(tmp_path, jenkins_rules):
    """The two-step exec shape with an in-band sha256sum verification
    in between is the documented safe form — must not fire (presumed
    verified)."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh '''\n"
        "            wget -q https://example.com/installer.sh\n"
        "            sha256sum -c installer.sh.sha256\n"
        "            bash installer.sh\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


def test_does_not_fire_on_two_step_with_cosign_verify_blob(tmp_path, jenkins_rules):
    """cosign verify-blob is the sigstore equivalent of sha256sum --check
    for blob artifacts.  The two-step shape gated by cosign verify
    must not fire — same exemption rationale as sha256sum above."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh '''\n"
        "            curl -fsSL https://e.com/release.sh -o release.sh\n"
        "            cosign verify-blob --signature release.sh.sig release.sh\n"
        "            bash release.sh\n"
        "        '''\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


def test_does_not_fire_on_curl_pipe_jq(tmp_path, jenkins_rules):
    """``curl ... | jq`` — jq is not an interpreter; the predicate
    must NOT classify it as a download-pipe-to-RCE."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        sh 'curl -s https://api.x.com/v1 | jq .ok'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


def test_does_not_fire_on_literal_string_outside_shell(tmp_path, jenkins_rules):
    """The substring ``curl ... | bash`` appears inside an
    ``environment { DOC = '...' }`` value (Groovy string, not a
    shell body).  Walker yields ``value_kind='string'``, not
    ``'shell'``, so our predicate never sees it — this is the
    primary FP class the structural reader closes."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  environment {\n"
        "    DOC_NOTE = 'avoid curl https://x | bash patterns'\n"
        "  }\n"
        "  stages {\n"
        "    stage('s') { steps { sh 'make' } }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


def test_does_not_fire_on_commented_shell_sink(tmp_path, jenkins_rules):
    """Groovy ``//`` comment containing the offending shape — the
    walker doesn't emit a LEAF for commented-out code, so the rule
    must stay silent."""
    f = _write(
        tmp_path,
        "pipeline {\n"
        "  agent any\n"
        "  stages {\n"
        "    stage('s') {\n"
        "      steps {\n"
        "        // sh 'curl https://x.com/i.sh | bash'\n"
        "        sh 'make'\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    assert "SEC9-JK-004" not in _ids(scan_file(str(f), jenkins_rules))


# ---------------------------------------------------------------------------
# Failure-soft contract — predicate must survive walker / parser hiccups.
# ---------------------------------------------------------------------------


def test_returns_empty_on_unparseable_input():
    """Malformed Jenkinsfile produces a CUTOFF from the walker; the
    pattern must honour that and return no findings rather than
    raising."""
    from taintly.rules.jenkins.sec_jenkins import (
        _JenkinsfileShellLeafPattern,
        _sec9_jk_004_predicate,
    )

    pat = _JenkinsfileShellLeafPattern(_sec9_jk_004_predicate)
    garbled = "pipeline { agent any { { { unclosed"
    assert pat.check(garbled, garbled.splitlines()) == []


def test_returns_empty_on_empty_input():
    from taintly.rules.jenkins.sec_jenkins import (
        _JenkinsfileShellLeafPattern,
        _sec9_jk_004_predicate,
    )

    pat = _JenkinsfileShellLeafPattern(_sec9_jk_004_predicate)
    assert pat.check("", []) == []
