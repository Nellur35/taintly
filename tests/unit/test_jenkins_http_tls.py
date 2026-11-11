import pytest

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.jenkins.http_tls import HttpRequestTLSOptionPattern


def check(source):
    return HttpRequestTLSOptionPattern().check(source, source.splitlines())


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ("httpRequest url: 'https://example.invalid', ignoreSslErrors: true", 1),
        ("node { httpRequest(url: 'https://example.invalid',\nignoreSslErrors: true) }", 2),
        ("httpRequest url: 'https://example.invalid',\n\nignoreSslErrors: true", 3),
        ("def response = httpRequest(['ignoreSslErrors': true, url: endpoint,])", 1),
        ("httpRequest(customHeaders: [[name: 'X-Trace', value: 'abc']], ignoreSslErrors: true)", 1),
        ("httpRequest(ignoreSslErrors: true).content", 1),
        ("httpRequest(url: 'https://example.invalid', // comment\nignoreSslErrors: true)", 2),
        ("httpRequest ignoreSslErrors: true // comment", 1),
    ],
)
def test_bypass_belongs_to_direct_call_and_literal_option(source, line):
    assert check(source) == [(line, source.splitlines()[line - 1].strip())]
    assert not isinstance(check(source), IncompletePatternMatches)


@pytest.mark.parametrize(
    "source",
    [
        "echo 'httpRequest(ignoreSslErrors: true)'",
        'echo "httpRequest(ignoreSslErrors: true)"',
        "println(/httpRequest(ignoreSslErrors: true)/)",
        'sh """httpRequest(ignoreSslErrors: true)"""',
        "// httpRequest(ignoreSslErrors: true)",
        "/* httpRequest(ignoreSslErrors: true) */",
        "def config = [httpRequest: [ignoreSslErrors: true]]",
        "otherCall(ignoreSslErrors: true)",
        "httpRequest(requestBody: [ignoreSslErrors: true])",
        "httpRequest('https://example.invalid')",
        "httpRequest(ignoreSslErrors: false)",
        "new httpRequest(ignoreSslErrors: true)",
    ],
)
def test_data_or_no_bypass_has_no_claim(source):
    matches = check(source)
    assert matches == []
    assert not isinstance(matches, IncompletePatternMatches)


@pytest.mark.parametrize(
    "source",
    [
        "httpRequest(ignoreSslErrors: params.BYPASS)",
        "httpRequest(ignoreSslErrors: true && false)",
        "httpRequest(ignoreSslErrors: True)",
        "httpRequest(ignoreSslErrors: true  # comment\n)",
        "httpRequest(ignoreSslErrors: 'true')",
        "httpRequest(ignoreSslErrors: true, ignoreSslErrors: false)",
        "httpRequest(ignoreSslErrors: true, *:options)",
        "httpRequest(options)",
        "httpRequest ignoreSslErrors: true,",
        "httpRequest(ignoreSslErrors: true",
        "client.httpRequest(ignoreSslErrors: true)",
        "client.\nhttpRequest(ignoreSslErrors: true)",
        "def httpRequest(args) { args }; httpRequest(ignoreSslErrors: true)",
        "def httpRequest(args)\n{ args }\nhttpRequest(ignoreSslErrors: true)",
        "def httpRequest = { args -> args }; httpRequest(ignoreSslErrors: true)",
        "node { httpRequest -> httpRequest(ignoreSslErrors: true) }",
        "import static custom.Client.*\nhttpRequest(ignoreSslErrors: true)",
        "httpRequest(ignoreSslErrors: true) { echo 'example' }",
        'echo "${httpRequest(ignoreSslErrors: true)}"',
        'this."${name}"(ignoreSslErrors: true)',
        "config: |\n  httpRequest(ignoreSslErrors: true)",
        pytest.param(
            "// padding\n" * 6000 + "httpRequest(ignoreSslErrors: true)",
            id="beyond-source-limit",
        ),
    ],
)
def test_unresolved_syntax_or_binding_is_partial(source):
    matches = check(source)
    assert matches == []
    assert isinstance(matches, IncompletePatternMatches)
    assert matches.reason


def test_generic_mutations_cannot_turn_non_equivalent_groovy_into_positives():
    applicable = HttpRequestTLSOptionPattern.self_test_mutation_applicable
    source = "httpRequest(ignoreSslErrors: true, url: 'https://example.invalid')"
    assert not applicable(source, source.replace("true", "True"), "case_change")
    assert not applicable(source, source + "  # comment", "comment_inject")
    assert applicable(source, source + "  // comment", "comment_inject")
    with_string = source.replace("example.invalid", "true.example.invalid")
    assert applicable(with_string, with_string.replace("true", "True"), "case_change")
    assert applicable("echo '''text\n'''", "echo '''text  # comment\n'''", "comment_inject")


def test_report_keeps_the_proved_call_and_names_the_unresolved_one(tmp_path, jenkins_rules):
    path = tmp_path / "Jenkinsfile"
    path.write_text(
        "node {\n"
        "  echo 'httpRequest(ignoreSslErrors: true)'\n"
        "  httpRequest(url: 'https://example.invalid',\n"
        "    ignoreSslErrors: true)\n"
        "  client.httpRequest(ignoreSslErrors: true)\n"
        "  httpRequest(ignoreSslErrors: params.BYPASS)\n"
        "}\n",
        encoding="utf-8",
    )
    report = scan_repo(str(tmp_path), jenkins_rules, platform=Platform.JENKINS)[0]
    findings = [f for f in report.findings if f.rule_id == "SEC6-JK-009"]
    assert [(f.line, f.severity.value) for f in findings] == [(4, "HIGH")]
    [diagnostic] = [
        f for f in report.findings if f.rule_id == "ENGINE-ERR" and "SEC6-JK-009" in f.title
    ]
    assert "line 5: source ownership" in diagnostic.description
    assert "line 6: unresolved ignoreSslErrors value" in diagnostic.description
