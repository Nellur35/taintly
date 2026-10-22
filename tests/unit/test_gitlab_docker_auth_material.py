"""Source-value contrasts for GitLab registry-auth configuration."""

from taintly.rules.gitlab.sec2_sec4_sec6_sec8_sec9_sec10 import DockerAuthMaterialPattern


def _lines(source: str) -> list[int]:
    return [line for line, _ in DockerAuthMaterialPattern().check(source, source.splitlines())]


def test_inline_auth_material_remains_a_finding():
    source = 'variables:\n  DOCKER_AUTH_CONFIG: \'{"auths":{"example":{"auth":"abc"}}}\'\n'
    assert _lines(source) == [2]


def test_exact_variable_references_have_no_inline_material_finding():
    source = (
        'variables:\n  DOCKER_AUTH_CONFIG: "${REGISTRY_AUTH}"\n'
        "job:\n  variables:\n    DOCKER_AUTH_CONFIG: $OTHER_AUTH\n"
    )
    assert _lines(source) == []


def test_mixed_values_and_aliases_stay_unresolved():
    source = (
        "variables:\n"
        '  DOCKER_AUTH_CONFIG: "${AUTH:-fallback}"\n'
        '  DOCKER_AUTH_CONFIG: "${AUTH} suffix"\n'
        "  DOCKER_AUTH_CONFIG: *auth_alias\n"
    )
    assert _lines(source) == [2, 3, 4]


def test_same_file_alias_to_inline_auth_keeps_finding():
    source = (
        "variables:\n"
        '  AUTH_JSON: \'{"auths":{"example":{"auth":"abc"}}}\'\n'
        '  DOCKER_AUTH_CONFIG: "${AUTH_JSON}"\n'
    )
    assert _lines(source) == [3]


def test_comment_and_invalid_unquoted_reference_do_not_claim_auth_material():
    source = "variables:\n  # DOCKER_AUTH_CONFIG: secret\n  DOCKER_AUTH_CONFIG:$AUTH\n"
    assert _lines(source) == []
