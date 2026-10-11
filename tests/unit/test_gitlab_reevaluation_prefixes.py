"""SEC4-GL-006 tracks CI variables through shell re-evaluation prefixes."""

from taintly.rules.gitlab.sec1_sec4_sec6_sec7_sec9 import RULES
from taintly.rules.gitlab.sec3_sec6_supply_chain_creds import RULES as SEC6_RULES


def _hits(source: str) -> list[tuple[int, str]]:
    rule = next(rule for rule in RULES if rule.id == "SEC4-GL-006")
    return rule.pattern.check(source, source.splitlines())


def test_eval_detects_attacker_variable_after_nested_quoted_prefix() -> None:
    source = """build:
  script:
    - eval "echo 'prefix' $CI_COMMIT_MESSAGE"
"""
    assert len(_hits(source)) == 1


def test_shell_c_detects_variable_after_nested_quotes_and_title_source() -> None:
    source = """build:
  script:
    - bash -c "printf '%s' 'prefix' $CI_COMMIT_TITLE"
"""
    assert len(_hits(source)) == 1


def test_shell_c_detects_double_quoted_nested_variable() -> None:
    source = """build:
  script:
    - sh -c "echo \\"prefix $CI_COMMIT_BRANCH\\""
"""
    assert len(_hits(source)) == 1


def test_hash_inside_double_quoted_prefix_does_not_start_a_comment() -> None:
    source = """build:
  script:
    - eval "echo # quoted prefix $CI_COMMIT_MESSAGE"
"""
    assert len(_hits(source)) == 1


def test_single_quoted_literal_and_shell_c_positional_argument_are_safe() -> None:
    source = """build:
  script:
    - eval 'echo $CI_COMMIT_MESSAGE'
    - bash -c 'printf "%s" "$1"' -- "$CI_COMMIT_TITLE"
"""
    assert _hits(source) == []


def test_single_quoted_deferred_command_position_sources_remain_findings() -> None:
    source = """build:
  script:
    - eval '$CI_COMMIT_MESSAGE'
    - bash -c '$CI_MERGE_REQUEST_TITLE'
    - eval 'echo safe; $CI_COMMIT_BRANCH'
"""
    assert len(_hits(source)) == 3


def test_single_quoted_deferred_data_arguments_remain_safe() -> None:
    source = """build:
  script:
    - eval 'echo "$CI_COMMIT_MESSAGE"'
    - bash -c 'printf "%s" "$CI_MERGE_REQUEST_TITLE"'
    - sh -c 'do_thing $CI_COMMIT_TAG'
"""
    assert _hits(source) == []


def test_delayed_source_detects_command_after_real_shell_separator() -> None:
    source = """build:
  script:
    - eval 'echo safe; $CI_COMMIT_MESSAGE'
    - bash -c 'echo safe && $CI_MERGE_REQUEST_TITLE'
"""
    assert len(_hits(source)) == 2


def test_yaml_marker_keywords_and_quoted_operators_do_not_create_boundaries() -> None:
    source = """build:
  script:
    - eval 'echo - $CI_COMMIT_MESSAGE'
    - eval 'echo then $CI_COMMIT_TITLE'
    - echo then eval "$CI_COMMIT_BRANCH"
    - bash -c 'printf "%s" ";" $CI_MERGE_REQUEST_TITLE'
"""
    assert _hits(source) == []


def test_safe_shell_c_does_not_hide_later_reevaluation_sink() -> None:
    source = """build:
  script:
    - bash -c 'printf ok'; eval "$CI_COMMIT_MESSAGE"
"""
    assert len(_hits(source)) == 1


def test_constant_eval_and_comment_are_not_findings() -> None:
    source = """build:
  script:
    - eval "echo 'literal'"
    # - eval "prefix $CI_COMMIT_MESSAGE"
"""
    assert _hits(source) == []


def test_generic_sec6_echo_exclusion_is_preserved() -> None:
    source = '    - eval echo "$CI_COMMIT_MESSAGE"\n'
    generic = next(rule for rule in SEC6_RULES if rule.id == "SEC6-GL-004")
    assert generic.pattern.check(source, source.splitlines()) == []
    assert len(_hits(source)) == 1


def test_metadata_and_quoted_heredoc_text_are_not_shell_sinks() -> None:
    source = """variables:
  DESCRIPTION: 'eval "$CI_COMMIT_MESSAGE"'
build:
  description: "eval '$CI_COMMIT_TITLE'"
  script:
    - cat <<'EOF'
      eval "$CI_COMMIT_MESSAGE"
      EOF
"""
    assert _hits(source) == []


def test_ci_variable_name_must_not_match_a_suffix_prefix() -> None:
    source = """build:
  script:
    - eval "$CI_COMMIT_TITLE_SUFFIX"
"""
    assert _hits(source) == []
