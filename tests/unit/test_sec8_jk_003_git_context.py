"""An HTTP endpoint is not a source-code checkout."""

from taintly.engine import scan_file
from taintly.rules.registry import get_rule_by_id


def _hits(content: str) -> list[int]:
    rule = get_rule_by_id("SEC8-JK-003")
    assert rule is not None
    return [
        finding.line
        for finding in scan_file("Jenkinsfile", [rule], _content=content)
    ]


def test_multiline_status_update_http_request_is_not_git_checkout() -> None:
    content = """pipeline {
  stages {
    stage('Status') {
      steps {
        httpRequest(
          url: "http://status.example.com:3333/project/build",
          httpMode: 'POST',
          requestBody: payload
        )
      }
    }
  }
}
"""
    assert _hits(content) == []


def test_remote_config_bracket_scope_does_not_leak_to_later_request() -> None:
    content = """node {
  checkout([$class: 'GitSCM', userRemoteConfigs: [[
    url: 'http://git.example.com/project.git'
  ]]])
  httpRequest(
    url: 'http://status.example.com/build',
    httpMode: 'POST'
  )
}
"""
    assert _hits(content) == [3]


def test_git_step_and_shell_clone_still_fire() -> None:
    content = """node {
  git(url: 'http://git.example.com/one.git')
  sh 'git clone http://git.example.com/two.git'
  git branch: 'main', url: 'http://git.example.com/three.git'
}
"""
    assert _hits(content) == [2, 3, 4]


def test_comment_or_string_cannot_create_remote_config_context() -> None:
    content = """node {
  // userRemoteConfigs: [[
  echo "userRemoteConfigs: [["
  httpRequest(url: 'http://status.example.com/api')
}
"""
    assert _hits(content) == []


def test_completed_git_call_does_not_own_later_http_request_on_same_line() -> None:
    content = """node {
  git(url: 'https://git.example.com/safe.git'); httpRequest(url: 'http://status.example.com/api')
}
"""
    assert _hits(content) == []
