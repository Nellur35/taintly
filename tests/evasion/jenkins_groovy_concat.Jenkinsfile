// Evasion: Jenkins SEC4-JK-001 deliberately distinguishes
// double-quoted (interpolated) from single-quoted (literal) sh strings.
// String concatenation that mixes literal pieces with raw param.X
// references avoids the double-quoted GString shape the rule anchors
// on, while still injecting the parameter into the shell command.
//
// Discovered: 2026-05-09  (audit chunk 3.1 — Jenkins evasion gap)
// Severity:   HIGH
// Platform:   jenkins
pipeline {
  agent any
  parameters {
    string(name: 'PR_TITLE', defaultValue: '')
  }
  stages {
    stage('s') {
      steps {
        sh 'echo Building: ' + params.PR_TITLE
      }
    }
  }
}
