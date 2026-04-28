// Triggers: SEC3-JK-001 — @Library pinned to branch ref, not 40-char commit SHA
@Library('corp-lib@main') _

pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
