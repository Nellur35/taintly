// Triggers: SEC7-JK-001 — 'agent any' allows build on any connected node
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
