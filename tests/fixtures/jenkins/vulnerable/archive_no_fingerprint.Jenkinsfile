// Triggers: SEC9-JK-002 — archiveArtifacts without fingerprint: true
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
                archiveArtifacts artifacts: 'dist/**/*.jar'
            }
        }
    }
}
