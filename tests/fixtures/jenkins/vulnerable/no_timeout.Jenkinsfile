// Triggers: SEC1-JK-002 — declarative pipeline has no timeout
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
    }
    post {
        always { cleanWs() }
    }
}
