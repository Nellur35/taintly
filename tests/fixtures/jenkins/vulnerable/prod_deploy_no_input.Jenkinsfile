// Triggers: SEC1-JK-001 — production deploy stage has no manual approval gate
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Deploy to Production') {
            steps {
                sh './deploy.sh prod'
            }
        }
    }
}
