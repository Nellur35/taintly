// Triggers: SEC10-JK-001 — declarative pipeline has no post { always { } } block
pipeline {
    agent { label 'linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
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
}
