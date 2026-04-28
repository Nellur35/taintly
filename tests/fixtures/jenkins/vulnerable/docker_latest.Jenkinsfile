// Triggers: SEC8-JK-001 — Docker agent uses mutable :latest image
pipeline {
    agent {
        docker {
            image 'ubuntu:latest'
            label 'docker-capable'
        }
    }
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
