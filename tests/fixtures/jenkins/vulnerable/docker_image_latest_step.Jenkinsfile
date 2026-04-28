// Triggers: SEC3-JK-003 — docker.image().inside() with mutable :latest tag
pipeline {
    agent { label 'linux' }
    stages {
        stage('Test') {
            steps {
                docker.image('ubuntu:latest').inside {
                    sh 'make test'
                }
            }
        }
    }
}
