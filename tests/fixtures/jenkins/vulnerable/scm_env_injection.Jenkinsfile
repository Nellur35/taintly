// Triggers: SEC4-JK-002 — SCM-controlled env var interpolated into shell command
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                sh "git checkout ${env.GIT_BRANCH}"
            }
        }
    }
}
