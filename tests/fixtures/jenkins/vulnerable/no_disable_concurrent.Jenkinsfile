// Triggers: SEC5-JK-001 — deploy stage present without the concurrent build guard
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps { sh 'make build' }
        }
        stage('Deploy to Production') {
            steps {
                input(message: 'Deploy?', ok: 'Deploy', submitter: 'release-team')
                sh './deploy.sh prod'
            }
        }
    }
    post {
        always { cleanWs() }
    }
}
