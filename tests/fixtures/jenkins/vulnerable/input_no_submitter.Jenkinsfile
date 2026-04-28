// Triggers: SEC4-JK-004 — input step without submitter restriction (any user can approve)
pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps { sh 'make build' }
        }
        stage('Approve') {
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'
            }
        }
        stage('Deploy') {
            steps {
                sh './deploy.sh prod'
            }
        }
    }
}
