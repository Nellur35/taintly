// Triggers: SEC4-JK-005 — PR author email (attacker-controlled) interpolated into shell
pipeline {
    agent { label 'linux' }
    stages {
        stage('Notify') {
            steps {
                sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"
                sh 'git commit --amend --reset-author --no-edit'
            }
        }
    }
}
