// Triggers: SEC4-JK-001 — user-controlled params.* interpolated into shell command
pipeline {
    agent { label 'linux' }
    parameters {
        string(name: 'BRANCH_NAME', defaultValue: 'main', description: 'Branch to deploy')
    }
    stages {
        stage('Deploy') {
            steps {
                sh "git checkout ${params.BRANCH_NAME}"
            }
        }
    }
}
