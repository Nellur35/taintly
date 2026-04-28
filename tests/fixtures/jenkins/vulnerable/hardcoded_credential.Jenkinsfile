// Triggers: SEC6-JK-001 — hardcoded credential literal in environment block
pipeline {
    agent { label 'linux' }
    environment {
        GITHUB_TOKEN = 'ghp_abcXYZ1234567890abcdefghijklmnopqr'
    }
    stages {
        stage('Deploy') {
            steps {
                sh 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/org/repo/releases'
            }
        }
    }
}
