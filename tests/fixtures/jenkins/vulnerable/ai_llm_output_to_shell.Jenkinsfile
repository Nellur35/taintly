// Jenkinsfile fixture — expected findings: AI-JK-003 (LLM output to sh)
@Library('shared-lib@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2') _

pipeline {
    agent { label 'ml-linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Classify') {
            steps {
                sh 'openai api chat.completions.create -m gpt-4 -p "$CHANGE_TITLE" | bash'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
