// Triggers: SEC2-JK-002 — credentialsId derived from user-controlled build parameter
pipeline {
    agent { label 'linux' }
    parameters {
        string(name: 'CRED_ID', defaultValue: 'staging-token', description: 'Credential ID to use')
    }
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: params.CRED_ID, variable: 'TOKEN')]) {
                    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com/deploy'
                }
            }
        }
    }
}
