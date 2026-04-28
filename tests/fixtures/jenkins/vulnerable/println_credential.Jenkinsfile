// Triggers: SEC6-JK-003 — println inside withCredentials block may expose secret
pipeline {
    agent { label 'linux' }
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {
                    println "Using token: ${TOKEN}"
                    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com'
                }
            }
        }
    }
}
