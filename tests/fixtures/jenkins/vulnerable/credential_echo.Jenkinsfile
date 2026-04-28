// Triggers: SEC6-JK-002 — echo of credential variable inside withCredentials block
pipeline {
    agent { label 'linux' }
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'api-token', variable: 'TOKEN')]) {
                    echo "$TOKEN"
                    sh 'curl -H "Authorization: Bearer $TOKEN" https://api.example.com'
                }
            }
        }
    }
}
